use std::{
    collections::VecDeque,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use wc_protocol::{
    relay::RelayTopic,
    session::{
        JsonRpcError, JsonRpcErrorResponse, JsonRpcRequest, Session, SessionDeleteParams,
        SessionEventParams, SessionNamespaces, SessionProposeParams,
    },
};

use crate::pairing::{
    DEFAULT_SESSION_EXPIRY_SECONDS, PairingClient, PairingClientConfig, PairingClientError,
    PairingPayload, PairingReceivedMessage, PairingSubscription, SessionClientEvent,
    SessionLifecycleRequest, SessionLifecycleResponseMessage, SessionLifecycleResponsePayload,
    SessionPayload, SessionProposalApproval, SessionReceivedMessage, SessionSubscription,
};
use crate::session_request::{SessionRequestReview, SessionRequestReviewError};
use crate::session_update::{SessionNamespacesDiff, diff_session_namespaces};

/// Default number of fetched or internally queued events retained by `SingleSessionClient`.
pub const DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY: usize = 128;

/// `SingleSessionClient` configuration.
#[derive(Debug, Clone)]
pub struct SingleSessionClientConfig {
    pairing: PairingClientConfig,
    max_queued_events: usize,
}

impl SingleSessionClientConfig {
    /// Builds a single-session client configuration from the native relay config.
    #[must_use]
    pub const fn new(pairing: PairingClientConfig) -> Self {
        Self {
            pairing,
            max_queued_events: DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY,
        }
    }

    /// Native pairing relay configuration used by `SingleSessionClient`.
    #[must_use]
    pub const fn pairing(&self) -> &PairingClientConfig {
        &self.pairing
    }

    /// Maximum number of events retained before `next_event` is polled.
    #[must_use]
    pub const fn max_queued_events(&self) -> usize {
        self.max_queued_events
    }

    /// Sets the event queue bound used for retained relay messages.
    #[must_use]
    pub const fn with_max_queued_events(mut self, max_queued_events: usize) -> Self {
        self.max_queued_events = max_queued_events;
        self
    }
}

impl From<PairingClientConfig> for SingleSessionClientConfig {
    fn from(pairing: PairingClientConfig) -> Self {
        Self::new(pairing)
    }
}

/// In-memory single-session runtime over the current pairing/session primitives.
///
/// This first runtime owns one relay connection, at most one active pairing or
/// session topic, and a small event queue. Persistence, restore, reconnect,
/// and background polling are separate follow-up layers.
///
/// Applications should create one `SingleSessionClient` and reuse it for the
/// wallet runtime. Creating multiple instances to hold multiple active sessions
/// bypasses the trust boundary this type is designed to enforce.
pub struct SingleSessionClient {
    pairing: PairingClient,
    state: SingleSessionClientState,
    queued_events: BoundedQueue<SingleSessionClientEvent>,
}

impl SingleSessionClient {
    /// Opens an authenticated relay connection.
    pub async fn connect(
        config: &SingleSessionClientConfig,
    ) -> Result<Self, SingleSessionClientError> {
        let pairing = PairingClient::connect(config.pairing())
            .await
            .map_err(SingleSessionClientError::from)?;

        Ok(Self {
            pairing,
            state: SingleSessionClientState::Idle,
            queued_events: BoundedQueue::new(config.max_queued_events()),
        })
    }

    /// HTTP status returned during the relay WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.pairing.status()
    }

    /// Subscribes to a `WalletConnect` pairing URI and queues retained proposals.
    ///
    /// Relay clients fetch retained messages before subscribing so proposals
    /// published while the wallet was offline are not skipped.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn pair(&mut self, uri: &str) -> Result<RelayTopic, SingleSessionClientError> {
        self.ensure_idle_for_pairing()?;
        let pairing_uri = wc_protocol::pairing::PairingUri::parse(uri).map_err(|source| {
            SingleSessionClientError::Pairing {
                source: PairingClientError::PairingUri { source },
            }
        })?;
        let fetched = self
            .pairing
            .fetch_pairing_messages(&pairing_uri)
            .await
            .map_err(SingleSessionClientError::from)?;
        self.queued_events.ensure_capacity_for(fetched.len())?;

        let subscription = self
            .pairing
            .subscribe_pairing(&pairing_uri)
            .await
            .map_err(SingleSessionClientError::from)?;
        let topic = subscription.topic().clone();
        let mut fetched_events = Vec::with_capacity(fetched.len());
        let mut pairing_deleted = false;

        for message in fetched {
            pairing_deleted |= matches!(message.payload(), PairingPayload::PairingDelete(_));
            fetched_events.push(self.handle_pairing_message(&subscription, message).await?);
        }

        if pairing_deleted {
            self.unsubscribe_pairing(&subscription).await?;
        } else {
            self.state = SingleSessionClientState::Pairing(subscription);
        }
        self.queued_events.extend_within_capacity(fetched_events);
        Ok(topic)
    }

    /// Waits for the next queued, pairing-topic, or session-topic event.
    ///
    /// Session messages are exposed as `SessionClientEvent`. Invalid
    /// `wc_sessionRequest` payloads are auto-rejected by the lower-level
    /// receive path; deterministic `wc_sessionPing` and `wc_sessionDelete`
    /// side effects are handled before the event is returned.
    /// `wc_sessionUpdate` is returned without acknowledgement because it
    /// replaces session permissions.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
    ///
    /// > Triggered when a session request is received and should be presented
    /// > to the user for approval or rejection.
    pub async fn next_event(
        &mut self,
    ) -> Result<Option<SingleSessionClientEvent>, SingleSessionClientError> {
        if let Some(event) = self.take_expired_session()? {
            return Ok(Some(SingleSessionClientEvent::SessionExpired(event)));
        }

        if let Some(event) = self.queued_events.pop_front() {
            return Ok(Some(event));
        }

        if let Some(session) = self.active_client_session().cloned() {
            let event = self
                .pairing
                .next_session_event(&session.subscription, &session.session)
                .await
                .map_err(SingleSessionClientError::from)?;
            if let Some(event) = event {
                return self
                    .handle_session_event(&session.subscription, event)
                    .await;
            }
        }

        if let SingleSessionClientState::Pairing(subscription) = &self.state {
            let subscription = subscription.clone();
            let message = self
                .pairing
                .next_pairing_message(&subscription)
                .await
                .map_err(SingleSessionClientError::from)?;
            if let Some(message) = message {
                return self
                    .handle_pairing_message(&subscription, message)
                    .await
                    .map(Some);
            }

            return Ok(None);
        }

        Ok(None)
    }

    /// Approves a queued `wc_sessionPropose` event and stores the active session.
    ///
    /// The lower-level primitive publishes the proposal response and
    /// `wc_sessionSettle`; this method also waits for the matching settle ack so
    /// the stored session is acknowledged before session events are emitted.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L528-L548>
    ///
    /// > await this.sendApproveSession({
    /// > sessionTopic,
    /// > proposal,
    pub async fn approve_session(
        &mut self,
        proposal: &SingleSessionProposal,
        approval: SessionProposalApproval,
    ) -> Result<Session, SingleSessionClientError> {
        let subscription = self.active_pairing(proposal.pairing_topic())?.clone();
        let approved = self
            .pairing
            .approve_session_proposal(&subscription, proposal.request(), approval)
            .await
            .map_err(SingleSessionClientError::from)?;
        let session_topic = approved.session_topic().clone();
        self.state = SingleSessionClientState::Session(Box::new(ActiveSession {
            subscription: approved.subscription().clone(),
            session: approved.pending_session().clone(),
        }));

        let settle_response = match self.pairing.next_session_settle_response(&approved).await {
            Ok(Some(response)) => response,
            Ok(None) => {
                self.clear_session(&session_topic);
                return Err(SingleSessionClientError::SessionSettleResponseMissing {
                    topic: session_topic,
                });
            }
            Err(source) => {
                self.clear_session(&session_topic);
                return Err(SingleSessionClientError::from(source));
            }
        };
        let session = match approved.acknowledged_session(&settle_response) {
            Ok(session) => session,
            Err(source) => {
                self.clear_session(&session_topic);
                return Err(SingleSessionClientError::from(source));
            }
        };
        self.client_session_mut(&session_topic)?.session = session.clone();

        Ok(session)
    }

    /// Rejects a queued `wc_sessionPropose` event on the pairing topic.
    pub async fn reject_session(
        &mut self,
        proposal: &SingleSessionProposal,
        reason: JsonRpcError,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.active_pairing(proposal.pairing_topic())?.clone();
        let ack = self
            .pairing
            .reject_session_proposal(&subscription, proposal.proposal_id(), reason)
            .await
            .map_err(SingleSessionClientError::from)?;
        self.unsubscribe_pairing(&subscription).await?;
        self.state = SingleSessionClientState::Idle;

        Ok(ack)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionRequest`.
    pub async fn respond_session_request_success(
        &mut self,
        message: &SessionReceivedMessage,
        result: impl Into<serde_json::Value>,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_request_success(&subscription, message, result)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Publishes an error response for a `SessionClientEvent::SessionRequest`.
    pub async fn respond_session_request_error(
        &mut self,
        message: &SessionReceivedMessage,
        error: JsonRpcError,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_request_error(&subscription, message, error)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Extracts wallet-facing review data from a `SessionClientEvent::SessionRequest`.
    ///
    /// This helper verifies that the request belongs to an active session held
    /// by this runtime. It does not send a response and does not apply wallet
    /// policy by itself.
    pub fn session_request_review(
        &self,
        message: &SessionReceivedMessage,
    ) -> Result<SessionRequestReview, SingleSessionClientError> {
        self.client_session(message.topic())?;
        SessionRequestReview::from_message(message)
            .map_err(|source| SingleSessionClientError::SessionRequestReview { source })
    }

    /// Publishes a success response for a `SessionClientEvent::SessionPing`.
    ///
    /// `SingleSessionClient::next_event` already responds to session pings it returns. This
    /// method is retained for callers that receive a session message through a
    /// lower-level path.
    pub async fn respond_session_ping(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_ping(&subscription, message)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Approves a `SessionClientEvent::SessionUpdate`.
    ///
    /// Session updates replace the active namespace set, so the polling API
    /// surfaces them first. The caller should approve only after applying wallet
    /// policy and user consent.
    ///
    /// <https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session>
    ///
    /// > include new accounts or chains or methods in an existing session
    pub async fn approve_session_update(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        let SessionPayload::SessionUpdate(request) = message.payload() else {
            return Err(SingleSessionClientError::Pairing {
                source: PairingClientError::SessionResponseTargetNotUpdate,
            });
        };
        let namespaces = request.params.namespaces.clone();
        let publish_ack = self
            .pairing
            .respond_session_update(&subscription, message)
            .await
            .map_err(SingleSessionClientError::from)?;

        if publish_ack {
            self.client_session_mut(message.topic())?.session.namespaces = namespaces;
        }

        Ok(publish_ack)
    }

    /// Describes the permission change requested by a `SessionClientEvent::SessionUpdate`.
    ///
    /// This helper does not acknowledge the peer and does not mutate local
    /// session state.
    pub fn session_update_diff(
        &self,
        message: &SessionReceivedMessage,
    ) -> Result<SessionNamespacesDiff, SingleSessionClientError> {
        let session = self.client_session(message.topic())?;
        let SessionPayload::SessionUpdate(request) = message.payload() else {
            return Err(SingleSessionClientError::Pairing {
                source: PairingClientError::SessionResponseTargetNotUpdate,
            });
        };

        Ok(diff_session_namespaces(
            &session.session.namespaces,
            &request.params.namespaces,
        ))
    }

    /// Rejects a `SessionClientEvent::SessionUpdate` without mutating session permissions.
    ///
    /// Use this when the requested namespace replacement is not allowed by
    /// wallet policy or by user choice.
    pub async fn reject_session_update(
        &mut self,
        message: &SessionReceivedMessage,
        error: JsonRpcError,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .reject_session_update(&subscription, message, error)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionExtend`.
    ///
    /// `SingleSessionClient::next_event` already responds to session extends it returns and
    /// refreshes local expiry. This method is retained for callers that receive
    /// a session message through a lower-level path.
    pub async fn respond_session_extend(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_extend(&subscription, message)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionDelete`.
    ///
    /// `SingleSessionClient::next_event` already responds to session deletes it returns and
    /// removes the local session. This method is retained for callers that
    /// receive a session message through a lower-level path.
    pub async fn respond_session_delete(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        let ack = self
            .pairing
            .respond_session_delete(&subscription, message)
            .await
            .map_err(SingleSessionClientError::from)?;
        self.clear_session(message.topic());

        Ok(ack)
    }

    /// Publishes `wc_sessionUpdate`, waits for acknowledgement, then stores namespaces.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L638-L650>
    ///
    /// > method: "wc_sessionUpdate",
    /// > params: { namespaces },
    /// > await this.client.session.update(topic, { namespaces });
    pub async fn update_session(
        &mut self,
        topic: &RelayTopic,
        namespaces: &SessionNamespaces,
    ) -> Result<SessionLifecycleResponseMessage, SingleSessionClientError> {
        let session = self.client_session(topic)?.clone();
        let request = self
            .pairing
            .update_session(&session.subscription, &session.session, namespaces)
            .await
            .map_err(SingleSessionClientError::from)?;
        let response = self
            .pairing
            .next_session_lifecycle_response(&session.subscription, &request)
            .await
            .map_err(SingleSessionClientError::from)?
            .ok_or_else(
                || SingleSessionClientError::SessionLifecycleResponseMissing {
                    topic: topic.clone(),
                    request_id: request.request_id(),
                },
            )?;

        ensure_session_lifecycle_success(&response)?;
        self.client_session_mut(topic)?
            .session
            .namespaces
            .clone_from(namespaces);

        Ok(response)
    }

    /// Publishes `wc_sessionExtend`, waits for acknowledgement, then refreshes expiry.
    ///
    /// Current Sign Client traffic sends empty params and updates local expiry
    /// with `calcExpiry(SESSION_EXPIRY)`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L678-L685>
    ///
    /// > await this.setExpiry(topic, calcExpiry(SESSION_EXPIRY));
    /// > method: "wc_sessionExtend",
    /// > params: {},
    pub async fn extend_session(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<SessionLifecycleResponseMessage, SingleSessionClientError> {
        let session = self.client_session(topic)?.clone();
        let request = self
            .pairing
            .extend_session(&session.subscription, &session.session)
            .await
            .map_err(SingleSessionClientError::from)?;
        let response = self
            .pairing
            .next_session_lifecycle_response(&session.subscription, &request)
            .await
            .map_err(SingleSessionClientError::from)?
            .ok_or_else(
                || SingleSessionClientError::SessionLifecycleResponseMissing {
                    topic: topic.clone(),
                    request_id: request.request_id(),
                },
            )?;

        ensure_session_lifecycle_success(&response)?;
        let new_expiry = session_extended_expiry()?;
        self.client_session_mut(topic)?.session.expiry = new_expiry;

        Ok(response)
    }

    /// Publishes `wc_sessionEvent` for an acknowledged session.
    ///
    /// Current Sign Client traffic validates the event, emits it to listeners,
    /// and does not send a success acknowledgement.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L881-L896>
    ///
    /// > method: "wc_sessionEvent",
    /// > params: { event, chainId },
    /// > throwOnFailedPublish: true,
    pub async fn emit_session_event(
        &mut self,
        topic: &RelayTopic,
        params: &SessionEventParams,
    ) -> Result<SessionLifecycleRequest, SingleSessionClientError> {
        let session = self.client_session(topic)?.clone();
        self.pairing
            .emit_session_event(&session.subscription, &session.session, params)
            .await
            .map_err(SingleSessionClientError::from)
    }

    /// Publishes `wc_sessionDelete` and removes the acknowledged session locally.
    ///
    /// The maintained Sign Client removes local session state after the relay
    /// accepts the delete request publish.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L897-L909>
    ///
    /// > await this.sendRequest({
    /// > method: "wc_sessionDelete",
    /// > await this.deleteSession({ topic, emitEvent: false });
    pub async fn disconnect(
        &mut self,
        topic: &RelayTopic,
        reason: SessionDeleteParams,
    ) -> Result<SessionLifecycleRequest, SingleSessionClientError> {
        let session = self.client_session(topic)?.clone();
        let request = self
            .pairing
            .disconnect_session(&session.subscription, &session.session, reason)
            .await
            .map_err(SingleSessionClientError::from)?;
        if request.publish_ack() {
            self.clear_session(topic);
        }

        Ok(request)
    }

    /// Active session currently held by this single-session runtime.
    #[must_use]
    pub fn active_session(&self) -> Option<&Session> {
        self.active_client_session().map(|state| &state.session)
    }

    fn session_subscription(
        &self,
        topic: &RelayTopic,
    ) -> Result<&SessionSubscription, SingleSessionClientError> {
        self.client_session(topic).map(|state| &state.subscription)
    }

    fn client_session(
        &self,
        topic: &RelayTopic,
    ) -> Result<&ActiveSession, SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Session(state) if state.session.topic == *topic => Ok(state),
            _ => Err(SingleSessionClientError::SessionMissing {
                topic: topic.clone(),
            }),
        }
    }

    fn client_session_mut(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<&mut ActiveSession, SingleSessionClientError> {
        match &mut self.state {
            SingleSessionClientState::Session(state) if state.session.topic == *topic => Ok(state),
            _ => Err(SingleSessionClientError::SessionMissing {
                topic: topic.clone(),
            }),
        }
    }

    fn active_pairing(
        &self,
        topic: &RelayTopic,
    ) -> Result<&PairingSubscription, SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Pairing(subscription) if subscription.topic() == topic => {
                Ok(subscription)
            }
            _ => Err(SingleSessionClientError::PairingSubscriptionMissing {
                topic: topic.clone(),
            }),
        }
    }

    const fn active_client_session(&self) -> Option<&ActiveSession> {
        match &self.state {
            SingleSessionClientState::Session(state) => Some(&**state),
            SingleSessionClientState::Idle | SingleSessionClientState::Pairing(_) => None,
        }
    }

    fn clear_session(&mut self, topic: &RelayTopic) {
        if matches!(&self.state, SingleSessionClientState::Session(state) if state.session.topic == *topic)
        {
            self.state = SingleSessionClientState::Idle;
        }
    }

    fn ensure_idle_for_pairing(&self) -> Result<(), SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Idle => Ok(()),
            SingleSessionClientState::Pairing(subscription) => {
                Err(SingleSessionClientError::ActivePairingExists {
                    topic: subscription.topic().clone(),
                })
            }
            SingleSessionClientState::Session(state) => {
                Err(SingleSessionClientError::ActiveSessionExists {
                    topic: state.session.topic.clone(),
                })
            }
        }
    }

    async fn unsubscribe_pairing(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<(), SingleSessionClientError> {
        let unsubscribed = self
            .pairing
            .unsubscribe_pairing(subscription)
            .await
            .map_err(SingleSessionClientError::from)?;
        if !unsubscribed {
            return Err(SingleSessionClientError::from(
                PairingClientError::PairingUnsubscribeRejected {
                    topic: subscription.topic().clone(),
                },
            ));
        }

        Ok(())
    }

    fn take_expired_session(&mut self) -> Result<Option<SessionExpired>, SingleSessionClientError> {
        let SingleSessionClientState::Session(state) = &self.state else {
            return Ok(None);
        };
        if !state.session.is_expired_at(now_unix_seconds()?) {
            return Ok(None);
        }

        let topic = state.session.topic.clone();
        let expiry = state.session.expiry;
        self.state = SingleSessionClientState::Idle;

        Ok(Some(SessionExpired { topic, expiry }))
    }

    async fn handle_pairing_message(
        &mut self,
        subscription: &PairingSubscription,
        message: PairingReceivedMessage,
    ) -> Result<SingleSessionClientEvent, SingleSessionClientError> {
        match message.payload() {
            PairingPayload::PairingPing(_) => {
                self.pairing
                    .respond_pairing_ping(subscription, &message)
                    .await
                    .map_err(SingleSessionClientError::from)?;
            }
            PairingPayload::PairingDelete(_) => {
                if matches!(
                    &self.state,
                    SingleSessionClientState::Pairing(subscription) if subscription.topic() == message.topic()
                ) {
                    self.state = SingleSessionClientState::Idle;
                }
            }
            PairingPayload::SessionProposal(_)
            | PairingPayload::Sign(_)
            | PairingPayload::Unknown(_)
            | PairingPayload::Missing => {}
        }

        Ok(SingleSessionClientEvent::from_pairing_message(message))
    }

    /// Applies deterministic session-topic side effects for the polling API.
    ///
    /// `wc_sessionPing` has no wallet decision: the peer expects `true`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2401-L2411>
    ///
    /// > await this.sendResult<"wc_sessionPing">({
    /// > id,
    /// > result: true,
    ///
    /// `wc_sessionDelete` is also deterministic for the runtime: acknowledge
    /// the request and remove local session state.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2442-L2454>
    ///
    /// > await this.isValidDisconnect({ topic, reason: payload.params });
    /// > await this.deleteSession({ topic, id });
    ///
    /// `wc_sessionUpdate` carries replacement namespaces. The high-level client
    /// returns it to the caller instead of acknowledging it here, because
    /// namespace replacement is a wallet permission decision.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2302-L2327>
    ///
    /// > await this.client.session.update(topic, { namespaces: params.namespaces });
    ///
    /// `wc_sessionExtend` refreshes session expiry and acknowledges with
    /// `true`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2363-L2375>
    ///
    /// > await this.setExpiry(topic, calcExpiry(SESSION_EXPIRY));
    /// > await this.sendResult<"wc_sessionExtend">({
    /// > result: true,
    async fn handle_session_event(
        &mut self,
        subscription: &SessionSubscription,
        event: SessionClientEvent,
    ) -> Result<Option<SingleSessionClientEvent>, SingleSessionClientError> {
        match &event {
            SessionClientEvent::SessionPing(message) => {
                self.pairing
                    .respond_session_ping(subscription, message)
                    .await
                    .map_err(SingleSessionClientError::from)?;
            }
            SessionClientEvent::SessionExtend(message) => {
                let expiry = match message.payload() {
                    SessionPayload::SessionExtend(request) => request
                        .params
                        .expiry
                        .map_or_else(session_extended_expiry, Ok)?,
                    _ => return Ok(Some(SingleSessionClientEvent::Session(event))),
                };
                self.pairing
                    .respond_session_extend(subscription, message)
                    .await
                    .map_err(SingleSessionClientError::from)?;
                self.client_session_mut(message.topic())?.session.expiry = expiry;
            }
            SessionClientEvent::SessionDelete(message) => {
                self.pairing
                    .respond_session_delete(subscription, message)
                    .await
                    .map_err(SingleSessionClientError::from)?;
                self.clear_session(message.topic());
            }
            SessionClientEvent::SessionRequest(_)
            | SessionClientEvent::SessionUpdate(_)
            | SessionClientEvent::SessionEvent(_)
            | SessionClientEvent::Unsupported(_)
            | SessionClientEvent::RejectedSessionRequest(_) => {}
        }

        Ok(Some(SingleSessionClientEvent::Session(event)))
    }
}

/// `SingleSessionClient` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingleSessionClientEvent {
    /// A dapp proposed a session on a pairing topic.
    SessionProposal(Box<SingleSessionProposal>),
    /// Pairing-topic message that is not a session proposal.
    PairingMessage(PairingReceivedMessage),
    /// Message on an acknowledged session topic.
    Session(SessionClientEvent),
    /// Local session expiry detected before polling relay messages.
    SessionExpired(SessionExpired),
}

impl SingleSessionClientEvent {
    pub(crate) fn from_pairing_message(message: PairingReceivedMessage) -> Self {
        match message.payload() {
            PairingPayload::SessionProposal(request) => {
                Self::SessionProposal(Box::new(SingleSessionProposal {
                    pairing_topic: message.topic().clone(),
                    request: (**request).clone(),
                    message,
                }))
            }
            PairingPayload::PairingPing(_)
            | PairingPayload::PairingDelete(_)
            | PairingPayload::Sign(_)
            | PairingPayload::Unknown(_)
            | PairingPayload::Missing => Self::PairingMessage(message),
        }
    }
}

/// Session proposal retained for approval or rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleSessionProposal {
    pairing_topic: RelayTopic,
    request: JsonRpcRequest<SessionProposeParams>,
    message: PairingReceivedMessage,
}

impl SingleSessionProposal {
    /// Pairing topic that received the proposal.
    #[must_use]
    pub const fn pairing_topic(&self) -> &RelayTopic {
        &self.pairing_topic
    }

    /// JSON-RPC request id from `wc_sessionPropose`.
    #[must_use]
    pub const fn proposal_id(&self) -> u64 {
        self.request.id
    }

    /// Typed proposal request.
    #[must_use]
    pub const fn request(&self) -> &JsonRpcRequest<SessionProposeParams> {
        &self.request
    }

    /// Original decrypted pairing-topic message.
    #[must_use]
    pub const fn message(&self) -> &PairingReceivedMessage {
        &self.message
    }
}

/// Active session removed after its expiry timestamp passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionExpired {
    topic: RelayTopic,
    expiry: u64,
}

impl SessionExpired {
    /// Session topic removed from the in-memory runtime.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Expiry timestamp that made the session inactive.
    #[must_use]
    pub const fn expiry(&self) -> u64 {
        self.expiry
    }
}

#[derive(Debug, Clone)]
struct ActiveSession {
    subscription: SessionSubscription,
    session: Session,
}

#[derive(Debug, Clone)]
enum SingleSessionClientState {
    Idle,
    Pairing(PairingSubscription),
    Session(Box<ActiveSession>),
}

/// Bounded FIFO for runtime events waiting for application polling.
///
/// Wallet events can require explicit user approval, so overflow is rejected
/// before state mutation instead of dropping older proposals or requests.
#[derive(Debug, Clone)]
struct BoundedQueue<T> {
    capacity: usize,
    items: VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: VecDeque::new(),
        }
    }

    fn pop_front(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    fn ensure_capacity_for(&self, incoming: usize) -> Result<(), SingleSessionClientError> {
        let required = self.items.len().checked_add(incoming).ok_or(
            SingleSessionClientError::EventQueueFull {
                capacity: self.capacity,
                queued: self.items.len(),
                incoming,
            },
        )?;

        if required > self.capacity {
            return Err(SingleSessionClientError::EventQueueFull {
                capacity: self.capacity,
                queued: self.items.len(),
                incoming,
            });
        }

        Ok(())
    }

    fn extend_within_capacity(&mut self, events: impl IntoIterator<Item = T>) {
        self.items.extend(events);
    }
}

/// `SingleSessionClient` runtime error.
#[derive(Debug, thiserror::Error)]
pub enum SingleSessionClientError {
    /// Lower-level pairing/session primitive failed.
    #[error("single-session client pairing primitive failed")]
    Pairing {
        /// Source pairing client error.
        #[source]
        source: PairingClientError,
    },

    /// A pairing topic is already active in the single-session runtime.
    #[error("single-session client active pairing exists")]
    ActivePairingExists {
        /// Active pairing topic.
        topic: RelayTopic,
    },

    /// A session topic is already active in the single-session runtime.
    #[error("single-session client active session exists")]
    ActiveSessionExists {
        /// Active session topic.
        topic: RelayTopic,
    },

    /// Proposal belongs to a pairing topic this runtime no longer tracks.
    #[error("single-session client pairing subscription missing")]
    PairingSubscriptionMissing {
        /// Pairing topic from the proposal.
        topic: RelayTopic,
    },

    /// Session topic is not registered in this runtime.
    #[error("single-session client session missing")]
    SessionMissing {
        /// Session topic from the message.
        topic: RelayTopic,
    },

    /// The peer did not acknowledge the settlement request.
    #[error("single-session client session settle response missing")]
    SessionSettleResponseMissing {
        /// Session topic waiting for settlement acknowledgement.
        topic: RelayTopic,
    },

    /// The peer did not answer an update or extend request.
    #[error("single-session client session lifecycle response missing")]
    SessionLifecycleResponseMissing {
        /// Session topic waiting for lifecycle acknowledgement.
        topic: RelayTopic,
        /// Pending JSON-RPC request id.
        request_id: u64,
    },

    /// The peer rejected an update or extend request.
    #[error("single-session client session lifecycle rejected")]
    SessionLifecycleRejected {
        /// JSON-RPC error response received from the peer.
        response: JsonRpcErrorResponse,
    },

    /// System clock failed while refreshing session expiry.
    #[error("single-session client clock failed")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Default session extension exceeded `u64`.
    #[error("single-session client session expiry overflow")]
    SessionExpiryOverflow,

    /// `SingleSessionClient` event queue cannot retain all pending messages.
    #[error("single-session client event queue full")]
    EventQueueFull {
        /// Configured queue capacity.
        capacity: usize,
        /// Events already retained.
        queued: usize,
        /// New events that need to be retained.
        incoming: usize,
    },

    /// A session-topic message could not be converted to request review data.
    #[error("single-session client session request review failed")]
    SessionRequestReview {
        /// Source review construction error.
        #[source]
        source: SessionRequestReviewError,
    },
}

impl From<PairingClientError> for SingleSessionClientError {
    fn from(source: PairingClientError) -> Self {
        Self::Pairing { source }
    }
}

fn ensure_session_lifecycle_success(
    response: &SessionLifecycleResponseMessage,
) -> Result<(), SingleSessionClientError> {
    match response.payload() {
        SessionLifecycleResponsePayload::Success(_) => Ok(()),
        SessionLifecycleResponsePayload::Error(response) => {
            Err(SingleSessionClientError::SessionLifecycleRejected {
                response: response.clone(),
            })
        }
    }
}

fn now_unix_seconds() -> Result<u64, SingleSessionClientError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| SingleSessionClientError::Clock { source })
}

fn session_extended_expiry() -> Result<u64, SingleSessionClientError> {
    now_unix_seconds()?
        .checked_add(DEFAULT_SESSION_EXPIRY_SECONDS)
        .ok_or(SingleSessionClientError::SessionExpiryOverflow)
}

#[cfg(test)]
mod tests {
    use super::{
        BoundedQueue, DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY, SingleSessionClientError,
    };
    use crate::{PairingClientConfig, SingleSessionClientConfig};

    #[test]
    fn client_config_uses_default_event_queue_capacity() {
        let pairing = PairingClientConfig::new("project", [7; 32], "subject");
        let config = SingleSessionClientConfig::new(pairing);

        assert_eq!(
            config.max_queued_events(),
            DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY
        );
    }

    #[test]
    fn client_config_sets_event_queue_capacity() {
        let pairing = PairingClientConfig::new("project", [7; 32], "subject");
        let config = SingleSessionClientConfig::new(pairing).with_max_queued_events(2);

        assert_eq!(config.max_queued_events(), 2);
    }

    #[test]
    fn bounded_queue_rejects_overflow_without_mutating() {
        let mut queue = BoundedQueue::new(2);
        queue.extend_within_capacity([1]);

        let error = queue
            .ensure_capacity_for(2)
            .expect_err("queue should reject overflow");

        assert!(matches!(
            error,
            SingleSessionClientError::EventQueueFull {
                capacity: 2,
                queued: 1,
                incoming: 2
            }
        ));
        assert_eq!(queue.pop_front(), Some(1));
        assert_eq!(queue.pop_front(), None);
    }
}
