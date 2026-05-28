use std::{
    collections::{BTreeMap, VecDeque},
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
    SessionProposalApproval, SessionReceivedMessage, SessionSubscription,
};

/// Default number of fetched or internally queued events retained for `next_event`.
pub const DEFAULT_CLIENT_EVENT_QUEUE_CAPACITY: usize = 128;

/// Runtime client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pairing: PairingClientConfig,
    max_queued_events: usize,
}

impl ClientConfig {
    /// Builds a client configuration from the native pairing relay config.
    #[must_use]
    pub const fn new(pairing: PairingClientConfig) -> Self {
        Self {
            pairing,
            max_queued_events: DEFAULT_CLIENT_EVENT_QUEUE_CAPACITY,
        }
    }

    /// Native pairing relay configuration used by the first runtime client.
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

impl From<PairingClientConfig> for ClientConfig {
    fn from(pairing: PairingClientConfig) -> Self {
        Self::new(pairing)
    }
}

/// In-memory client runtime over the current pairing/session primitives.
///
/// This first runtime owns one relay connection, pairing subscriptions, active
/// sessions, and a small event queue. Persistence, restore, reconnect, and
/// background polling are separate follow-up layers.
pub struct Client {
    pairing: PairingClient,
    pairings: BTreeMap<RelayTopic, PairingSubscription>,
    sessions: BTreeMap<RelayTopic, ClientSession>,
    queued_events: BoundedQueue<ClientEvent>,
}

impl Client {
    /// Opens an authenticated relay connection.
    pub async fn connect(config: &ClientConfig) -> Result<Self, ClientError> {
        let pairing = PairingClient::connect(config.pairing())
            .await
            .map_err(ClientError::from)?;

        Ok(Self {
            pairing,
            pairings: BTreeMap::new(),
            sessions: BTreeMap::new(),
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
    pub async fn pair(&mut self, uri: &str) -> Result<RelayTopic, ClientError> {
        let pairing_uri = wc_protocol::pairing::PairingUri::parse(uri).map_err(|source| {
            ClientError::Pairing {
                source: PairingClientError::PairingUri { source },
            }
        })?;
        let fetched = self
            .pairing
            .fetch_pairing_messages(&pairing_uri)
            .await
            .map_err(ClientError::from)?;
        self.queued_events.ensure_capacity_for(fetched.len())?;

        let subscription = self
            .pairing
            .subscribe_pairing(&pairing_uri)
            .await
            .map_err(ClientError::from)?;
        let topic = subscription.topic().clone();
        let mut fetched_events = Vec::with_capacity(fetched.len());
        let mut pairing_deleted = false;

        for message in fetched {
            pairing_deleted |= matches!(message.payload(), PairingPayload::PairingDelete(_));
            fetched_events.push(self.handle_pairing_message(&subscription, message).await?);
        }

        if pairing_deleted {
            self.pairing
                .unsubscribe_pairing(&subscription)
                .await
                .map_err(ClientError::from)?;
        } else {
            self.pairings.insert(topic.clone(), subscription);
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
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
    ///
    /// > Triggered when a session request is received and should be presented
    /// > to the user for approval or rejection.
    pub async fn next_event(&mut self) -> Result<Option<ClientEvent>, ClientError> {
        if let Some(event) = self.queued_events.pop_front() {
            return Ok(Some(event));
        }

        if let Some(session) = self.sessions.values().next().cloned() {
            let event = self
                .pairing
                .next_session_event(&session.subscription, &session.session)
                .await
                .map_err(ClientError::from)?;
            if let Some(event) = event {
                return self
                    .handle_session_event(&session.subscription, event)
                    .await;
            }
        }

        if let Some(subscription) = self.pairings.values().next().cloned() {
            let message = self
                .pairing
                .next_pairing_message(&subscription)
                .await
                .map_err(ClientError::from)?;
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
        proposal: &ClientSessionProposal,
        approval: SessionProposalApproval,
    ) -> Result<Session, ClientError> {
        let subscription = self
            .pairings
            .get(proposal.pairing_topic())
            .ok_or_else(|| ClientError::PairingSubscriptionMissing {
                topic: proposal.pairing_topic().clone(),
            })?
            .clone();
        let approved = self
            .pairing
            .approve_session_proposal(&subscription, proposal.request(), approval)
            .await
            .map_err(ClientError::from)?;
        let settle_response = self
            .pairing
            .next_session_settle_response(&approved)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| ClientError::SessionSettleResponseMissing {
                topic: approved.session_topic().clone(),
            })?;
        let session = approved
            .acknowledged_session(&settle_response)
            .map_err(ClientError::from)?;
        self.sessions.insert(
            session.topic.clone(),
            ClientSession {
                subscription: approved.subscription().clone(),
                session: session.clone(),
            },
        );
        self.pairings.remove(proposal.pairing_topic());

        Ok(session)
    }

    /// Rejects a queued `wc_sessionPropose` event on the pairing topic.
    pub async fn reject_session(
        &mut self,
        proposal: &ClientSessionProposal,
        reason: JsonRpcError,
    ) -> Result<bool, ClientError> {
        let subscription = self
            .pairings
            .get(proposal.pairing_topic())
            .ok_or_else(|| ClientError::PairingSubscriptionMissing {
                topic: proposal.pairing_topic().clone(),
            })?
            .clone();
        let ack = self
            .pairing
            .reject_session_proposal(&subscription, proposal.proposal_id(), reason)
            .await
            .map_err(ClientError::from)?;
        self.pairings.remove(proposal.pairing_topic());

        Ok(ack)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionRequest`.
    pub async fn respond_session_request_success(
        &mut self,
        message: &SessionReceivedMessage,
        result: impl Into<serde_json::Value>,
    ) -> Result<bool, ClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_request_success(&subscription, message, result)
            .await
            .map_err(ClientError::from)
    }

    /// Publishes an error response for a `SessionClientEvent::SessionRequest`.
    pub async fn respond_session_request_error(
        &mut self,
        message: &SessionReceivedMessage,
        error: JsonRpcError,
    ) -> Result<bool, ClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_request_error(&subscription, message, error)
            .await
            .map_err(ClientError::from)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionPing`.
    ///
    /// `Client::next_event` already responds to session pings it returns. This
    /// method is retained for callers that receive a session message through a
    /// lower-level path.
    pub async fn respond_session_ping(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, ClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        self.pairing
            .respond_session_ping(&subscription, message)
            .await
            .map_err(ClientError::from)
    }

    /// Publishes a success response for a `SessionClientEvent::SessionDelete`.
    ///
    /// `Client::next_event` already responds to session deletes it returns and
    /// removes the local session. This method is retained for callers that
    /// receive a session message through a lower-level path.
    pub async fn respond_session_delete(
        &mut self,
        message: &SessionReceivedMessage,
    ) -> Result<bool, ClientError> {
        let subscription = self.session_subscription(message.topic())?.clone();
        let ack = self
            .pairing
            .respond_session_delete(&subscription, message)
            .await
            .map_err(ClientError::from)?;
        self.sessions.remove(message.topic());

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
    ) -> Result<SessionLifecycleResponseMessage, ClientError> {
        let session = self
            .sessions
            .get(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
            .clone();
        let request = self
            .pairing
            .update_session(&session.subscription, &session.session, namespaces)
            .await
            .map_err(ClientError::from)?;
        let response = self
            .pairing
            .next_session_lifecycle_response(&session.subscription, &request)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| ClientError::SessionLifecycleResponseMissing {
                topic: topic.clone(),
                request_id: request.request_id(),
            })?;

        ensure_session_lifecycle_success(&response)?;
        self.sessions
            .get_mut(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
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
    ) -> Result<SessionLifecycleResponseMessage, ClientError> {
        let session = self
            .sessions
            .get(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
            .clone();
        let request = self
            .pairing
            .extend_session(&session.subscription, &session.session)
            .await
            .map_err(ClientError::from)?;
        let response = self
            .pairing
            .next_session_lifecycle_response(&session.subscription, &request)
            .await
            .map_err(ClientError::from)?
            .ok_or_else(|| ClientError::SessionLifecycleResponseMissing {
                topic: topic.clone(),
                request_id: request.request_id(),
            })?;

        ensure_session_lifecycle_success(&response)?;
        let new_expiry = now_unix_seconds()?
            .checked_add(DEFAULT_SESSION_EXPIRY_SECONDS)
            .ok_or(ClientError::SessionExpiryOverflow)?;
        self.sessions
            .get_mut(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
            .session
            .expiry = new_expiry;

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
    ) -> Result<SessionLifecycleRequest, ClientError> {
        let session = self
            .sessions
            .get(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
            .clone();
        self.pairing
            .emit_session_event(&session.subscription, &session.session, params)
            .await
            .map_err(ClientError::from)
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
    ) -> Result<SessionLifecycleRequest, ClientError> {
        let session = self
            .sessions
            .get(topic)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })?
            .clone();
        let request = self
            .pairing
            .disconnect_session(&session.subscription, &session.session, reason)
            .await
            .map_err(ClientError::from)?;
        if request.publish_ack() {
            self.sessions.remove(topic);
        }

        Ok(request)
    }

    /// Active sessions currently held by this in-memory runtime.
    #[must_use]
    pub fn active_sessions(&self) -> Vec<&Session> {
        self.sessions.values().map(|state| &state.session).collect()
    }

    fn session_subscription(
        &self,
        topic: &RelayTopic,
    ) -> Result<&SessionSubscription, ClientError> {
        self.sessions
            .get(topic)
            .map(|state| &state.subscription)
            .ok_or_else(|| ClientError::SessionMissing {
                topic: topic.clone(),
            })
    }

    async fn handle_pairing_message(
        &mut self,
        subscription: &PairingSubscription,
        message: PairingReceivedMessage,
    ) -> Result<ClientEvent, ClientError> {
        match message.payload() {
            PairingPayload::PairingPing(_) => {
                self.pairing
                    .respond_pairing_ping(subscription, &message)
                    .await
                    .map_err(ClientError::from)?;
            }
            PairingPayload::PairingDelete(_) => {
                self.pairings.remove(message.topic());
            }
            PairingPayload::SessionProposal(_)
            | PairingPayload::Sign(_)
            | PairingPayload::Unknown(_)
            | PairingPayload::Missing => {}
        }

        Ok(ClientEvent::from_pairing_message(message))
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
    async fn handle_session_event(
        &mut self,
        subscription: &SessionSubscription,
        event: SessionClientEvent,
    ) -> Result<Option<ClientEvent>, ClientError> {
        match &event {
            SessionClientEvent::SessionPing(message) => {
                self.pairing
                    .respond_session_ping(subscription, message)
                    .await
                    .map_err(ClientError::from)?;
            }
            SessionClientEvent::SessionDelete(message) => {
                self.pairing
                    .respond_session_delete(subscription, message)
                    .await
                    .map_err(ClientError::from)?;
                self.sessions.remove(message.topic());
            }
            SessionClientEvent::SessionRequest(_)
            | SessionClientEvent::SessionUpdate(_)
            | SessionClientEvent::SessionExtend(_)
            | SessionClientEvent::SessionEvent(_)
            | SessionClientEvent::Unsupported(_)
            | SessionClientEvent::RejectedSessionRequest(_) => {}
        }

        Ok(Some(ClientEvent::Session(event)))
    }
}

/// Client-level event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A dapp proposed a session on a pairing topic.
    SessionProposal(Box<ClientSessionProposal>),
    /// Pairing-topic message that is not a session proposal.
    PairingMessage(PairingReceivedMessage),
    /// Message on an acknowledged session topic.
    Session(SessionClientEvent),
}

impl ClientEvent {
    pub(crate) fn from_pairing_message(message: PairingReceivedMessage) -> Self {
        match message.payload() {
            PairingPayload::SessionProposal(request) => {
                Self::SessionProposal(Box::new(ClientSessionProposal {
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
pub struct ClientSessionProposal {
    pairing_topic: RelayTopic,
    request: JsonRpcRequest<SessionProposeParams>,
    message: PairingReceivedMessage,
}

impl ClientSessionProposal {
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

#[derive(Debug, Clone)]
struct ClientSession {
    subscription: SessionSubscription,
    session: Session,
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

    fn ensure_capacity_for(&self, incoming: usize) -> Result<(), ClientError> {
        let required =
            self.items
                .len()
                .checked_add(incoming)
                .ok_or(ClientError::EventQueueFull {
                    capacity: self.capacity,
                    queued: self.items.len(),
                    incoming,
                })?;

        if required > self.capacity {
            return Err(ClientError::EventQueueFull {
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

/// Client runtime error.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Lower-level pairing/session primitive failed.
    #[error("client pairing primitive failed")]
    Pairing {
        /// Source pairing client error.
        #[source]
        source: PairingClientError,
    },

    /// Proposal belongs to a pairing topic this runtime no longer tracks.
    #[error("client pairing subscription missing")]
    PairingSubscriptionMissing {
        /// Pairing topic from the proposal.
        topic: RelayTopic,
    },

    /// Session topic is not registered in this runtime.
    #[error("client session missing")]
    SessionMissing {
        /// Session topic from the message.
        topic: RelayTopic,
    },

    /// The peer did not acknowledge the settlement request.
    #[error("client session settle response missing")]
    SessionSettleResponseMissing {
        /// Session topic waiting for settlement acknowledgement.
        topic: RelayTopic,
    },

    /// The peer did not answer an update or extend request.
    #[error("client session lifecycle response missing")]
    SessionLifecycleResponseMissing {
        /// Session topic waiting for lifecycle acknowledgement.
        topic: RelayTopic,
        /// Pending JSON-RPC request id.
        request_id: u64,
    },

    /// The peer rejected an update or extend request.
    #[error("client session lifecycle rejected")]
    SessionLifecycleRejected {
        /// JSON-RPC error response received from the peer.
        response: JsonRpcErrorResponse,
    },

    /// System clock failed while refreshing session expiry.
    #[error("client clock failed")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Default session extension exceeded `u64`.
    #[error("client session expiry overflow")]
    SessionExpiryOverflow,

    /// Client event queue cannot retain all pending messages.
    #[error("client event queue full")]
    EventQueueFull {
        /// Configured queue capacity.
        capacity: usize,
        /// Events already retained.
        queued: usize,
        /// New events that need to be retained.
        incoming: usize,
    },
}

impl From<PairingClientError> for ClientError {
    fn from(source: PairingClientError) -> Self {
        Self::Pairing { source }
    }
}

fn ensure_session_lifecycle_success(
    response: &SessionLifecycleResponseMessage,
) -> Result<(), ClientError> {
    match response.payload() {
        SessionLifecycleResponsePayload::Success(_) => Ok(()),
        SessionLifecycleResponsePayload::Error(response) => {
            Err(ClientError::SessionLifecycleRejected {
                response: response.clone(),
            })
        }
    }
}

fn now_unix_seconds() -> Result<u64, ClientError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|source| ClientError::Clock { source })
}

#[cfg(test)]
mod tests {
    use super::{BoundedQueue, ClientError, DEFAULT_CLIENT_EVENT_QUEUE_CAPACITY};
    use crate::{ClientConfig, PairingClientConfig};

    #[test]
    fn client_config_uses_default_event_queue_capacity() {
        let pairing = PairingClientConfig::new("project", [7; 32], "subject");
        let config = ClientConfig::new(pairing);

        assert_eq!(
            config.max_queued_events(),
            DEFAULT_CLIENT_EVENT_QUEUE_CAPACITY
        );
    }

    #[test]
    fn client_config_sets_event_queue_capacity() {
        let pairing = PairingClientConfig::new("project", [7; 32], "subject");
        let config = ClientConfig::new(pairing).with_max_queued_events(2);

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
            ClientError::EventQueueFull {
                capacity: 2,
                queued: 1,
                incoming: 2
            }
        ));
        assert_eq!(queue.pop_front(), Some(1));
        assert_eq!(queue.pop_front(), None);
    }
}
