use std::{
    collections::{HashSet, VecDeque},
    num::NonZeroUsize,
    time::{Duration, Instant, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use wc_protocol::{
    relay::RelayTopic,
    session::{
        JsonRpcError, JsonRpcErrorResponse, JsonRpcRequest, ProposalAuthRequest,
        RelayProtocolOptions, Session, SessionAuthenticateParams, SessionDeleteParams,
        SessionEventParams, SessionNamespaces, SessionParticipant, SessionProposeParams,
        SessionTransportType,
    },
    verify::VerifyContext,
};
use wc_transport::{RelayClientError, RelayReconnectConfig};

use crate::pairing::{
    DEFAULT_SESSION_EXPIRY_SECONDS, PairingClient, PairingClientConfig as SingleSessionRelayConfig,
    PairingClientError, PairingPayload, PairingReceivedMessage, PairingSubscription,
    SessionClientEvent, SessionLifecycleRequest, SessionLifecycleResponseMessage,
    SessionLifecycleResponsePayload, SessionPayload, SessionProposalApproval,
    SessionReceivedMessage, SessionSubscription,
};
use crate::session_authenticate::{
    SessionAuthenticateApproval, SessionAuthenticateReview, SessionAuthenticateReviewError,
};
use crate::session_request::{SessionRequestReview, SessionRequestReviewError};
use crate::session_update::{SessionNamespacesDiff, diff_session_namespaces};
use crate::verify_policy::{VerifyContextRisk, classify_verify_context};

/// Default number of fetched or internally queued events retained by `SingleSessionClient`.
pub const DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY: usize = 128;

/// Default cooldown between automatic reconnect cycles started by `next_event`.
pub const DEFAULT_SINGLE_SESSION_CLIENT_RECONNECT_COOLDOWN: Duration = Duration::from_secs(5);

/// Default receive-timeout count before `next_event` treats the socket as stale.
pub const DEFAULT_SINGLE_SESSION_CLIENT_RECEIVE_TIMEOUTS_BEFORE_RECONNECT: NonZeroUsize =
    NonZeroUsize::new(2).expect("non-zero");

/// `SingleSessionClient` configuration.
#[derive(Debug, Clone)]
pub struct SingleSessionClientConfig {
    pairing: SingleSessionRelayConfig,
    max_queued_events: usize,
    reconnect: RelayReconnectConfig,
    automatic_reconnect_cooldown: Duration,
    receive_timeouts_before_reconnect: NonZeroUsize,
}

impl SingleSessionClientConfig {
    /// Builds a single-session client configuration from the native relay config.
    #[must_use]
    pub const fn new(pairing: SingleSessionRelayConfig) -> Self {
        Self {
            pairing,
            max_queued_events: DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY,
            reconnect: RelayReconnectConfig::new(
                wc_transport::DEFAULT_CONNECT_RETRY_ATTEMPTS,
                wc_transport::DEFAULT_CONNECT_RETRY_INITIAL_DELAY,
                wc_transport::DEFAULT_CONNECT_RETRY_MAX_DELAY,
            ),
            automatic_reconnect_cooldown: DEFAULT_SINGLE_SESSION_CLIENT_RECONNECT_COOLDOWN,
            receive_timeouts_before_reconnect:
                DEFAULT_SINGLE_SESSION_CLIENT_RECEIVE_TIMEOUTS_BEFORE_RECONNECT,
        }
    }

    /// Native pairing relay configuration used by `SingleSessionClient`.
    #[must_use]
    pub const fn pairing(&self) -> &SingleSessionRelayConfig {
        &self.pairing
    }

    /// Maximum number of events retained before `next_event` is polled.
    #[must_use]
    pub const fn max_queued_events(&self) -> usize {
        self.max_queued_events
    }

    /// Relay reconnect policy used by `SingleSessionClient::reconnect`.
    #[must_use]
    pub const fn reconnect(&self) -> &RelayReconnectConfig {
        &self.reconnect
    }

    /// Minimum time between automatic reconnect cycles started by `next_event`.
    #[must_use]
    pub const fn automatic_reconnect_cooldown(&self) -> Duration {
        self.automatic_reconnect_cooldown
    }

    /// Receive-timeout count before `next_event` probes liveness by reconnecting.
    #[must_use]
    pub const fn receive_timeouts_before_reconnect(&self) -> NonZeroUsize {
        self.receive_timeouts_before_reconnect
    }

    /// Sets the event queue bound used for retained relay messages.
    #[must_use]
    pub const fn with_max_queued_events(mut self, max_queued_events: usize) -> Self {
        self.max_queued_events = max_queued_events;
        self
    }

    /// Sets the relay reconnect policy.
    #[must_use]
    pub const fn with_reconnect(mut self, reconnect: RelayReconnectConfig) -> Self {
        self.reconnect = reconnect;
        self
    }

    /// Sets the automatic reconnect cooldown used by `next_event`.
    #[must_use]
    pub const fn with_automatic_reconnect_cooldown(mut self, cooldown: Duration) -> Self {
        assert!(
            !cooldown.is_zero(),
            "automatic reconnect cooldown must be non-zero"
        );
        self.automatic_reconnect_cooldown = cooldown;
        self
    }

    /// Sets how many consecutive receive timeouts make `next_event` reconnect.
    #[must_use]
    pub const fn with_receive_timeouts_before_reconnect(mut self, count: NonZeroUsize) -> Self {
        self.receive_timeouts_before_reconnect = count;
        self
    }
}

impl From<SingleSessionRelayConfig> for SingleSessionClientConfig {
    fn from(pairing: SingleSessionRelayConfig) -> Self {
        Self::new(pairing)
    }
}

/// Relay connection state tracked by `SingleSessionClient`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSessionClientConnectionState {
    /// Relay socket is expected to be usable.
    Connected,
    /// Runtime is currently opening a replacement relay socket.
    Reconnecting,
    /// Caller explicitly closed the relay socket.
    DisconnectedByUser,
    /// Automatic reconnect failed or is cooling down.
    Unavailable,
}

/// In-memory single-session runtime over the current pairing/session primitives.
///
/// This first runtime owns one relay connection, at most one active pairing or
/// session topic, bounded reconnect behavior, and a small event queue.
/// Persistence, restore, and background polling are separate follow-up layers.
///
/// Applications should create one `SingleSessionClient` and reuse it for the
/// wallet runtime. Creating multiple instances to hold multiple active sessions
/// bypasses the trust boundary this type is designed to enforce.
pub struct SingleSessionClient {
    config: SingleSessionClientConfig,
    pairing: PairingClient,
    state: SingleSessionClientState,
    connection_state: SingleSessionClientConnectionState,
    last_automatic_reconnect: Option<Instant>,
    consecutive_receive_timeouts: usize,
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
            config: config.clone(),
            pairing,
            state: SingleSessionClientState::Idle,
            connection_state: SingleSessionClientConnectionState::Connected,
            last_automatic_reconnect: None,
            consecutive_receive_timeouts: 0,
            queued_events: BoundedQueue::new(config.max_queued_events()),
        })
    }

    /// HTTP status returned during the relay WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.pairing.status()
    }

    /// Current relay connection state for this single-session runtime.
    #[must_use]
    pub const fn connection_state(&self) -> SingleSessionClientConnectionState {
        self.connection_state
    }

    /// Closes the relay socket and prevents automatic reconnect.
    ///
    /// Call `reconnect` explicitly to reopen the socket after shutdown.
    pub async fn shutdown(&mut self) -> Result<(), SingleSessionClientError> {
        let close_result = self.pairing.close().await;
        self.state = SingleSessionClientState::Idle;
        self.queued_events.clear();
        self.connection_state = SingleSessionClientConnectionState::DisconnectedByUser;
        self.consecutive_receive_timeouts = 0;
        close_result.map_err(SingleSessionClientError::from)
    }

    /// Reopens the relay connection and resubscribes the one active topic.
    ///
    /// `SingleSessionClient` does not restore multiple topics. If the runtime
    /// is idle, this only refreshes the relay socket. If a pairing or session
    /// is active, the same topic is subscribed again after the socket is
    /// reopened.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn reconnect(&mut self) -> Result<(), SingleSessionClientError> {
        self.reconnect_inner().await?;
        self.connection_state = SingleSessionClientConnectionState::Connected;
        self.consecutive_receive_timeouts = 0;
        Ok(())
    }

    async fn reconnect_inner(&mut self) -> Result<(), SingleSessionClientError> {
        let config = self.config.clone();
        let previous_state = self.state.clone();
        self.pairing
            .reconnect(config.pairing(), config.reconnect().clone())
            .await
            .map_err(SingleSessionClientError::from)?;

        match previous_state {
            SingleSessionClientState::Idle => {
                self.state = SingleSessionClientState::Idle;
                Ok(())
            }
            SingleSessionClientState::Pairing(subscription) => {
                match self.pairing.resubscribe_pairing(&subscription).await {
                    Ok(subscription) => {
                        self.state = SingleSessionClientState::Pairing(subscription);
                        Ok(())
                    }
                    Err(source) => {
                        self.state = SingleSessionClientState::Idle;
                        self.queued_events.clear();
                        Err(SingleSessionClientError::from(source))
                    }
                }
            }
            SingleSessionClientState::Session(mut session) => {
                match self
                    .pairing
                    .resubscribe_session(&session.subscription)
                    .await
                {
                    Ok(subscription) => {
                        session.subscription = subscription;
                        self.state = SingleSessionClientState::Session(session);
                        Ok(())
                    }
                    Err(source) => {
                        self.state = SingleSessionClientState::Idle;
                        self.queued_events.clear();
                        Err(SingleSessionClientError::from(source))
                    }
                }
            }
        }
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
    /// Closed relay sockets are reopened at most once per call with the
    /// configured reconnect policy. Consecutive receive timeouts also trigger
    /// one reconnect after the configured liveness threshold. Automatic
    /// reconnects obey a cross-call cooldown so a peer that repeatedly closes
    /// the socket cannot make the caller hammer the relay by polling in a loop.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
    ///
    /// > Triggered when a session request is received and should be presented
    /// > to the user for approval or rejection.
    pub async fn next_event(
        &mut self,
    ) -> Result<Option<SingleSessionClientEvent>, SingleSessionClientError> {
        if self.connection_state == SingleSessionClientConnectionState::DisconnectedByUser {
            return Err(SingleSessionClientError::DisconnectedByUser);
        }

        let mut reconnected = false;

        loop {
            match self.next_event_once().await {
                Ok(event) => {
                    self.consecutive_receive_timeouts = 0;
                    if self.connection_state
                        != SingleSessionClientConnectionState::DisconnectedByUser
                    {
                        self.connection_state = SingleSessionClientConnectionState::Connected;
                    }
                    return Ok(event);
                }
                Err(error) if !reconnected && error.is_relay_connection_closed() => {
                    reconnected = true;
                    self.reconnect_automatically().await?;
                }
                Err(error) if !reconnected && error.is_receive_timed_out() => {
                    if self.record_receive_timeout_requires_reconnect() {
                        reconnected = true;
                        self.reconnect_automatically().await?;
                    } else {
                        return Err(error);
                    }
                }
                Err(error) if error.is_relay_connection_closed() => {
                    self.connection_state = SingleSessionClientConnectionState::Unavailable;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn next_event_once(
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

    async fn reconnect_automatically(&mut self) -> Result<(), SingleSessionClientError> {
        match self.ensure_automatic_reconnect_allowed() {
            Ok(()) => {}
            Err(SingleSessionClientError::DisconnectedByUser) => {
                return Err(SingleSessionClientError::DisconnectedByUser);
            }
            Err(error) => {
                self.connection_state = SingleSessionClientConnectionState::Unavailable;
                return Err(error);
            }
        }

        self.connection_state = SingleSessionClientConnectionState::Reconnecting;
        self.last_automatic_reconnect = Some(Instant::now());

        match self.reconnect_inner().await {
            Ok(()) => {
                self.connection_state = SingleSessionClientConnectionState::Connected;
                self.consecutive_receive_timeouts = 0;
                Ok(())
            }
            Err(error) => {
                self.connection_state = SingleSessionClientConnectionState::Unavailable;
                Err(error)
            }
        }
    }

    fn ensure_automatic_reconnect_allowed(&self) -> Result<(), SingleSessionClientError> {
        if self.connection_state == SingleSessionClientConnectionState::DisconnectedByUser {
            return Err(SingleSessionClientError::DisconnectedByUser);
        }

        let Some(last_reconnect) = self.last_automatic_reconnect else {
            return Ok(());
        };

        let cooldown = self.config.automatic_reconnect_cooldown();
        let elapsed = last_reconnect.elapsed();
        if elapsed >= cooldown {
            return Ok(());
        }

        Err(SingleSessionClientError::ReconnectCoolingDown {
            remaining: cooldown.saturating_sub(elapsed),
        })
    }

    const fn record_receive_timeout_requires_reconnect(&mut self) -> bool {
        self.consecutive_receive_timeouts = self.consecutive_receive_timeouts.saturating_add(1);
        self.consecutive_receive_timeouts >= self.config.receive_timeouts_before_reconnect().get()
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
        self.state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
            approved.subscription().clone(),
            approved.pending_session().clone(),
        )));

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

    /// Extracts wallet-facing review data from a `wc_sessionAuthenticate` event.
    ///
    /// This helper verifies that the authentication request still belongs to
    /// the active pairing topic. It does not sign CACAOs and does not apply
    /// wallet policy by itself.
    pub fn session_authenticate_review(
        &self,
        authenticate: &SingleSessionAuthenticate,
    ) -> Result<SessionAuthenticateReview, SingleSessionClientError> {
        self.active_pairing(authenticate.pairing_topic())?;
        SessionAuthenticateReview::from_message(authenticate.message())
            .map_err(|source| SingleSessionClientError::SessionAuthenticateReview { source })
    }

    /// Approves a queued `wc_sessionAuthenticate` event with signed CACAOs.
    ///
    /// Approval publishes a type-1 success response on the requester public-key
    /// response topic. If approval includes session namespaces, the runtime
    /// subscribes the derived authenticated session topic and stores an
    /// acknowledged session; otherwise it drops the pairing topic. The caller
    /// owns message formatting, user approval, signing, and namespace policy.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375>
    ///
    /// > if (approvedMethods?.length > 0) {
    /// > session = {
    pub async fn approve_session_authenticate(
        &mut self,
        authenticate: &SingleSessionAuthenticate,
        approval: SessionAuthenticateApproval,
    ) -> Result<SessionAuthenticateApprovalOutcome, SingleSessionClientError> {
        let subscription = self.active_pairing(authenticate.pairing_topic())?.clone();
        let request = authenticate.request();
        let now_unix_seconds = now_unix_seconds()?;
        if request.params.is_expired_at(now_unix_seconds) {
            return Err(SingleSessionClientError::SessionAuthenticateExpired {
                request_id: request.id,
                expiry: request.params.expiry_timestamp,
                now_unix_seconds,
            });
        }

        let (wallet_metadata, cacaos, session_namespaces) = approval.into_parts();
        let adopt_session = session_namespaces.is_some();
        if adopt_session {
            self.unsubscribe_pairing(&subscription).await?;
        }
        let approved = self
            .pairing
            .approve_session_authenticate(
                &subscription,
                authenticate.message(),
                wallet_metadata.clone(),
                cacaos.clone(),
                adopt_session,
            )
            .await
            .map_err(|source| {
                if adopt_session {
                    self.state = SingleSessionClientState::Idle;
                    self.queued_events.clear();
                }
                SingleSessionClientError::from(source)
            })?;
        if let Some(namespaces) = session_namespaces {
            let Some(session_subscription) = approved.session_subscription().cloned() else {
                self.state = SingleSessionClientState::Idle;
                self.queued_events.clear();
                return Err(
                    SingleSessionClientError::SessionAuthenticateSubscriptionMissing {
                        topic: approved.session_topic().clone(),
                    },
                );
            };
            let session = match authenticated_session(
                &subscription,
                request,
                approved.session_topic().clone(),
                approved.responder_public_key().clone(),
                wallet_metadata,
                cacaos,
                namespaces,
            ) {
                Ok(session) => session,
                Err(error) => {
                    self.state = SingleSessionClientState::Idle;
                    self.queued_events.clear();
                    return Err(error);
                }
            };
            self.state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
                session_subscription,
                session.clone(),
            )));

            return Ok(SessionAuthenticateApprovalOutcome {
                response_ack: approved.response_ack(),
                session: Some(session),
            });
        }

        self.unsubscribe_pairing(&subscription).await?;
        self.state = SingleSessionClientState::Idle;

        Ok(SessionAuthenticateApprovalOutcome {
            response_ack: approved.response_ack(),
            session: None,
        })
    }

    /// Rejects a queued `wc_sessionAuthenticate` event.
    ///
    /// Rejection publishes a type-1 error response on the requester public-key
    /// response topic, then drops the pairing topic from the single-session
    /// runtime.
    pub async fn reject_session_authenticate(
        &mut self,
        authenticate: &SingleSessionAuthenticate,
        reason: JsonRpcError,
    ) -> Result<bool, SingleSessionClientError> {
        let subscription = self.active_pairing(authenticate.pairing_topic())?.clone();
        let ack = self
            .pairing
            .reject_session_authenticate(&subscription, authenticate.message(), reason)
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
        let request_id = session_request_id(message)?;
        self.client_session(message.topic())?
            .ensure_pending_session_request(request_id)?;
        let subscription = self.session_subscription(message.topic())?.clone();
        let response_ack = self
            .pairing
            .respond_session_request_success(&subscription, message, result)
            .await
            .map_err(SingleSessionClientError::from)?;
        if response_ack {
            self.client_session_mut(message.topic())?
                .complete_session_request(request_id);
        }

        Ok(response_ack)
    }

    /// Publishes an error response for a `SessionClientEvent::SessionRequest`.
    pub async fn respond_session_request_error(
        &mut self,
        message: &SessionReceivedMessage,
        error: JsonRpcError,
    ) -> Result<bool, SingleSessionClientError> {
        let request_id = session_request_id(message)?;
        self.client_session(message.topic())?
            .ensure_pending_session_request(request_id)?;
        let subscription = self.session_subscription(message.topic())?.clone();
        let response_ack = self
            .pairing
            .respond_session_request_error(&subscription, message, error)
            .await
            .map_err(SingleSessionClientError::from)?;
        if response_ack {
            self.client_session_mut(message.topic())?
                .complete_session_request(request_id);
        }

        Ok(response_ack)
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
        let request_id = session_request_id(message)?;
        let session = self.client_session(message.topic())?;
        session.ensure_pending_session_request(request_id)?;
        let verify_context =
            VerifyContext::unresolved_from_metadata(&session.session.peer.metadata);
        SessionRequestReview::from_message_with_verify_context(message, verify_context)
            .map_err(|source| SingleSessionClientError::SessionRequestReview { source })
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
        let request_id = request.id;
        self.client_session(message.topic())?
            .ensure_pending_session_update(request_id)?;
        let namespaces = request.params.namespaces.clone();
        let publish_ack = self
            .pairing
            .respond_session_update(&subscription, message)
            .await
            .map_err(SingleSessionClientError::from)?;

        if publish_ack {
            let session = self.client_session_mut(message.topic())?;
            session.session.namespaces = namespaces;
            session.complete_session_update(request_id);
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
        session.ensure_pending_session_update(request.id)?;

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
        let request_id = session_update_id(message)?;
        self.client_session(message.topic())?
            .ensure_pending_session_update(request_id)?;
        let subscription = self.session_subscription(message.topic())?.clone();
        let response_ack = self
            .pairing
            .reject_session_update(&subscription, message, error)
            .await
            .map_err(SingleSessionClientError::from)?;
        if response_ack {
            self.client_session_mut(message.topic())?
                .complete_session_update(request_id);
        }

        Ok(response_ack)
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
        let now_unix_seconds = now_unix_seconds()?;
        Ok(take_expired_session_from_state(
            &mut self.state,
            now_unix_seconds,
        ))
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
            | PairingPayload::SessionAuthenticate(_)
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
            SessionClientEvent::SessionRequest(message) => {
                let request_id = session_request_id(message)?;
                if !self
                    .client_session_mut(message.topic())?
                    .mark_session_request_pending(request_id)
                {
                    return Ok(None);
                }
            }
            SessionClientEvent::SessionUpdate(message) => {
                let request_id = session_update_id(message)?;
                if !self
                    .client_session_mut(message.topic())?
                    .mark_session_update_pending(request_id)
                {
                    return Ok(None);
                }
            }
            SessionClientEvent::SessionEvent(_)
            | SessionClientEvent::Unsupported(_)
            | SessionClientEvent::RejectedSessionRequest(_) => {}
        }

        Ok(Some(SingleSessionClientEvent::Session(event)))
    }
}

fn take_expired_session_from_state(
    state: &mut SingleSessionClientState,
    now_unix_seconds: u64,
) -> Option<SessionExpired> {
    let SingleSessionClientState::Session(active_session) = state else {
        return None;
    };
    if !active_session.session.is_expired_at(now_unix_seconds) {
        return None;
    }

    let topic = active_session.session.topic.clone();
    let expiry = active_session.session.expiry;
    *state = SingleSessionClientState::Idle;

    Some(SessionExpired { topic, expiry })
}

/// `SingleSessionClient` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingleSessionClientEvent {
    /// A dapp proposed a session on a pairing topic.
    SessionProposal(Box<SingleSessionProposal>),
    /// A dapp requested CAIP-122/CACAO authentication on a pairing topic.
    SessionAuthenticate(Box<SingleSessionAuthenticate>),
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
                let request = (**request).clone();
                let verify_context =
                    VerifyContext::unresolved_from_metadata(&request.params.proposer.metadata);
                Self::SessionProposal(Box::new(SingleSessionProposal {
                    pairing_topic: message.topic().clone(),
                    request,
                    verify_context,
                    message,
                }))
            }
            PairingPayload::SessionAuthenticate(request) => {
                let request = (**request).clone();
                let verify_context =
                    VerifyContext::unresolved_from_metadata(&request.params.requester.metadata);
                Self::SessionAuthenticate(Box::new(SingleSessionAuthenticate {
                    pairing_topic: message.topic().clone(),
                    request,
                    verify_context,
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
    verify_context: VerifyContext,
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

    /// Unresolved Verify context built from proposal metadata.
    ///
    /// The maintained Sign Client emits `verifyContext` with
    /// `session_proposal` events after seeding it from metadata and then
    /// attempting Verify resolution.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/client.ts#L33-L36>
    ///
    /// > session_proposal: {
    /// > verifyContext: Verify.Context;
    #[must_use]
    pub const fn verify_context(&self) -> &VerifyContext {
        &self.verify_context
    }

    /// Current policy classification for `verify_context`.
    #[must_use]
    pub const fn verify_risk(&self) -> VerifyContextRisk {
        classify_verify_context(&self.verify_context)
    }

    /// Authentication subrequests embedded in this proposal.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L302-L333>
    ///
    /// > requests: {
    /// > authentication: authentication?.map((auth) => {
    /// > const protocolParams: AuthTypes.AuthenticateParams = {
    #[must_use]
    pub fn authentication_requests(&self) -> &[ProposalAuthRequest] {
        self.request
            .params
            .requests
            .as_ref()
            .and_then(|requests| requests.authentication.as_deref())
            .unwrap_or(&[])
    }

    /// Original decrypted pairing-topic message.
    #[must_use]
    pub const fn message(&self) -> &PairingReceivedMessage {
        &self.message
    }
}

/// Session-authenticate request retained for review or rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleSessionAuthenticate {
    pairing_topic: RelayTopic,
    request: JsonRpcRequest<SessionAuthenticateParams>,
    verify_context: VerifyContext,
    message: PairingReceivedMessage,
}

impl SingleSessionAuthenticate {
    /// Pairing topic that received the authentication request.
    #[must_use]
    pub const fn pairing_topic(&self) -> &RelayTopic {
        &self.pairing_topic
    }

    /// JSON-RPC request id from `wc_sessionAuthenticate`.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request.id
    }

    /// Typed authentication request.
    #[must_use]
    pub const fn request(&self) -> &JsonRpcRequest<SessionAuthenticateParams> {
        &self.request
    }

    /// Unresolved Verify context built from authentication requester metadata.
    ///
    /// The maintained Sign Client emits `verifyContext` with
    /// `session_authenticate` events.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/client.ts#L58-L61>
    ///
    /// > session_authenticate: {
    /// > verifyContext: Verify.Context;
    #[must_use]
    pub const fn verify_context(&self) -> &VerifyContext {
        &self.verify_context
    }

    /// Current policy classification for `verify_context`.
    #[must_use]
    pub const fn verify_risk(&self) -> VerifyContextRisk {
        classify_verify_context(&self.verify_context)
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

/// Result of approving a `wc_sessionAuthenticate` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticateApprovalOutcome {
    response_ack: bool,
    session: Option<Session>,
}

impl SessionAuthenticateApprovalOutcome {
    /// Relay ack for the auth success response publish.
    #[must_use]
    pub const fn response_ack(&self) -> bool {
        self.response_ack
    }

    /// Auth-created session adopted by the single-session runtime.
    ///
    /// This is `None` when the approval did not include session namespaces.
    #[must_use]
    pub const fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Moves the adopted session out of the approval result.
    #[must_use]
    pub fn into_session(self) -> Option<Session> {
        self.session
    }
}

#[derive(Debug, Clone)]
struct ActiveSession {
    subscription: SessionSubscription,
    session: Session,
    pending_session_requests: HashSet<u64>,
    pending_session_updates: HashSet<u64>,
}

impl ActiveSession {
    fn new(subscription: SessionSubscription, session: Session) -> Self {
        Self {
            subscription,
            session,
            pending_session_requests: HashSet::new(),
            pending_session_updates: HashSet::new(),
        }
    }

    fn mark_session_request_pending(&mut self, request_id: u64) -> bool {
        self.pending_session_requests.insert(request_id)
    }

    fn ensure_pending_session_request(
        &self,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        if self.pending_session_requests.contains(&request_id) {
            return Ok(());
        }

        Err(SingleSessionClientError::SessionRequestDecisionMissing {
            topic: self.session.topic.clone(),
            request_id,
        })
    }

    fn complete_session_request(&mut self, request_id: u64) {
        self.pending_session_requests.remove(&request_id);
    }

    fn mark_session_update_pending(&mut self, request_id: u64) -> bool {
        self.pending_session_updates.insert(request_id)
    }

    fn ensure_pending_session_update(
        &self,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        if self.pending_session_updates.contains(&request_id) {
            return Ok(());
        }

        Err(SingleSessionClientError::SessionUpdateDecisionMissing {
            topic: self.session.topic.clone(),
            request_id,
        })
    }

    fn complete_session_update(&mut self, request_id: u64) {
        self.pending_session_updates.remove(&request_id);
    }
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

    fn clear(&mut self) {
        self.items.clear();
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

    /// Automatic reconnect is delayed by the cross-call cooldown.
    #[error("single-session client reconnect cooling down for {remaining:?}")]
    ReconnectCoolingDown {
        /// Remaining cooldown duration.
        remaining: Duration,
    },

    /// Caller explicitly shut down the relay connection.
    #[error("single-session client disconnected by user")]
    DisconnectedByUser,

    /// A session-topic message could not be converted to request review data.
    #[error("single-session client session request review failed")]
    SessionRequestReview {
        /// Source review construction error.
        #[source]
        source: SessionRequestReviewError,
    },

    /// A pairing-topic message could not be converted to auth review data.
    #[error("single-session client session authenticate review failed")]
    SessionAuthenticateReview {
        /// Source review construction error.
        #[source]
        source: SessionAuthenticateReviewError,
    },

    /// Authentication request expired before caller approval.
    #[error("single-session client session authenticate request expired")]
    SessionAuthenticateExpired {
        /// JSON-RPC request id from the expired auth request.
        request_id: u64,
        /// Request expiry timestamp.
        expiry: u64,
        /// Unix timestamp used for the comparison.
        now_unix_seconds: u64,
    },

    /// Auth approval requested session adoption but no session subscription was returned.
    #[error("single-session client session authenticate subscription missing")]
    SessionAuthenticateSubscriptionMissing {
        /// Derived authenticated session topic.
        topic: RelayTopic,
    },

    /// No pending caller decision exists for this session request.
    #[error("single-session client session request decision is not pending")]
    SessionRequestDecisionMissing {
        /// Active session topic.
        topic: RelayTopic,
        /// JSON-RPC request id.
        request_id: u64,
    },

    /// No pending caller decision exists for this session update.
    #[error("single-session client session update decision is not pending")]
    SessionUpdateDecisionMissing {
        /// Active session topic.
        topic: RelayTopic,
        /// JSON-RPC request id.
        request_id: u64,
    },
}

impl From<PairingClientError> for SingleSessionClientError {
    fn from(source: PairingClientError) -> Self {
        Self::Pairing { source }
    }
}

impl SingleSessionClientError {
    const fn is_relay_connection_closed(&self) -> bool {
        matches!(
            self,
            Self::Pairing {
                source: PairingClientError::Relay {
                    source: RelayClientError::ConnectionClosed { .. }
                }
            }
        )
    }

    const fn is_receive_timed_out(&self) -> bool {
        matches!(
            self,
            Self::Pairing {
                source: PairingClientError::ReceiveTimedOut { .. }
            }
        )
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

const fn session_request_id(
    message: &SessionReceivedMessage,
) -> Result<u64, SingleSessionClientError> {
    match message.payload() {
        SessionPayload::SessionRequest(request) => Ok(request.id),
        _ => Err(SingleSessionClientError::Pairing {
            source: PairingClientError::SessionResponseTargetNotRequest,
        }),
    }
}

const fn session_update_id(
    message: &SessionReceivedMessage,
) -> Result<u64, SingleSessionClientError> {
    match message.payload() {
        SessionPayload::SessionUpdate(request) => Ok(request.id),
        _ => Err(SingleSessionClientError::Pairing {
            source: PairingClientError::SessionResponseTargetNotUpdate,
        }),
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

/// Builds the wallet-side session stored after `wc_sessionAuthenticate` approval.
///
/// The maintained SDK stores an acknowledged session when authenticated methods
/// are granted, with the responder key as `controller` and the signed CACAOs in
/// `authentication`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375>
///
/// > session = {
/// > topic: sessionTopic,
/// > acknowledged: true,
/// > authentication: auths,
/// > namespaces: buildNamespacesFromAuth(
fn authenticated_session(
    pairing_subscription: &PairingSubscription,
    request: &JsonRpcRequest<SessionAuthenticateParams>,
    session_topic: RelayTopic,
    responder_public_key: wc_protocol::key::X25519PublicKey,
    wallet_metadata: wc_protocol::session::DappMetadata,
    cacaos: Vec<wc_protocol::session::Cacao>,
    namespaces: SessionNamespaces,
) -> Result<Session, SingleSessionClientError> {
    Ok(Session {
        topic: session_topic,
        pairing_topic: pairing_subscription.topic().clone(),
        relay: RelayProtocolOptions {
            protocol: "irn".to_owned(),
            data: None,
        },
        expiry: session_extended_expiry()?,
        acknowledged: true,
        controller: responder_public_key.clone(),
        namespaces,
        required_namespaces: std::collections::BTreeMap::default(),
        optional_namespaces: std::collections::BTreeMap::default(),
        session_properties: None,
        scoped_properties: None,
        session_config: None,
        self_participant: SessionParticipant {
            public_key: responder_public_key,
            metadata: wallet_metadata,
        },
        peer: request.params.requester.clone(),
        authentication: Some(cacaos),
        wallet_pay_result: None,
        transport_type: Some(SessionTransportType::Relay),
    })
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};

    use super::{
        ActiveSession, BoundedQueue, DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY,
        DEFAULT_SINGLE_SESSION_CLIENT_RECEIVE_TIMEOUTS_BEFORE_RECONNECT,
        DEFAULT_SINGLE_SESSION_CLIENT_RECONNECT_COOLDOWN, SingleSessionClient,
        SingleSessionClientConfig, SingleSessionClientConnectionState, SingleSessionClientError,
        SingleSessionClientState, authenticated_session, take_expired_session_from_state,
    };
    use futures_util::{SinkExt, StreamExt};
    use serde_json::{Value, json};
    use tokio::net::TcpListener;
    use tokio::time::sleep;
    use tokio_tungstenite::{
        accept_async,
        tungstenite::{
            Message,
            protocol::{CloseFrame, frame::coding::CloseCode},
        },
    };
    use wc_protocol::{
        caip::NamespaceKey,
        did::DidPkh,
        key::X25519PublicKey,
        pairing::PairingSymKey,
        relay::RelayTopic,
        session::{
            AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
            CacaoSignatureType, CacaoSignatureValue, DappMetadata, JsonRpcRequest,
            RelayProtocolOptions, Session, SessionAuthenticateParams, SessionNamespace,
            SessionParticipant, SessionTransportType, SignMethod,
        },
    };

    use crate::{
        PairingClientError, RelayReconnectConfig, SingleSessionRelayConfig,
        low_level::{PairingSubscription, SessionSubscription},
    };

    const FUTURE_SESSION_EXPIRY: u64 = 4_102_444_800;

    #[test]
    fn client_config_uses_default_event_queue_capacity() {
        let pairing = SingleSessionRelayConfig::new("project", [7; 32], "subject");
        let config = SingleSessionClientConfig::new(pairing);

        assert_eq!(
            config.max_queued_events(),
            DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY
        );
        assert_eq!(
            config.automatic_reconnect_cooldown(),
            DEFAULT_SINGLE_SESSION_CLIENT_RECONNECT_COOLDOWN
        );
        assert_eq!(
            config.receive_timeouts_before_reconnect(),
            DEFAULT_SINGLE_SESSION_CLIENT_RECEIVE_TIMEOUTS_BEFORE_RECONNECT
        );
    }

    #[test]
    fn client_config_sets_runtime_limits() {
        let pairing = SingleSessionRelayConfig::new("project", [7; 32], "subject");
        let config = SingleSessionClientConfig::new(pairing)
            .with_max_queued_events(2)
            .with_automatic_reconnect_cooldown(Duration::from_millis(17))
            .with_receive_timeouts_before_reconnect(NonZeroUsize::new(3).expect("non-zero"));

        assert_eq!(config.max_queued_events(), 2);
        assert_eq!(
            config.automatic_reconnect_cooldown(),
            Duration::from_millis(17)
        );
        assert_eq!(
            config.receive_timeouts_before_reconnect(),
            NonZeroUsize::new(3).expect("non-zero")
        );
    }

    #[test]
    #[should_panic(expected = "automatic reconnect cooldown must be non-zero")]
    fn client_config_rejects_zero_automatic_reconnect_cooldown() {
        let pairing = SingleSessionRelayConfig::new("project", [7; 32], "subject");
        let _config = SingleSessionClientConfig::new(pairing)
            .with_automatic_reconnect_cooldown(Duration::ZERO);
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

    #[test]
    fn expired_session_event_is_taken_once_and_clears_session() {
        let topic = RelayTopic::from_bytes([0x44; 32]);
        let expiry = 1;
        let mut state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
            SessionSubscription::for_test(topic.clone(), PairingSymKey::from_bytes([0x55; 32])),
            test_session(topic.clone(), expiry),
        )));

        let expired = take_expired_session_from_state(&mut state, expiry)
            .expect("expired session event is emitted");

        assert_eq!(expired.topic(), &topic);
        assert_eq!(expired.expiry(), expiry);
        assert!(matches!(state, SingleSessionClientState::Idle));
        assert_eq!(take_expired_session_from_state(&mut state, expiry), None);
    }

    #[test]
    fn authenticated_session_uses_responder_as_controller() -> Result<(), Box<dyn std::error::Error>>
    {
        let pairing_topic = RelayTopic::from_bytes([0x52; 32]);
        let session_topic = RelayTopic::from_bytes([0x53; 32]);
        let responder_public_key = X25519PublicKey::from_bytes([0x54; 32]);
        let wallet_metadata = test_metadata("Wallet");
        let namespaces = BTreeMap::from([(
            NamespaceKey::parse("eip155")?,
            SessionNamespace {
                chains: Some(vec!["eip155:1".parse()?]),
                accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".parse()?],
                methods: vec!["personal_sign".parse()?],
                events: Vec::new(),
            },
        )]);
        let cacaos = vec![test_cacao()?];
        let subscription = PairingSubscription::for_test(
            pairing_topic.clone(),
            PairingSymKey::from_bytes([0x55; 32]),
        );

        let session = authenticated_session(
            &subscription,
            &auth_request()?,
            session_topic.clone(),
            responder_public_key.clone(),
            wallet_metadata.clone(),
            cacaos.clone(),
            namespaces.clone(),
        )?;

        assert_eq!(session.topic, session_topic);
        assert_eq!(session.pairing_topic, pairing_topic);
        assert!(session.acknowledged);
        assert_eq!(session.controller, responder_public_key);
        assert_eq!(session.self_participant.metadata, wallet_metadata);
        assert_eq!(session.authentication, Some(cacaos));
        assert_eq!(session.namespaces, namespaces);
        assert_eq!(session.transport_type, Some(SessionTransportType::Relay));

        Ok(())
    }

    #[test]
    fn active_session_tracks_one_shot_session_request_decisions() {
        let topic = RelayTopic::from_bytes([0x56; 32]);
        let mut session = ActiveSession::new(
            SessionSubscription::for_test(topic.clone(), PairingSymKey::from_bytes([0x57; 32])),
            test_session(topic.clone(), FUTURE_SESSION_EXPIRY),
        );

        assert!(session.mark_session_request_pending(42));
        assert!(!session.mark_session_request_pending(42));
        assert!(session.ensure_pending_session_request(42).is_ok());

        session.complete_session_request(42);

        match session
            .ensure_pending_session_request(42)
            .expect_err("completed request decision is no longer pending")
        {
            SingleSessionClientError::SessionRequestDecisionMissing {
                topic: actual_topic,
                request_id,
            } => {
                assert_eq!(actual_topic, topic);
                assert_eq!(request_id, 42);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn active_session_tracks_one_shot_session_update_decisions() {
        let topic = RelayTopic::from_bytes([0x58; 32]);
        let mut session = ActiveSession::new(
            SessionSubscription::for_test(topic.clone(), PairingSymKey::from_bytes([0x59; 32])),
            test_session(topic.clone(), FUTURE_SESSION_EXPIRY),
        );

        assert!(session.mark_session_update_pending(99));
        assert!(!session.mark_session_update_pending(99));
        assert!(session.ensure_pending_session_update(99).is_ok());

        session.complete_session_update(99);

        match session
            .ensure_pending_session_update(99)
            .expect_err("completed update decision is no longer pending")
        {
            SingleSessionClientError::SessionUpdateDecisionMissing {
                topic: actual_topic,
                request_id,
            } => {
                assert_eq!(actual_topic, topic);
                assert_eq!(request_id, 99);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reconnect_resubscribes_active_pairing_topic() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x45; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let _first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("resubscribed-pairing"),
            )
            .await;
            sleep(Duration::from_millis(30)).await;
        });

        let config = reconnect_test_config(address);
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Pairing(PairingSubscription::for_test(
            topic.clone(),
            PairingSymKey::from_bytes([0x46; 32]),
        ));

        client.reconnect().await.expect("reconnects");

        match &client.state {
            SingleSessionClientState::Pairing(subscription) => {
                assert_eq!(subscription.topic(), &topic);
                assert_eq!(subscription.subscription_id(), "resubscribed-pairing");
            }
            other => panic!("unexpected state: {other:?}"),
        }

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn reconnect_resubscribes_active_session_topic() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x47; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let _first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("resubscribed-session"),
            )
            .await;
            sleep(Duration::from_millis(30)).await;
        });

        let config = reconnect_test_config(address);
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
            SessionSubscription::for_test(topic.clone(), PairingSymKey::from_bytes([0x48; 32])),
            test_session(topic.clone(), FUTURE_SESSION_EXPIRY),
        )));

        client.reconnect().await.expect("reconnects");

        match &client.state {
            SingleSessionClientState::Session(session) => {
                assert_eq!(session.subscription.topic(), &topic);
                assert_eq!(
                    session.subscription.subscription_id(),
                    "resubscribed-session"
                );
                assert_eq!(session.session.topic, topic);
            }
            other => panic!("unexpected state: {other:?}"),
        }

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn next_event_reconnects_pairing_topic_after_close() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x49; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let mut first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");
            send_close_frame(&mut first_websocket).await;

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("poll-resubscribed-pairing"),
            )
            .await;
            sleep(Duration::from_millis(100)).await;
        });

        let config = reconnect_test_config(address);
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Pairing(PairingSubscription::for_test(
            topic.clone(),
            PairingSymKey::from_bytes([0x4a; 32]),
        ));

        let error = client
            .next_event()
            .await
            .expect_err("poll should reconnect and then time out waiting for data");

        assert_receive_timed_out(error);
        match &client.state {
            SingleSessionClientState::Pairing(subscription) => {
                assert_eq!(subscription.topic(), &topic);
                assert_eq!(subscription.subscription_id(), "poll-resubscribed-pairing");
            }
            other => panic!("unexpected state: {other:?}"),
        }

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn next_event_reconnects_session_topic_after_close() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x4b; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let mut first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");
            send_close_frame(&mut first_websocket).await;

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("poll-resubscribed-session"),
            )
            .await;
            sleep(Duration::from_millis(100)).await;
        });

        let config = reconnect_test_config(address);
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
            SessionSubscription::for_test(topic.clone(), PairingSymKey::from_bytes([0x4c; 32])),
            test_session(topic.clone(), FUTURE_SESSION_EXPIRY),
        )));

        let error = client
            .next_event()
            .await
            .expect_err("poll should reconnect and then time out waiting for data");

        assert_receive_timed_out(error);
        match &client.state {
            SingleSessionClientState::Session(session) => {
                assert_eq!(session.subscription.topic(), &topic);
                assert_eq!(
                    session.subscription.subscription_id(),
                    "poll-resubscribed-session"
                );
                assert_eq!(session.session.topic, topic);
            }
            other => panic!("unexpected state: {other:?}"),
        }

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn next_event_reconnect_cooldown_blocks_repeated_close_loop() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x4d; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let mut first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");
            send_close_frame(&mut first_websocket).await;

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("cooldown-resubscribed"),
            )
            .await;
            send_close_frame(&mut second_websocket).await;
        });

        let config = reconnect_test_config(address)
            .with_automatic_reconnect_cooldown(Duration::from_secs(60));
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Pairing(PairingSubscription::for_test(
            topic.clone(),
            PairingSymKey::from_bytes([0x4e; 32]),
        ));

        let first_error = client
            .next_event()
            .await
            .expect_err("first poll reconnects once and sees the replacement close");
        assert!(first_error.is_relay_connection_closed());

        let second_error = client
            .next_event()
            .await
            .expect_err("cooldown should block a second automatic reconnect");
        match second_error {
            SingleSessionClientError::ReconnectCoolingDown { remaining } => {
                assert!(remaining > Duration::ZERO);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert_eq!(
            client.connection_state(),
            SingleSessionClientConnectionState::Unavailable
        );

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn repeated_receive_timeouts_reconnect_active_pairing_topic() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let topic = RelayTopic::from_bytes([0x4f; 32]);
        let server_topic = topic.clone();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.expect("accepts first client");
            let _first_websocket = accept_async(first_stream)
                .await
                .expect("accepts first websocket");

            let (second_stream, _) = listener.accept().await.expect("accepts second client");
            let mut second_websocket = accept_async(second_stream)
                .await
                .expect("accepts second websocket");
            let subscribe = read_json_frame(&mut second_websocket).await;
            assert_eq!(subscribe["method"], "irn_subscribe");
            assert_eq!(subscribe["params"]["topic"], server_topic.as_str());
            send_result(
                &mut second_websocket,
                &subscribe,
                json!("timeout-resubscribed"),
            )
            .await;
            sleep(Duration::from_millis(80)).await;
        });

        let config = reconnect_test_config(address)
            .with_automatic_reconnect_cooldown(Duration::from_millis(1))
            .with_receive_timeouts_before_reconnect(NonZeroUsize::new(2).expect("non-zero"));
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to first relay websocket");
        client.state = SingleSessionClientState::Pairing(PairingSubscription::for_test(
            topic.clone(),
            PairingSymKey::from_bytes([0x50; 32]),
        ));

        let first_error = client
            .next_event()
            .await
            .expect_err("first quiet poll only records one timeout");
        assert_receive_timed_out(first_error);

        let second_error = client
            .next_event()
            .await
            .expect_err("second quiet poll reconnects and then times out waiting for data");
        assert_receive_timed_out(second_error);
        match &client.state {
            SingleSessionClientState::Pairing(subscription) => {
                assert_eq!(subscription.topic(), &topic);
                assert_eq!(subscription.subscription_id(), "timeout-resubscribed");
            }
            other => panic!("unexpected state: {other:?}"),
        }

        server.await.expect("server task joins");
    }

    #[tokio::test]
    async fn shutdown_blocks_next_event_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binds local websocket listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accepts client");
            let mut websocket = accept_async(stream).await.expect("accepts websocket");
            while websocket.next().await.is_some() {}
        });

        let config = reconnect_test_config(address);
        let mut client = SingleSessionClient::connect(&config)
            .await
            .expect("connects to relay websocket");
        client
            .shutdown()
            .await
            .expect("explicit shutdown closes the relay socket");

        assert_eq!(
            client.connection_state(),
            SingleSessionClientConnectionState::DisconnectedByUser
        );
        assert!(matches!(
            client
                .next_event()
                .await
                .expect_err("shutdown disables automatic reconnect"),
            SingleSessionClientError::DisconnectedByUser
        ));

        server.await.expect("server task joins");
    }

    fn test_session(topic: RelayTopic, expiry: u64) -> Session {
        let public_key = X25519PublicKey::from_bytes([0x66; 32]);
        let metadata = test_metadata("Test");

        Session {
            topic,
            pairing_topic: RelayTopic::from_bytes([0x77; 32]),
            relay: RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: None,
            },
            expiry,
            acknowledged: true,
            controller: public_key.clone(),
            namespaces: BTreeMap::new(),
            required_namespaces: BTreeMap::new(),
            optional_namespaces: BTreeMap::new(),
            session_properties: None,
            scoped_properties: None,
            session_config: None,
            self_participant: SessionParticipant {
                public_key: public_key.clone(),
                metadata: metadata.clone(),
            },
            peer: SessionParticipant {
                public_key,
                metadata,
            },
            authentication: None,
            wallet_pay_result: None,
            transport_type: Some(SessionTransportType::Relay),
        }
    }

    fn auth_request()
    -> Result<JsonRpcRequest<SessionAuthenticateParams>, Box<dyn std::error::Error>> {
        Ok(JsonRpcRequest::new(
            42,
            SignMethod::SessionAuthenticate,
            SessionAuthenticateParams {
                requester: SessionParticipant {
                    public_key: X25519PublicKey::from_bytes([0x67; 32]),
                    metadata: test_metadata("Dapp"),
                },
                auth_payload: AuthPayload {
                    kind: CacaoHeaderType::Caip122,
                    chains: vec!["eip155:1".parse()?],
                    aud: "https://example.com/login".to_owned(),
                    domain: "example.com".to_owned(),
                    version: "1".to_owned(),
                    nonce: "1234567890".to_owned(),
                    iat: "2026-05-29T12:00:00.000Z".to_owned(),
                    statement: Some("Sign in to Example".to_owned()),
                    exp: None,
                    nbf: None,
                    request_id: None,
                    resources: Vec::new(),
                },
                expiry_timestamp: FUTURE_SESSION_EXPIRY,
            },
        ))
    }

    fn test_cacao() -> Result<Cacao, Box<dyn std::error::Error>> {
        Ok(Cacao {
            h: CacaoHeader {
                kind: CacaoHeaderType::Caip122,
            },
            p: CacaoPayload {
                iss: DidPkh::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")?,
                domain: "example.com".to_owned(),
                aud: "https://example.com/login".to_owned(),
                version: "1".to_owned(),
                nonce: "1234567890".to_owned(),
                iat: "2026-05-29T12:00:00.000Z".to_owned(),
                statement: Some("Sign in to Example".to_owned()),
                exp: None,
                nbf: None,
                request_id: None,
                resources: Vec::new(),
            },
            s: CacaoSignature {
                kind: CacaoSignatureType::Eip191,
                signature: CacaoSignatureValue::from_wire("0x00"),
                meta: None,
            },
        })
    }

    fn test_metadata(name: &str) -> DappMetadata {
        DappMetadata {
            name: name.to_owned(),
            description: name.to_owned(),
            url: "https://example.com".to_owned(),
            icons: Vec::new(),
            verify_url: None,
            redirect: None,
        }
    }

    fn reconnect_test_config(address: std::net::SocketAddr) -> SingleSessionClientConfig {
        let mut pairing = SingleSessionRelayConfig::new("project", [7; 32], "subject");
        pairing.relay_url = format!("ws://{address}");
        pairing.receive_timeout = Duration::from_millis(20);
        SingleSessionClientConfig::new(pairing).with_reconnect(RelayReconnectConfig::new(
            NonZeroUsize::new(2).expect("non-zero"),
            Duration::ZERO,
            Duration::ZERO,
        ))
    }

    fn assert_receive_timed_out(error: SingleSessionClientError) {
        match error {
            SingleSessionClientError::Pairing {
                source: PairingClientError::ReceiveTimedOut { timeout },
            } => assert_eq!(timeout, Duration::from_millis(20)),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    async fn read_json_frame(
        websocket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) -> Value {
        let message = websocket
            .next()
            .await
            .expect("peer sends frame")
            .expect("frame is readable");

        match message {
            Message::Text(text) => {
                serde_json::from_str::<Value>(&text).expect("text frame is json")
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    async fn send_result(
        websocket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        request: &Value,
        result: Value,
    ) {
        websocket
            .send(Message::Text(
                json!({
                    "id": request["id"],
                    "jsonrpc": "2.0",
                    "result": result,
                })
                .to_string()
                .into(),
            ))
            .await
            .expect("sends result");
    }

    async fn send_close_frame(
        websocket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    ) {
        websocket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "server restart".into(),
            })))
            .await
            .expect("sends close frame");
    }
}
