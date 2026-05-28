use std::collections::{BTreeMap, VecDeque};

use wc_protocol::{
    relay::RelayTopic,
    session::{JsonRpcError, JsonRpcRequest, Session, SessionDeleteParams, SessionProposeParams},
};

use crate::pairing::{
    PairingClient, PairingClientConfig, PairingClientError, PairingPayload, PairingReceivedMessage,
    PairingSubscription, SessionClientEvent, SessionLifecycleRequest, SessionProposalApproval,
    SessionReceivedMessage, SessionSubscription,
};

/// Runtime client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pairing: PairingClientConfig,
}

impl ClientConfig {
    /// Builds a client configuration from the native pairing relay config.
    #[must_use]
    pub const fn new(pairing: PairingClientConfig) -> Self {
        Self { pairing }
    }

    /// Native pairing relay configuration used by the first runtime client.
    #[must_use]
    pub const fn pairing(&self) -> &PairingClientConfig {
        &self.pairing
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
    queued_events: VecDeque<ClientEvent>,
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
            queued_events: VecDeque::new(),
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
        let subscription = self
            .pairing
            .subscribe_pairing(&pairing_uri)
            .await
            .map_err(ClientError::from)?;
        let topic = subscription.topic().clone();

        self.pairings.insert(topic.clone(), subscription);
        self.queued_events
            .extend(fetched.into_iter().map(ClientEvent::from_pairing_message));

        Ok(topic)
    }

    /// Waits for the next queued, pairing-topic, or session-topic event.
    ///
    /// Session messages are exposed as `SessionClientEvent`; invalid
    /// `wc_sessionRequest` payloads are still auto-rejected by the lower-level
    /// receive path before being returned as `RejectedSessionRequest`.
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
                return Ok(Some(ClientEvent::Session(event)));
            }
        }

        if let Some(subscription) = self.pairings.values().next().cloned() {
            let message = self
                .pairing
                .next_pairing_message(&subscription)
                .await
                .map_err(ClientError::from)?;
            return Ok(message.map(ClientEvent::from_pairing_message));
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
}

impl From<PairingClientError> for ClientError {
    fn from(source: PairingClientError) -> Self {
        Self::Pairing { source }
    }
}
