//! Pairing-topic receive behavior.

use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use tokio::time::timeout;
use wc_protocol::{
    dto::pairing::{PairingDeleteParams, PairingJsonRpcRequest, PairingMethod, PairingPingParams},
    envelope::{Envelope, EnvelopeEncoding, EnvelopeError},
    key::{X25519KeyPair, X25519KeyPairError, derive_shared_sym_key, derive_topic_from_sym_key},
    namespaces::{NamespaceValidationError, validate_approved_namespaces},
    pairing::{PairingSymKey, PairingUri, PairingUriError},
    pairing_message::{PairingMessage, PairingMessageError, PairingMessageMethod},
    relay::{
        DEFAULT_RELAY_URL, IrnPublish, IrnSubscriptionData, RelayAuthError, RelayAuthToken,
        RelayConnectionUrl, RelayTopic, relay_auth_audience,
    },
    session::{
        DappMetadata, JsonRpcError, JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResponse,
        RelayProtocolOptions, ScopedProperties, Session, SessionConfig, SessionNamespaces,
        SessionParticipant, SessionProperties, SessionProposeParams, SessionProposeResult,
        SessionSettleParams, SessionSettleResponse, SessionTransportType, SignMethod,
        session_propose_error_response,
    },
};
use wc_transport::{RelayClient, RelayClientConfig, RelayClientError};

static SIGN_RPC_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Default wait time for one live pairing-topic message.
pub const DEFAULT_PAIRING_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default session lifetime used by the first approval primitive.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/constants/session.ts#L1-L5>
///
/// > export const SESSION_EXPIRY = SEVEN_DAYS;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L482-L486>
///
/// > const sessionSettle = {
/// > relay: { protocol: relayProtocol ?? "irn" },
/// > namespaces,
/// > expiry: calcExpiry(SESSION_EXPIRY),
pub const DEFAULT_SESSION_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Relay tag used for approved `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L13-L17>
///
/// > res: { ttl: FIVE_MINUTES, prompt: false, tag: 1101 }
pub const SESSION_PROPOSE_RESPONSE_TAG: u64 = 1101;

/// Relay tag used for rejected `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L18-L22>
///
/// > reject: { ttl: FIVE_MINUTES, prompt: false, tag: 1120 }
pub const SESSION_PROPOSE_REJECT_TAG: u64 = 1120;

/// Relay tag used for `wc_sessionSettle` requests.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L29-L34>
///
/// > req: { ttl: FIVE_MINUTES, prompt: false, tag: 1102 }
pub const SESSION_SETTLE_REQUEST_TAG: u64 = 1102;

/// Relay tag used for `wc_sessionSettle` responses.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > // Success result
/// > true
/// > Tag     | 1103
pub const SESSION_SETTLE_RESPONSE_TAG: u64 = 1103;

/// Relay retention window for approved `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L13-L17>
///
/// > res: { ttl: FIVE_MINUTES, prompt: false, tag: 1101 }
pub const SESSION_PROPOSE_RESPONSE_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for rejected `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L18-L22>
///
/// > reject: { ttl: FIVE_MINUTES, prompt: false, tag: 1120 }
pub const SESSION_PROPOSE_REJECT_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for `wc_sessionSettle` requests.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L29-L34>
///
/// > req: { ttl: FIVE_MINUTES, prompt: false, tag: 1102 }
pub const SESSION_SETTLE_REQUEST_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for `wc_sessionSettle` responses.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > TTL     | 300
/// > Tag     | 1103
pub const SESSION_SETTLE_RESPONSE_TTL_SECONDS: u64 = 5 * 60;

/// Configuration for a native pairing-topic relay client.
///
/// The pairing receive path uses Relay Auth query parameters before opening the
/// WebSocket connection.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
///
/// > WalletConnect expects an `Authorization: Bearer <signed jwt>` header when establishing the Websocket connection.
/// > Where websocket headers are not supported i.e. browsers, use the URL query param `?auth=<signed jwt>`.
///
/// # Examples
///
/// ```
/// use wc_core::{PairingClientConfig, DEFAULT_PAIRING_RECEIVE_TIMEOUT};
///
/// let config = PairingClientConfig::new("project-id", [7; 32], "client-subject");
///
/// assert_eq!(config.project_id, "project-id");
/// assert_eq!(config.receive_timeout, DEFAULT_PAIRING_RECEIVE_TIMEOUT);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingClientConfig {
    /// Reown/WalletConnect Cloud project ID used by the public relay.
    pub project_id: String,
    /// Relay WebSocket endpoint.
    pub relay_url: String,
    /// User-agent value placed in the relay connection URL.
    pub user_agent: String,
    /// Ed25519 seed used to sign the Relay Auth JWT.
    pub auth_seed: [u8; 32],
    /// Relay Auth JWT `sub` claim.
    pub auth_subject: String,
    /// Relay Auth JWT lifetime in seconds.
    pub auth_ttl_seconds: u64,
    /// Maximum time spent waiting for one live pairing message.
    pub receive_timeout: Duration,
    /// Runtime limits for the underlying relay client.
    pub relay_client: RelayClientConfig,
}

impl PairingClientConfig {
    /// Builds a config with the public relay URL and conservative runtime defaults.
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        auth_seed: [u8; 32],
        auth_subject: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            user_agent: "wc-2/rust-poc-0.1.0/macos/native".to_owned(),
            auth_seed,
            auth_subject: auth_subject.into(),
            auth_ttl_seconds: 86_400,
            receive_timeout: DEFAULT_PAIRING_RECEIVE_TIMEOUT,
            relay_client: RelayClientConfig::default(),
        }
    }
}

/// Native client for receiving encrypted messages on a pairing topic.
///
/// This is the first core behavior layer above the relay transport. It parses
/// and checks pairing metadata, fetches retained relay messages, subscribes to
/// the pairing topic, and decodes encrypted pairing-topic payloads.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
///
/// > Used to propose a session through topic A. Requires a success response
/// > with associated data.
///
/// # Examples
///
/// ```no_run
/// use wc_core::{PairingClient, PairingClientConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = PairingClient::connect(&PairingClientConfig::new(
///     "project-id",
///     [7; 32],
///     "client-subject",
/// ))
/// .await?;
///
/// assert_eq!(client.status(), 101);
/// # Ok(())
/// # }
/// ```
pub struct PairingClient {
    relay: RelayClient,
    receive_timeout: Duration,
}

impl PairingClient {
    /// Opens an authenticated relay connection for pairing-topic operations.
    pub async fn connect(config: &PairingClientConfig) -> Result<Self, PairingClientError> {
        let url = relay_connection_url(config, now_unix_seconds()?)?;
        let relay = RelayClient::connect_with_config(url.as_str(), config.relay_client.clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(Self {
            relay,
            receive_timeout: config.receive_timeout,
        })
    }

    /// HTTP status returned during the relay WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.relay.status()
    }

    /// Fetches retained messages for a parsed pairing URI.
    ///
    /// Relay clients fetch before subscribing so messages published while a
    /// wallet was offline are not skipped.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
    pub async fn fetch_pairing_messages(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<Vec<PairingReceivedMessage>, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let response = self
            .relay
            .fetch_messages(pairing.topic())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        response
            .messages
            .into_iter()
            .map(|data| decode_subscription_data(data, pairing.sym_key()))
            .collect()
    }

    /// Subscribes to the relay topic carried by a parsed pairing URI.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn subscribe_pairing(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<PairingSubscription, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let subscription_id = self
            .relay
            .subscribe(pairing.topic().clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(PairingSubscription {
            topic: pairing.topic().clone(),
            sym_key: pairing.sym_key().clone(),
            subscription_id,
        })
    }

    /// Waits for one live message for a pairing subscription.
    ///
    /// The underlying relay client acknowledges relay pushes before returning
    /// them. This method then checks the topic and decrypts the `WalletConnect`
    /// envelope with the pairing symmetric key.
    pub async fn next_pairing_message(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<Option<PairingReceivedMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(self.receive_timeout, self.relay.next_message())
            .await
            .map_err(|_| PairingClientError::ReceiveTimedOut {
                timeout: self.receive_timeout,
            })?
            .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        if subscription_data.data.topic != subscription.topic {
            return Err(PairingClientError::UnexpectedTopic {
                expected: subscription.topic.clone(),
                actual: subscription_data.data.topic,
            });
        }

        decode_subscription_data(subscription_data.data, &subscription.sym_key).map(Some)
    }

    /// Unsubscribes the relay connection from a pairing topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
    ///
    /// > Used when a client unsubscribes a given topic.
    pub async fn unsubscribe_pairing(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<bool, PairingClientError> {
        self.relay
            .unsubscribe(&subscription.topic, &subscription.subscription_id)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }

    /// Approves a `wc_sessionPropose` request and publishes the settlement request.
    ///
    /// The first approval primitive follows the maintained Sign Client order:
    /// derive the session topic, subscribe to it, publish the proposal success
    /// response on the pairing topic, then publish `wc_sessionSettle` on the
    /// derived session topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L475-L498>
    ///
    /// > const selfPublicKey = await this.client.core.crypto.generateKeyPair();
    /// > const sessionTopic = await this.client.core.crypto.generateSharedKey(
    /// > await this.client.core.relayer.subscribe(sessionTopic, {
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L528-L548>
    ///
    /// > await this.sendApproveSession({
    /// > sessionTopic,
    /// > proposal,
    pub async fn approve_session_proposal(
        &mut self,
        subscription: &PairingSubscription,
        proposal: &JsonRpcRequest<SessionProposeParams>,
        approval: SessionProposalApproval,
    ) -> Result<ApprovedSession, PairingClientError> {
        let responder =
            X25519KeyPair::generate().map_err(|source| PairingClientError::KeyPair { source })?;
        let settle_request_id = next_sign_rpc_id()?;
        let approval_messages = session_proposal_approval_publishes(
            subscription,
            proposal,
            approval,
            &responder,
            settle_request_id,
        )?;
        let session_subscription_id = self
            .relay
            .subscribe(approval_messages.session_topic.clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        let proposal_response_ack = self
            .relay
            .publish(approval_messages.proposal_response)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;
        let session_settle_ack = self
            .relay
            .publish(approval_messages.session_settle)
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(ApprovedSession {
            subscription: SessionSubscription {
                topic: approval_messages.session_topic,
                sym_key: approval_messages.session_sym_key,
                subscription_id: session_subscription_id,
            },
            responder_public_key: responder.public_key().clone(),
            session_settle_request_id: settle_request_id,
            session: approval_messages.session,
            proposal_response_ack,
            session_settle_ack,
        })
    }

    /// Waits for the peer response to the `wc_sessionSettle` request.
    ///
    /// The peer handles `wc_sessionSettle` on the derived session topic and
    /// responds with JSON-RPC `result: true` or a JSON-RPC error on the same
    /// topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2269-L2274>
    ///
    /// > await this.sendResult<"wc_sessionSettle">({
    /// > id: payload.id,
    /// > topic,
    /// > result: true,
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2278-L2283>
    ///
    /// > await this.sendError({
    /// > id,
    /// > topic,
    /// > error: err,
    pub async fn next_session_settle_response(
        &mut self,
        approved: &ApprovedSession,
    ) -> Result<Option<SessionSettleResponseMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(
            self.receive_timeout,
            self.relay.next_message_for_topic(approved.session_topic()),
        )
        .await
        .map_err(|_| PairingClientError::ReceiveTimedOut {
            timeout: self.receive_timeout,
        })?
        .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        decode_session_settle_response_data(
            subscription_data.data,
            approved.subscription(),
            approved.session_settle_request_id,
        )
        .map(Some)
    }

    /// Publishes a `wc_sessionPropose` JSON-RPC error response.
    ///
    /// This rejects the proposal on the pairing topic. Approval is intentionally
    /// separate because it must create a responder key pair and then settle a
    /// session on the derived session topic.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L593-L599>
    ///
    /// > await this.sendError({
    /// > id,
    /// > topic: pairingTopic,
    /// > error: reason,
    pub async fn reject_session_proposal(
        &mut self,
        subscription: &PairingSubscription,
        proposal_id: u64,
        error: JsonRpcError,
    ) -> Result<bool, PairingClientError> {
        let publish = session_proposal_reject_publish(subscription, proposal_id, error)?;
        self.relay
            .publish(publish)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }
}

/// Application data needed to approve a session proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProposalApproval {
    /// Relay protocol selected for the session.
    pub relay: RelayProtocolOptions,
    /// Approved namespaces with accounts.
    pub namespaces: SessionNamespaces,
    /// Wallet metadata sent as the session controller.
    pub wallet_metadata: DappMetadata,
    /// Absolute session expiry timestamp in unix seconds.
    pub expiry: u64,
    /// Optional string session properties.
    pub session_properties: Option<SessionProperties>,
    /// Optional namespace-scoped properties.
    pub scoped_properties: Option<ScopedProperties>,
    /// Optional session configuration.
    pub session_config: Option<SessionConfig>,
    /// Optional proposal subrequest responses.
    pub proposal_requests_responses: Option<serde_json::Value>,
}

impl SessionProposalApproval {
    /// Builds approval data with the default `irn` relay protocol.
    #[must_use]
    pub fn new(namespaces: SessionNamespaces, wallet_metadata: DappMetadata, expiry: u64) -> Self {
        Self {
            relay: RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: None,
            },
            namespaces,
            wallet_metadata,
            expiry,
            session_properties: None,
            scoped_properties: None,
            session_config: None,
            proposal_requests_responses: None,
        }
    }
}

/// Active relay subscription for one approved session topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSubscription {
    topic: RelayTopic,
    sym_key: PairingSymKey,
    subscription_id: String,
}

impl SessionSubscription {
    /// Session relay topic registered on the connection.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Symmetric key derived for the approved session topic.
    #[must_use]
    pub const fn sym_key(&self) -> &PairingSymKey {
        &self.sym_key
    }

    /// Subscription ID returned by `irn_subscribe`.
    #[must_use]
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }
}

/// Result of publishing the first session approval messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedSession {
    subscription: SessionSubscription,
    responder_public_key: wc_protocol::key::X25519PublicKey,
    session_settle_request_id: u64,
    session: Session,
    proposal_response_ack: bool,
    session_settle_ack: bool,
}

impl ApprovedSession {
    /// Active relay subscription for the approved session topic.
    #[must_use]
    pub const fn subscription(&self) -> &SessionSubscription {
        &self.subscription
    }

    /// Derived session topic.
    #[must_use]
    pub const fn session_topic(&self) -> &RelayTopic {
        self.subscription.topic()
    }

    /// Wallet responder public key sent to the dapp.
    #[must_use]
    pub const fn responder_public_key(&self) -> &wc_protocol::key::X25519PublicKey {
        &self.responder_public_key
    }

    /// JSON-RPC id used for the `wc_sessionSettle` request.
    #[must_use]
    pub const fn session_settle_request_id(&self) -> u64 {
        self.session_settle_request_id
    }

    /// Session record before the peer acknowledges `wc_sessionSettle`.
    #[must_use]
    pub const fn pending_session(&self) -> &Session {
        &self.session
    }

    /// Returns the session record after a successful `wc_sessionSettle` response.
    ///
    /// The maintained Sign Client stores the session before publishing approval,
    /// then flips `acknowledged` after receiving the matching settle response.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L506-L524>
    ///
    /// > const session: SessionTypes.Struct = {
    /// > acknowledged: false,
    /// > await this.client.session.set(sessionTopic, session);
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2288-L2299>
    ///
    /// > await this.client.session.update(topic, { acknowledged: true });
    pub fn acknowledged_session(
        &self,
        response: &SessionSettleResponseMessage,
    ) -> Result<Session, PairingClientError> {
        if response.topic() != self.session_topic() {
            return Err(PairingClientError::UnexpectedTopic {
                expected: self.session_topic().clone(),
                actual: response.topic().clone(),
            });
        }

        match response.payload() {
            SessionSettleResponsePayload::Success(response) => {
                if response.id != self.session_settle_request_id {
                    return Err(PairingClientError::SessionResponseIdMismatch {
                        expected: self.session_settle_request_id,
                        actual: response.id,
                    });
                }

                let mut session = self.session.clone();
                session.acknowledged = true;
                Ok(session)
            }
            SessionSettleResponsePayload::Error(response) => {
                Err(PairingClientError::SessionSettleRejected {
                    response: response.clone(),
                })
            }
        }
    }

    /// Relay ack for the proposal success response publish.
    #[must_use]
    pub const fn proposal_response_ack(&self) -> bool {
        self.proposal_response_ack
    }

    /// Relay ack for the `wc_sessionSettle` request publish.
    #[must_use]
    pub const fn session_settle_ack(&self) -> bool {
        self.session_settle_ack
    }
}

/// Peer response to the `wc_sessionSettle` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSettleResponseMessage {
    topic: RelayTopic,
    encoded_message_len: usize,
    published_at: u64,
    tag: Option<u64>,
    payload: SessionSettleResponsePayload,
}

impl SessionSettleResponseMessage {
    /// Relay topic that delivered this response.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Length of the encrypted relay message string before decoding.
    #[must_use]
    pub const fn encoded_message_len(&self) -> usize {
        self.encoded_message_len
    }

    /// Relay server publish timestamp in milliseconds.
    #[must_use]
    pub const fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Optional `WalletConnect` relay tag.
    #[must_use]
    pub const fn tag(&self) -> Option<u64> {
        self.tag
    }

    /// Parsed JSON-RPC settle response.
    #[must_use]
    pub const fn payload(&self) -> &SessionSettleResponsePayload {
        &self.payload
    }
}

/// Typed `wc_sessionSettle` response payload.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > // Success result
/// > true
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L28-L45>
///
/// > result,
/// > error: formatErrorMessage(error, data),
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSettleResponsePayload {
    /// Peer accepted the session settlement request.
    Success(SessionSettleResponse),
    /// Peer rejected the session settlement request.
    Error(JsonRpcErrorResponse),
}

/// Active relay subscription for one pairing topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSubscription {
    topic: RelayTopic,
    sym_key: PairingSymKey,
    subscription_id: String,
}

impl PairingSubscription {
    /// Pairing relay topic registered on the connection.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Subscription ID returned by `irn_subscribe`.
    #[must_use]
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }
}

/// Decrypted pairing-topic message plus relay delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingReceivedMessage {
    topic: RelayTopic,
    encoded_message_len: usize,
    published_at: u64,
    tag: Option<u64>,
    message: PairingMessage,
    payload: PairingPayload,
}

impl PairingReceivedMessage {
    /// Relay topic that delivered this message.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Length of the encrypted relay message string before decoding.
    #[must_use]
    pub const fn encoded_message_len(&self) -> usize {
        self.encoded_message_len
    }

    /// Relay server publish timestamp in milliseconds.
    #[must_use]
    pub const fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Optional `WalletConnect` relay tag.
    #[must_use]
    pub const fn tag(&self) -> Option<u64> {
        self.tag
    }

    /// Decrypted and classified pairing-topic payload.
    #[must_use]
    pub const fn message(&self) -> &PairingMessage {
        &self.message
    }

    /// Typed payload parsed from the decrypted pairing-topic JSON.
    #[must_use]
    pub const fn payload(&self) -> &PairingPayload {
        &self.payload
    }
}

/// Typed pairing-topic payload.
///
/// `wc_sessionPropose` is the first Sign API message expected after the wallet
/// subscribes to a pairing topic from a URI.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
///
/// > Used to propose a session through topic A. Requires a success response
/// > with associated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingPayload {
    /// `wc_sessionPropose` Sign API request.
    SessionProposal(Box<JsonRpcRequest<SessionProposeParams>>),
    /// `wc_pairingPing` Pairing API request.
    PairingPing(PairingJsonRpcRequest<PairingPingParams>),
    /// `wc_pairingDelete` Pairing API request.
    PairingDelete(PairingJsonRpcRequest<PairingDeleteParams>),
    /// Known Sign API method whose DTO is not parsed at the pairing layer yet.
    Sign(SignMethod),
    /// JSON-RPC method name is present but not implemented by current DTOs.
    Unknown(String),
    /// JSON has no string `method` field.
    Missing,
}

/// Pairing receive failure.
#[derive(Debug, thiserror::Error)]
pub enum PairingClientError {
    /// The pairing URI was malformed.
    #[error("pairing URI failed")]
    PairingUri {
        /// Source pairing URI parser error.
        #[source]
        source: PairingUriError,
    },

    /// The pairing URI expired before it was used.
    #[error("pairing URI expired")]
    PairingExpired {
        /// Expiry timestamp from the pairing URI.
        expiry_timestamp: u64,
        /// Unix timestamp used for the comparison.
        now_unix_seconds: u64,
    },

    /// Relay Auth JWT construction failed.
    #[error("pairing relay auth failed")]
    RelayAuth {
        /// Source Relay Auth error.
        #[source]
        source: RelayAuthError,
    },

    /// System clock failed while building relay auth or checking expiry.
    #[error("pairing clock failed")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Relay transport or relay JSON-RPC behavior failed.
    #[error("pairing relay failed")]
    Relay {
        /// Source relay client error.
        #[source]
        source: RelayClientError,
    },

    /// Responder X25519 key generation failed.
    #[error("pairing key generation failed")]
    KeyPair {
        /// Source X25519 key-pair error.
        #[source]
        source: X25519KeyPairError,
    },

    /// Approved namespaces do not satisfy the proposal.
    #[error("pairing namespace validation failed")]
    Namespace {
        /// Source namespace validation error.
        #[source]
        source: NamespaceValidationError,
    },

    /// No live pairing message arrived before the configured timeout.
    #[error("pairing receive timed out after {timeout:?}")]
    ReceiveTimedOut {
        /// Configured live receive timeout.
        timeout: Duration,
    },

    /// Relay returned a message for a different topic than this subscription.
    #[error("pairing received unexpected topic")]
    UnexpectedTopic {
        /// Topic from the active subscription.
        expected: RelayTopic,
        /// Topic delivered by the relay.
        actual: RelayTopic,
    },

    /// Relay message envelope decoding, decryption, or JSON parsing failed.
    #[error("pairing message failed")]
    PairingMessage {
        /// Source pairing message error.
        #[source]
        source: PairingMessageError,
    },

    /// Proposal params and active subscription disagree on the pairing topic.
    #[error("session proposal pairing topic does not match active subscription")]
    ProposalPairingTopicMismatch {
        /// Topic from the active pairing subscription.
        expected: RelayTopic,
        /// Topic duplicated in the session proposal params.
        actual: RelayTopic,
    },

    /// Outbound pairing message envelope encryption failed.
    #[error("pairing envelope failed")]
    Envelope {
        /// Source envelope encryption error.
        #[source]
        source: EnvelopeError,
    },

    /// Decrypted JSON did not match the DTO for its classified method.
    #[error("pairing payload DTO failed")]
    PairingPayload {
        /// Source DTO parse error.
        #[source]
        source: serde_json::Error,
    },

    /// Session-topic envelope decoding, decryption, or plaintext handling failed.
    #[error("session envelope failed")]
    SessionEnvelope {
        /// Source envelope failure.
        #[source]
        source: EnvelopeError,
    },

    /// Session-topic decrypted JSON did not match the expected DTO.
    #[error("session payload DTO failed")]
    SessionPayload {
        /// Source DTO parse error.
        #[source]
        source: serde_json::Error,
    },

    /// Session response payload did not carry a numeric JSON-RPC id.
    #[error("session response is missing a numeric id")]
    SessionResponseMissingId,

    /// Session response id did not match the pending request id.
    #[error("session response id does not match the pending request")]
    SessionResponseIdMismatch {
        /// JSON-RPC id from the pending request.
        expected: u64,
        /// JSON-RPC id from the received response.
        actual: u64,
    },

    /// Session settle response was neither a JSON-RPC result nor error.
    #[error("session settle response payload is unsupported")]
    SessionSettleUnsupportedPayload,

    /// Peer rejected the session settlement request.
    #[error("session settle rejected")]
    SessionSettleRejected {
        /// JSON-RPC error response received on the session topic.
        response: JsonRpcErrorResponse,
    },

    /// Sign JSON-RPC ID construction failed.
    #[error("sign rpc id construction failed")]
    SignRpcId {
        /// Source numeric overflow or system-clock failure.
        #[source]
        source: SignRpcIdError,
    },
}

impl PairingClientError {
    /// Parses a pairing URI and preserves the parser as the error source.
    pub fn parse_pairing_uri(uri: &str) -> Result<PairingUri, Self> {
        PairingUri::parse(uri).map_err(|source| Self::PairingUri { source })
    }
}

/// Builds the authenticated relay URL at a specific unix timestamp.
///
/// Keeping timestamp injection here makes Relay Auth testable without sleeping
/// or mocking the system clock.
fn relay_connection_url(
    config: &PairingClientConfig,
    issued_at: u64,
) -> Result<RelayConnectionUrl, PairingClientError> {
    let audience = relay_auth_audience(&config.relay_url);
    let token = RelayAuthToken::sign_with_seed(
        &config.auth_seed,
        &config.auth_subject,
        audience,
        issued_at,
        config.auth_ttl_seconds,
    )
    .map_err(|source| PairingClientError::RelayAuth { source })?;

    Ok(RelayConnectionUrl::new(
        &config.relay_url,
        &config.project_id,
        token.as_str(),
        &config.user_agent,
    ))
}

/// Returns unix seconds for Relay Auth `iat` and pairing expiry comparisons.
///
/// Pairing URI expiry is defined as `expiryTimestamp`; Relay Auth JWTs also
/// carry unix-second `iat` and `exp` claims.
fn now_unix_seconds() -> Result<u64, PairingClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| PairingClientError::Clock { source })?
        .as_secs())
}

/// Returns unix milliseconds for Sign JSON-RPC ID generation.
fn now_unix_millis() -> Result<u64, SignRpcIdError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| SignRpcIdError::Clock { source })?
        .as_millis()
        .try_into()
        .map_err(|_| SignRpcIdError::Overflow)
}

/// Builds a Sign JSON-RPC ID using the same timestamp-plus-entropy layout as JS.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L5-L8>
///
/// > const date = Date.now() * Math.pow(10, entropy);
/// > const extra = Math.floor(Math.random() * Math.pow(10, entropy));
fn next_sign_rpc_id() -> Result<u64, PairingClientError> {
    let entropy = u64::from(SIGN_RPC_ID_COUNTER.fetch_add(1, Ordering::Relaxed) % 1_000);
    now_unix_millis()
        .map_err(|source| PairingClientError::SignRpcId { source })?
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(entropy))
        .ok_or(SignRpcIdError::Overflow)
        .map_err(|source| PairingClientError::SignRpcId { source })
}

/// Rejects pairing URIs that cannot receive valid proposals anymore.
const fn validate_pairing_not_expired(
    pairing: &PairingUri,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    if let Some(expiry_timestamp) = pairing.expiry_timestamp()
        && expiry_timestamp <= now_unix_seconds
    {
        return Err(PairingClientError::PairingExpired {
            expiry_timestamp,
            now_unix_seconds,
        });
    }

    Ok(())
}

/// Converts one relay delivery record into a decrypted pairing message.
///
/// The relay only forwards an opaque string. Pairing-specific decoding starts
/// after topic routing has succeeded.
fn decode_subscription_data(
    data: IrnSubscriptionData,
    sym_key: &PairingSymKey,
) -> Result<PairingReceivedMessage, PairingClientError> {
    let encoded_message_len = data.message.len();
    let message = PairingMessage::decode_relay_message(&data.message, sym_key)
        .map_err(|source| PairingClientError::PairingMessage { source })?;
    let payload = parse_pairing_payload(&message)?;

    Ok(PairingReceivedMessage {
        topic: data.topic,
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        message,
        payload,
    })
}

/// Converts one relay delivery record into a typed `wc_sessionSettle` response.
fn decode_session_settle_response_data(
    data: IrnSubscriptionData,
    subscription: &SessionSubscription,
    expected_id: u64,
) -> Result<SessionSettleResponseMessage, PairingClientError> {
    let encoded_message_len = data.message.len();

    if data.topic != subscription.topic {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic.clone(),
            actual: data.topic,
        });
    }

    let envelope = Envelope::decode(&data.message, EnvelopeEncoding::Base64)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let plaintext = envelope
        .decrypt(&subscription.sym_key)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let json = serde_json::from_str::<serde_json::Value>(&plaintext)
        .map_err(|source| PairingClientError::SessionPayload { source })?;
    let payload = parse_session_settle_response_payload(json, expected_id)?;

    Ok(SessionSettleResponseMessage {
        topic: subscription.topic.clone(),
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        payload,
    })
}

/// Parses and correlates the JSON-RPC response to `wc_sessionSettle`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2288-L2299>
///
/// > const { id } = payload;
/// > if (isJsonRpcResult(payload)) {
/// > } else if (isJsonRpcError(payload)) {
fn parse_session_settle_response_payload(
    json: serde_json::Value,
    expected_id: u64,
) -> Result<SessionSettleResponsePayload, PairingClientError> {
    let actual_id = json
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PairingClientError::SessionResponseMissingId)?;

    if actual_id != expected_id {
        return Err(PairingClientError::SessionResponseIdMismatch {
            expected: expected_id,
            actual: actual_id,
        });
    }

    if json.get("result").is_some() {
        return serde_json::from_value::<SessionSettleResponse>(json)
            .map(SessionSettleResponsePayload::Success)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    if json.get("error").is_some() {
        return serde_json::from_value::<JsonRpcErrorResponse>(json)
            .map(SessionSettleResponsePayload::Error)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    Err(PairingClientError::SessionSettleUnsupportedPayload)
}

/// Parses the classified decrypted JSON into the DTO used by that method.
fn parse_pairing_payload(message: &PairingMessage) -> Result<PairingPayload, PairingClientError> {
    match message.method() {
        PairingMessageMethod::Sign(SignMethod::SessionPropose) => parse_json_rpc(message)
            .map(|request| PairingPayload::SessionProposal(Box::new(request))),
        PairingMessageMethod::Sign(method) => Ok(PairingPayload::Sign(*method)),
        PairingMessageMethod::Pairing(PairingMethod::Ping) => {
            parse_json_rpc(message).map(PairingPayload::PairingPing)
        }
        PairingMessageMethod::Pairing(PairingMethod::Delete) => {
            parse_json_rpc(message).map(PairingPayload::PairingDelete)
        }
        PairingMessageMethod::Unknown(method) => Ok(PairingPayload::Unknown(method.clone())),
        PairingMessageMethod::Missing => Ok(PairingPayload::Missing),
    }
}

/// Clones the already parsed JSON into a method-specific DTO.
fn parse_json_rpc<T>(message: &PairingMessage) -> Result<T, PairingClientError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(message.json().clone())
        .map_err(|source| PairingClientError::PairingPayload { source })
}

struct SessionProposalApprovalPublishes {
    session_topic: RelayTopic,
    session_sym_key: PairingSymKey,
    session: Session,
    proposal_response: IrnPublish,
    session_settle: IrnPublish,
}

/// Builds the encrypted relay publish payloads for proposal approval.
///
/// The maintained Sign Client formats one JSON-RPC result on the pairing topic
/// and one `wc_sessionSettle` request on the derived session topic.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1746-L1786>
///
/// > const pairingPayload = formatJsonRpcResult(proposal.id, pairingProposalResponse);
/// > const sessionSettlePayload = formatJsonRpcRequest(
/// > "wc_sessionSettle",
fn session_proposal_approval_publishes(
    subscription: &PairingSubscription,
    proposal: &JsonRpcRequest<SessionProposeParams>,
    approval: SessionProposalApproval,
    responder: &X25519KeyPair,
    settle_request_id: u64,
) -> Result<SessionProposalApprovalPublishes, PairingClientError> {
    validate_session_proposal_approval(subscription, proposal, &approval)?;

    let session_sym_key = derive_shared_sym_key(
        responder.private_key(),
        &proposal.params.proposer.public_key,
    );
    let session_topic = derive_topic_from_sym_key(&session_sym_key);
    let controller = SessionParticipant {
        public_key: responder.public_key().clone(),
        metadata: approval.wallet_metadata.clone(),
    };
    let session = Session {
        topic: session_topic.clone(),
        pairing_topic: subscription.topic.clone(),
        relay: approval.relay.clone(),
        expiry: approval.expiry,
        acknowledged: false,
        controller: responder.public_key().clone(),
        namespaces: approval.namespaces.clone(),
        required_namespaces: proposal.params.required_namespaces.clone(),
        optional_namespaces: proposal.params.optional_namespaces.clone(),
        session_properties: approval.session_properties.clone(),
        scoped_properties: approval.scoped_properties.clone(),
        session_config: approval.session_config.clone(),
        self_participant: controller.clone(),
        peer: SessionParticipant {
            public_key: proposal.params.proposer.public_key.clone(),
            metadata: proposal.params.proposer.metadata.clone(),
        },
        authentication: None,
        wallet_pay_result: None,
        transport_type: Some(SessionTransportType::Relay),
    };

    let proposal_response = JsonRpcResponse::new(
        proposal.id,
        SessionProposeResult {
            relay: approval.relay.clone(),
            responder_public_key: responder.public_key().clone(),
        },
    );
    let proposal_response = encrypted_json_publish(
        subscription.topic.clone(),
        &subscription.sym_key,
        &proposal_response,
        SESSION_PROPOSE_RESPONSE_TTL_SECONDS,
        SESSION_PROPOSE_RESPONSE_TAG,
    )?;

    let session_settle = JsonRpcRequest::new(
        settle_request_id,
        SignMethod::SessionSettle,
        SessionSettleParams {
            relay: approval.relay,
            namespaces: approval.namespaces,
            controller,
            expiry: approval.expiry,
            session_properties: approval.session_properties,
            scoped_properties: approval.scoped_properties,
            session_config: approval.session_config,
            special_namespaces: None,
            proposal_requests_responses: approval.proposal_requests_responses,
        },
    );
    let session_settle = encrypted_json_publish(
        session_topic.clone(),
        &session_sym_key,
        &session_settle,
        SESSION_SETTLE_REQUEST_TTL_SECONDS,
        SESSION_SETTLE_REQUEST_TAG,
    )?;

    Ok(SessionProposalApprovalPublishes {
        session_topic,
        session_sym_key,
        session,
        proposal_response,
        session_settle,
    })
}

/// Checks proposal-level invariants before encrypting approval messages.
fn validate_session_proposal_approval(
    subscription: &PairingSubscription,
    proposal: &JsonRpcRequest<SessionProposeParams>,
    approval: &SessionProposalApproval,
) -> Result<(), PairingClientError> {
    if let Some(pairing_topic) = &proposal.params.pairing_topic
        && pairing_topic != &subscription.topic
    {
        return Err(PairingClientError::ProposalPairingTopicMismatch {
            expected: subscription.topic.clone(),
            actual: pairing_topic.clone(),
        });
    }

    validate_approved_namespaces(&proposal.params.required_namespaces, &approval.namespaces)
        .map_err(|source| PairingClientError::Namespace { source })
}

/// Serializes a Sign JSON-RPC payload and encrypts it as a relay publish message.
fn encrypted_json_publish<T>(
    topic: RelayTopic,
    sym_key: &PairingSymKey,
    payload: &T,
    ttl: u64,
    tag: u64,
) -> Result<IrnPublish, PairingClientError>
where
    T: serde::Serialize,
{
    let plaintext = serde_json::to_string(payload)
        .map_err(|source| PairingClientError::PairingPayload { source })?;
    let envelope = Envelope::encrypt_type_0(&plaintext, sym_key)
        .map_err(|source| PairingClientError::Envelope { source })?;
    let message = envelope.encode(EnvelopeEncoding::Base64);

    Ok(IrnPublish::new(topic, message, ttl, tag))
}

/// Builds the encrypted relay publish payload for proposal rejection.
///
/// This helper keeps outbound encoding deterministic enough for unit tests:
/// tests can decrypt the produced relay message without opening a WebSocket.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1852-L1884>
///
/// > const payload = formatJsonRpcError(id, error);
/// > message = await this.client.core.crypto.encode(topic, payload, {
/// > this.client.core.relayer.publish(topic, message, opts);
fn session_proposal_reject_publish(
    subscription: &PairingSubscription,
    proposal_id: u64,
    error: JsonRpcError,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_propose_error_response(proposal_id, error);
    encrypted_json_publish(
        subscription.topic.clone(),
        &subscription.sym_key,
        &response,
        SESSION_PROPOSE_REJECT_TTL_SECONDS,
        SESSION_PROPOSE_REJECT_TAG,
    )
}

/// Sign JSON-RPC ID generation failure.
#[derive(Debug, thiserror::Error)]
pub enum SignRpcIdError {
    /// System clock is before the unix epoch.
    #[error("system clock is before the unix epoch")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Timestamp-based ID construction exceeded `u64`.
    #[error("sign rpc id overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wc_protocol::{
        envelope::{Envelope, EnvelopeEncoding},
        key::{X25519KeyPair, X25519PrivateKey},
        pairing::PairingSymKey,
        relay::IrnSubscriptionData,
        session::{
            DappMetadata, JsonRpcErrorCode, SessionNamespace, SessionProposeErrorResponse,
            SessionProposeResult, SessionSettleParams, session_ack_response,
        },
    };

    const PAIRING_URI: &str = concat!(
        "wc:1111111111111111111111111111111111111111111111111111111111111111@2",
        "?relay-protocol=irn",
        "&symKey=2222222222222222222222222222222222222222222222222222222222222222",
        "&expiryTimestamp=4102444800"
    );

    #[test]
    fn config_builds_authenticated_relay_url() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = PairingClientConfig::new("project", [7; 32], "subject");
        config.relay_url = "wss://relay.walletconnect.com?existing=1".to_owned();
        config.user_agent = "wc-2/rust-poc/test".to_owned();

        let url = relay_connection_url(&config, 1_700_000_000)?;
        let value = url.as_str();

        assert!(value.starts_with("wss://relay.walletconnect.com/?existing=1&auth="));
        assert!(value.contains("&projectId=project"));
        assert!(value.contains("&ua=wc-2%2Frust-poc%2Ftest"));

        Ok(())
    }

    #[test]
    fn validates_pairing_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let pairing = PairingUri::parse(PAIRING_URI)?;

        validate_pairing_not_expired(&pairing, 4_000_000_000)?;
        let error = validate_pairing_not_expired(&pairing, 4_102_444_800)
            .expect_err("expired URI should fail");

        assert!(matches!(error, PairingClientError::PairingExpired { .. }));

        Ok(())
    }

    #[test]
    fn decodes_subscription_data_with_pairing_key() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_pairingPing","params":{}}"#;
        let envelope = Envelope::encrypt_type_0(plaintext, &sym_key)?;
        let data = IrnSubscriptionData {
            topic: RelayTopic::from_hex("11".repeat(32))?,
            message: envelope.encode(EnvelopeEncoding::Base64),
            published_at: 1_700_000_000_000,
            tag: Some(1100),
        };

        let received = decode_subscription_data(data, &sym_key)?;

        assert!(received.encoded_message_len() > plaintext.len());
        assert_eq!(received.published_at(), 1_700_000_000_000);
        assert_eq!(received.tag(), Some(1100));
        assert_eq!(received.message().plaintext(), plaintext);
        assert!(matches!(received.payload(), PairingPayload::PairingPing(_)));

        Ok(())
    }

    #[test]
    fn parses_session_proposal_payload() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let plaintext = concat!(
            r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{"#,
            r#""id":1,"pairingTopic":"1111111111111111111111111111111111111111111111111111111111111111","#,
            r#""expiryTimestamp":4102444800,"relays":[{"protocol":"irn"}],"#,
            r#""proposer":{"publicKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""metadata":{"name":"Probe Dapp","description":"Probe","url":"https://example.com","icons":[]}},"#,
            r#""requiredNamespaces":{},"optionalNamespaces":{}}}"#
        );
        let data = encrypted_subscription_data(plaintext, &sym_key)?;

        let received = decode_subscription_data(data, &sym_key)?;

        let PairingPayload::SessionProposal(request) = received.payload() else {
            panic!("expected typed session proposal");
        };
        assert_eq!(request.id, 1);
        assert_eq!(request.params.proposer.metadata.name, "Probe Dapp");

        Ok(())
    }

    #[test]
    fn rejects_malformed_known_payload() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{}}"#;
        let data = encrypted_subscription_data(plaintext, &sym_key)?;

        let error = decode_subscription_data(data, &sym_key)
            .expect_err("known method with malformed params should fail");

        assert!(matches!(error, PairingClientError::PairingPayload { .. }));

        Ok(())
    }

    #[test]
    fn builds_session_proposal_reject_publish() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let subscription = PairingSubscription {
            topic: RelayTopic::from_hex("11".repeat(32))?,
            sym_key: sym_key.clone(),
            subscription_id: "sub-1".to_owned(),
        };

        let publish = session_proposal_reject_publish(
            &subscription,
            7,
            JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
        )?;

        assert_eq!(publish.topic, *subscription.topic());
        assert_eq!(publish.ttl, SESSION_PROPOSE_REJECT_TTL_SECONDS);
        assert_eq!(publish.tag, SESSION_PROPOSE_REJECT_TAG);
        assert_eq!(publish.prompt, None);

        let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
        let plaintext = envelope.decrypt(&sym_key)?;
        let response = serde_json::from_str::<SessionProposeErrorResponse>(&plaintext)?;

        assert_eq!(response.id, 7);
        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
        assert_eq!(response.error.message, "User rejected.");

        Ok(())
    }

    #[test]
    fn builds_session_proposal_approval_publishes() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let subscription = PairingSubscription {
            topic: RelayTopic::from_hex("11".repeat(32))?,
            sym_key: sym_key.clone(),
            subscription_id: "sub-1".to_owned(),
        };
        let proposal = session_proposal_request()?;
        let responder = X25519KeyPair::from_private_key(X25519PrivateKey::from_hex(
            "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
        )?);
        let approval = SessionProposalApproval::new(
            std::collections::BTreeMap::from([(
                "eip155".parse()?,
                SessionNamespace {
                    chains: Some(vec!["eip155:1".parse()?]),
                    accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?],
                    methods: vec!["personal_sign".parse()?],
                    events: vec!["accountsChanged".parse()?],
                },
            )]),
            wallet_metadata(),
            4_102_444_800,
        );

        let publishes =
            session_proposal_approval_publishes(&subscription, &proposal, approval, &responder, 9)?;

        assert_eq!(publishes.proposal_response.topic, *subscription.topic());
        assert_eq!(
            publishes.proposal_response.ttl,
            SESSION_PROPOSE_RESPONSE_TTL_SECONDS
        );
        assert_eq!(
            publishes.proposal_response.tag,
            SESSION_PROPOSE_RESPONSE_TAG
        );
        assert_eq!(publishes.session_settle.topic, publishes.session_topic);
        assert_eq!(
            publishes.session_settle.ttl,
            SESSION_SETTLE_REQUEST_TTL_SECONDS
        );
        assert_eq!(publishes.session_settle.tag, SESSION_SETTLE_REQUEST_TAG);

        let proposal_response = decrypt_publish::<JsonRpcResponse<SessionProposeResult>>(
            &publishes.proposal_response,
            &sym_key,
        )?;
        assert_eq!(proposal_response.id, proposal.id);
        assert_eq!(
            proposal_response.result.responder_public_key,
            *responder.public_key()
        );

        let settle_request = decrypt_publish::<JsonRpcRequest<SessionSettleParams>>(
            &publishes.session_settle,
            &publishes.session_sym_key,
        )?;
        assert_eq!(settle_request.id, 9);
        assert_eq!(settle_request.method, SignMethod::SessionSettle);
        assert_eq!(
            settle_request.params.controller.public_key,
            *responder.public_key()
        );
        assert_eq!(
            settle_request.params.controller.metadata.name,
            "Rust Wallet"
        );
        assert_eq!(settle_request.params.namespaces["eip155"].accounts.len(), 1);
        assert_eq!(publishes.session.topic, publishes.session_topic);
        assert_eq!(publishes.session.pairing_topic, *subscription.topic());
        assert!(!publishes.session.acknowledged);
        assert_eq!(publishes.session.controller, *responder.public_key());
        assert_eq!(
            publishes.session.self_participant.metadata.name,
            "Rust Wallet"
        );
        assert_eq!(publishes.session.peer.metadata.name, "Probe Dapp");
        assert_eq!(
            publishes.session.transport_type,
            Some(SessionTransportType::Relay)
        );

        Ok(())
    }

    #[test]
    fn acknowledged_session_marks_pending_session_active() -> Result<(), Box<dyn std::error::Error>>
    {
        let sym_key = PairingSymKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        let session_subscription = session_subscription(sym_key)?;
        let mut pending_session = session_from_subscription(&session_subscription)?;
        pending_session.acknowledged = false;
        let approved = ApprovedSession {
            subscription: session_subscription,
            responder_public_key: X25519PrivateKey::from_hex(
                "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
            )?
            .public_key(),
            session_settle_request_id: 9,
            session: pending_session,
            proposal_response_ack: true,
            session_settle_ack: true,
        };
        let response = SessionSettleResponseMessage {
            topic: approved.session_topic().clone(),
            encoded_message_len: 112,
            published_at: 1_779_955_000_000,
            tag: Some(SESSION_SETTLE_RESPONSE_TAG),
            payload: SessionSettleResponsePayload::Success(session_ack_response(9)),
        };

        let acknowledged = approved.acknowledged_session(&response)?;

        assert!(!approved.pending_session().acknowledged);
        assert!(acknowledged.acknowledged);
        assert_eq!(acknowledged.topic, *approved.session_topic());
        assert_eq!(acknowledged.peer.metadata.name, "Probe Dapp");

        Ok(())
    }

    #[test]
    fn acknowledged_session_rejects_settle_error_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let sym_key = PairingSymKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        let session_subscription = session_subscription(sym_key)?;
        let approved = ApprovedSession {
            responder_public_key: X25519PrivateKey::from_hex(
                "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
            )?
            .public_key(),
            session_settle_request_id: 9,
            session: session_from_subscription(&session_subscription)?,
            subscription: session_subscription,
            proposal_response_ack: true,
            session_settle_ack: true,
        };
        let response = SessionSettleResponseMessage {
            topic: approved.session_topic().clone(),
            encoded_message_len: 112,
            published_at: 1_779_955_000_000,
            tag: Some(SESSION_SETTLE_RESPONSE_TAG),
            payload: SessionSettleResponsePayload::Error(JsonRpcErrorResponse::new(
                9,
                JsonRpcError::new(
                    JsonRpcErrorCode::SessionSettlementFailed,
                    "settlement failed",
                ),
            )),
        };

        assert!(matches!(
            approved
                .acknowledged_session(&response)
                .expect_err("settle error is rejected"),
            PairingClientError::SessionSettleRejected { .. }
        ));

        Ok(())
    }

    #[test]
    fn decodes_session_settle_success_response() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        let subscription = session_subscription(sym_key.clone())?;
        let response = session_ack_response(9);
        let data = encrypted_subscription_data_for_topic(
            &response,
            &sym_key,
            subscription.topic().clone(),
            Some(SESSION_SETTLE_RESPONSE_TAG),
        )?;

        let received = decode_session_settle_response_data(data, &subscription, 9)?;

        assert_eq!(received.topic(), subscription.topic());
        assert_eq!(received.tag(), Some(SESSION_SETTLE_RESPONSE_TAG));
        assert!(matches!(
            received.payload(),
            SessionSettleResponsePayload::Success(response) if response.id == 9
        ));

        Ok(())
    }

    #[test]
    fn decodes_session_settle_error_response() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        let subscription = session_subscription(sym_key.clone())?;
        let response = JsonRpcErrorResponse::new(
            9,
            JsonRpcError::new(
                JsonRpcErrorCode::SessionSettlementFailed,
                "settlement failed",
            ),
        );
        let data = encrypted_subscription_data_for_topic(
            &response,
            &sym_key,
            subscription.topic().clone(),
            Some(SESSION_SETTLE_RESPONSE_TAG),
        )?;

        let received = decode_session_settle_response_data(data, &subscription, 9)?;

        match received.payload() {
            SessionSettleResponsePayload::Error(response) => {
                assert_eq!(response.id, 9);
                assert_eq!(
                    response.error.code,
                    JsonRpcErrorCode::SessionSettlementFailed
                );
            }
            SessionSettleResponsePayload::Success(response) => {
                panic!("unexpected success payload: {response:?}");
            }
        }

        Ok(())
    }

    #[test]
    fn rejects_session_settle_response_with_wrong_id() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "3333333333333333333333333333333333333333333333333333333333333333",
        )?;
        let subscription = session_subscription(sym_key.clone())?;
        let response = session_ack_response(10);
        let data = encrypted_subscription_data_for_topic(
            &response,
            &sym_key,
            subscription.topic().clone(),
            Some(SESSION_SETTLE_RESPONSE_TAG),
        )?;

        assert!(matches!(
            decode_session_settle_response_data(data, &subscription, 9)
                .expect_err("wrong response id is rejected"),
            PairingClientError::SessionResponseIdMismatch {
                expected: 9,
                actual: 10
            }
        ));

        Ok(())
    }

    fn encrypted_subscription_data(
        plaintext: &str,
        sym_key: &PairingSymKey,
    ) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>> {
        let envelope = Envelope::encrypt_type_0(plaintext, sym_key)?;
        Ok(IrnSubscriptionData {
            topic: RelayTopic::from_hex("11".repeat(32))?,
            message: envelope.encode(EnvelopeEncoding::Base64),
            published_at: 1_700_000_000_000,
            tag: Some(1100),
        })
    }

    fn encrypted_subscription_data_for_topic<T>(
        payload: &T,
        sym_key: &PairingSymKey,
        topic: RelayTopic,
        tag: Option<u64>,
    ) -> Result<IrnSubscriptionData, Box<dyn std::error::Error>>
    where
        T: serde::Serialize,
    {
        let plaintext = serde_json::to_string(payload)?;
        let envelope = Envelope::encrypt_type_0(&plaintext, sym_key)?;

        Ok(IrnSubscriptionData {
            topic,
            message: envelope.encode(EnvelopeEncoding::Base64),
            published_at: 1_779_954_250_000,
            tag,
        })
    }

    fn session_subscription(
        sym_key: PairingSymKey,
    ) -> Result<SessionSubscription, Box<dyn std::error::Error>> {
        Ok(SessionSubscription {
            topic: RelayTopic::from_hex("44".repeat(32))?,
            sym_key,
            subscription_id: "session-sub-1".to_owned(),
        })
    }

    fn session_from_subscription(
        subscription: &SessionSubscription,
    ) -> Result<Session, Box<dyn std::error::Error>> {
        let controller = X25519PrivateKey::from_hex(
            "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
        )?
        .public_key();
        let peer = X25519PrivateKey::from_hex(
            "4afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
        )?
        .public_key();

        Ok(Session {
            topic: subscription.topic().clone(),
            pairing_topic: RelayTopic::from_hex("11".repeat(32))?,
            relay: RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: None,
            },
            expiry: 4_102_444_800,
            acknowledged: false,
            controller: controller.clone(),
            namespaces: std::collections::BTreeMap::from([(
                "eip155".parse()?,
                SessionNamespace {
                    chains: Some(vec!["eip155:1".parse()?]),
                    accounts: vec!["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?],
                    methods: vec!["personal_sign".parse()?],
                    events: vec!["accountsChanged".parse()?],
                },
            )]),
            required_namespaces: std::collections::BTreeMap::new(),
            optional_namespaces: std::collections::BTreeMap::new(),
            session_properties: None,
            scoped_properties: None,
            session_config: None,
            self_participant: SessionParticipant {
                public_key: controller,
                metadata: wallet_metadata(),
            },
            peer: SessionParticipant {
                public_key: peer,
                metadata: DappMetadata {
                    name: "Probe Dapp".to_owned(),
                    description: "Probe".to_owned(),
                    url: "https://example.com".to_owned(),
                    icons: vec![],
                    verify_url: None,
                    redirect: None,
                },
            },
            authentication: None,
            wallet_pay_result: None,
            transport_type: Some(SessionTransportType::Relay),
        })
    }

    fn session_proposal_request()
    -> Result<JsonRpcRequest<SessionProposeParams>, Box<dyn std::error::Error>> {
        let json = concat!(
            r#"{"id":7,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{"#,
            r#""id":7,"pairingTopic":"1111111111111111111111111111111111111111111111111111111111111111","#,
            r#""expiryTimestamp":4102444800,"relays":[{"protocol":"irn"}],"#,
            r#""proposer":{"publicKey":"80dd64bd6e4c3612ff0f5ccbe9282f1f11ba56ada6a2f9740da063d1ed1f2b20","#,
            r#""metadata":{"name":"Probe Dapp","description":"Probe","url":"https://example.com","icons":[]}},"#,
            r#""requiredNamespaces":{"eip155":{"chains":["eip155:1"],"methods":["personal_sign"],"events":["accountsChanged"]}},"#,
            r#""optionalNamespaces":{}}}"#
        );

        serde_json::from_str(json).map_err(Into::into)
    }

    fn wallet_metadata() -> DappMetadata {
        DappMetadata {
            name: "Rust Wallet".to_owned(),
            description: "Rust Wallet".to_owned(),
            url: "https://example.com/wallet".to_owned(),
            icons: vec![],
            verify_url: None,
            redirect: None,
        }
    }

    fn decrypt_publish<T>(
        publish: &IrnPublish,
        sym_key: &PairingSymKey,
    ) -> Result<T, Box<dyn std::error::Error>>
    where
        T: serde::de::DeserializeOwned,
    {
        let envelope = Envelope::decode(&publish.message, EnvelopeEncoding::Base64)?;
        let plaintext = envelope.decrypt(sym_key)?;
        serde_json::from_str(&plaintext).map_err(Into::into)
    }
}
