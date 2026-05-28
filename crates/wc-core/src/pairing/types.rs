use wc_protocol::{
    dto::pairing::{PairingDeleteParams, PairingJsonRpcRequest, PairingPingParams},
    pairing::PairingSymKey,
    pairing_message::PairingMessage,
    relay::RelayTopic,
    session::{
        DappMetadata, JsonRpcErrorResponse, JsonRpcRequest, RelayProtocolOptions, ScopedProperties,
        Session, SessionConfig, SessionDeleteParams, SessionNamespaces, SessionPingParams,
        SessionProperties, SessionProposeParams, SessionRequestParams, SessionSettleResponse,
        SignMethod,
    },
};

use super::error::PairingClientError;

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
    pub(super) topic: RelayTopic,
    pub(super) sym_key: PairingSymKey,
    pub(super) subscription_id: String,
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
    pub(super) subscription: SessionSubscription,
    pub(super) responder_public_key: wc_protocol::key::X25519PublicKey,
    pub(super) session_settle_request_id: u64,
    pub(super) session: Session,
    pub(super) proposal_response_ack: bool,
    pub(super) session_settle_ack: bool,
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
    pub(super) topic: RelayTopic,
    pub(super) encoded_message_len: usize,
    pub(super) published_at: u64,
    pub(super) tag: Option<u64>,
    pub(super) payload: SessionSettleResponsePayload,
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

/// Decrypted session-topic message plus relay delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReceivedMessage {
    pub(super) topic: RelayTopic,
    pub(super) encoded_message_len: usize,
    pub(super) plaintext_len: usize,
    pub(super) published_at: u64,
    pub(super) tag: Option<u64>,
    pub(super) payload: SessionPayload,
}

/// Result of reading a session-topic message with invalid-request auto-rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMessageOutcome {
    /// Message passed local session validation and is ready for wallet handling.
    Received(SessionReceivedMessage),
    /// Request was invalid for the active session and was answered with an error.
    Rejected(SessionRequestRejection),
}

/// Protocol error response sent for an invalid `wc_sessionRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestRejection {
    pub(super) topic: RelayTopic,
    pub(super) request_id: u64,
    pub(super) error: wc_protocol::session::JsonRpcError,
    pub(super) response_ack: bool,
}

impl SessionRequestRejection {
    /// Session topic that received the invalid request.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request ID copied into the error response.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// JSON-RPC error sent to the peer.
    #[must_use]
    pub const fn error(&self) -> &wc_protocol::session::JsonRpcError {
        &self.error
    }

    /// Relay acknowledgement for the error response publish.
    #[must_use]
    pub const fn response_ack(&self) -> bool {
        self.response_ack
    }
}

impl SessionReceivedMessage {
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

    /// Length of the decrypted JSON string.
    #[must_use]
    pub const fn plaintext_len(&self) -> usize {
        self.plaintext_len
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

    /// Parsed session-topic JSON-RPC payload.
    #[must_use]
    pub const fn payload(&self) -> &SessionPayload {
        &self.payload
    }
}

/// Typed session-topic payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPayload {
    /// `wc_sessionRequest` Sign API request.
    SessionRequest(Box<JsonRpcRequest<SessionRequestParams>>),
    /// `wc_sessionPing` Sign API request.
    SessionPing(JsonRpcRequest<SessionPingParams>),
    /// `wc_sessionDelete` Sign API request.
    SessionDelete(JsonRpcRequest<SessionDeleteParams>),
    /// Known Sign API method whose DTO is not parsed at this layer yet.
    Sign(SignMethod),
    /// JSON-RPC method name is present but not implemented by current DTOs.
    Unknown(String),
    /// JSON has no string `method` field.
    Missing,
}

/// Active relay subscription for one pairing topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSubscription {
    pub(super) topic: RelayTopic,
    pub(super) sym_key: PairingSymKey,
    pub(super) subscription_id: String,
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
    pub(super) topic: RelayTopic,
    pub(super) encoded_message_len: usize,
    pub(super) published_at: u64,
    pub(super) tag: Option<u64>,
    pub(super) message: PairingMessage,
    pub(super) payload: PairingPayload,
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
