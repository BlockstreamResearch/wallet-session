use std::time::{Duration, SystemTimeError};

use wc_protocol::{
    envelope::EnvelopeError,
    key::X25519KeyPairError,
    namespaces::NamespaceValidationError,
    pairing::{PairingUri, PairingUriError},
    pairing_message::PairingMessageError,
    relay::{RelayAuthError, RelayTopic},
    session::{JsonRpcErrorResponse, SessionMethod},
};
use wc_transport::RelayClientError;

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

    /// Outbound Sign JSON-RPC payload serialization failed.
    #[error("outbound sign payload failed")]
    OutboundPayload {
        /// Source DTO serialization error.
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

    /// A `wc_sessionRequest` response was built from a different session message.
    #[error("session response target is not a session request")]
    SessionResponseTargetNotRequest,

    /// A `wc_sessionPing` response was built from a different session message.
    #[error("session response target is not a session ping")]
    SessionResponseTargetNotPing,

    /// A `wc_sessionDelete` response was built from a different session message.
    #[error("session response target is not a session delete")]
    SessionResponseTargetNotDelete,

    /// Peer rejected the session settlement request.
    #[error("session settle rejected")]
    SessionSettleRejected {
        /// JSON-RPC error response received on the session topic.
        response: JsonRpcErrorResponse,
    },

    /// Active session record and relay subscription use different topics.
    #[error("session topic does not match active subscription")]
    SessionSubscriptionTopicMismatch {
        /// Topic from the active session record.
        session_topic: RelayTopic,
        /// Topic registered on the relay connection.
        subscription_topic: RelayTopic,
    },

    /// Session messages are ignored until the settle request is acknowledged.
    #[error("session is not acknowledged")]
    SessionNotAcknowledged {
        /// Session topic that is still pending acknowledgement.
        topic: RelayTopic,
    },

    /// Session expired before the received message was processed.
    #[error("session expired")]
    SessionExpired {
        /// Session expiry timestamp.
        expiry_timestamp: u64,
        /// Unix timestamp used for the comparison.
        now_unix_seconds: u64,
    },

    /// Session request expired before the wallet processed it.
    #[error("session request expired")]
    SessionRequestExpired {
        /// Request expiry timestamp.
        expiry_timestamp: u64,
        /// Unix timestamp used for the comparison.
        now_unix_seconds: u64,
    },

    /// Session namespaces do not authorize the requested chain.
    #[error("session request chain is not authorized")]
    SessionUnauthorizedChain {
        /// Requested chain ID.
        chain_id: wc_protocol::caip::Caip2ChainId,
    },

    /// Session namespaces do not authorize the requested method on the chain.
    #[error("session request method is not authorized")]
    SessionUnauthorizedMethod {
        /// Requested chain ID.
        chain_id: wc_protocol::caip::Caip2ChainId,
        /// Requested method.
        method: SessionMethod,
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
