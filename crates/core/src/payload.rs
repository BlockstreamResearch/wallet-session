use serde::{Deserialize, Serialize};

/// Opaque application data carried inside a payload shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opaque(#[serde(with = "crate::codec::base64url")] pub Vec<u8>);

/// Body of a `proposal` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProposalPayload {
    /// The proposer's one-time X25519 public key.
    pub ephemeral_public_key: String,

    /// Unix timestamp.
    pub session_expiry: u64,

    /// Opaque application payload describing what is being requested.
    pub proposal: Opaque,
}

/// Body of an `approve` message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovePayload {
    /// The responder's one-time X25519 public key.
    pub ephemeral_public_key: String,

    /// Opaque application payload describing what the wallet approved.
    pub approval: Opaque,
}

/// Body of a `reject` message.
#[derive(Serialize, Deserialize)]
pub struct RejectPayload {
    /// Reason code for the rejection
    pub code: u32,

    /// Explanation accompanying the code.
    pub message: String,
}

/// Body of a `request` message.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestPayload {
    /// Caller-assigned identifier used to correlate the eventual `response`
    /// back to this request.
    pub request_id: String,

    /// Opaque application payload (e.g. a JSON-RPC call).
    pub request: Opaque,
}

/// Body of a `response` message.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponsePayload {
    /// Identifier of the `request` being answered.
    pub request_id: String,

    /// Opaque application result; present on success, absent on error.
    pub response: Option<Opaque>,

    /// Failure description; present on error, absent on success.
    pub error: Option<Opaque>,
}

/// Body of an `ack` message.
///
/// Confirms receipt of an ack-required message, driving the retransmission
/// logic.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckPayload {
    /// The envelope `id` of the message being acknowledged.
    pub ack_id: String,
}

/// Body of a `disconnect` message.
#[derive(Serialize, Deserialize)]
pub struct DisconnectPayload {
    /// Short reason label for the disconnect.
    pub reason: String,

    /// Machine-readable close code.
    pub code: u32,

    /// Human-readable detail.
    pub message: String,
}

/// Typed wrapper over the possible message bodies.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    /// Session proposal.
    Proposal(ProposalPayload),

    /// Session approval.
    Approve(ApprovePayload),

    /// Proposal rejection.
    Reject(RejectPayload),

    /// Application request.
    Request(RequestPayload),

    /// Application response.
    Response(ResponsePayload),

    /// Acknowledgement.
    Ack(AckPayload),

    /// Ping
    Ping,

    /// Pong
    Pong,

    /// Notifies that both proposer and responder have connected.
    SessionReady,

    /// Graceful teardown.
    Disconnect(DisconnectPayload),

    /// Session deletion notice.
    SessionDelete,
}
