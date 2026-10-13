use serde::{Deserialize, Serialize};
use serde_json::Value;
use wallet_session_core::{
    message::MessageType,
    payload::{ApprovePayload, ProposalPayload},
};

use crate::error::Result;

/// Caller-assigned id correlating a request with its response.
pub type RequestId = String;

/// Plaintext application message exchanged over the relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Propose a session.
    Proposal(ProposalPayload),

    /// Approve a session.
    Approve(ApprovePayload),

    /// Reject a proposal.
    Reject { code: u32, message: String },

    /// Application request.
    Request {
        request_id: RequestId,
        request: Value,
    },

    /// Application response to a request.
    Response {
        request_id: RequestId,
        response: Option<Value>,
        error: Option<Value>,
    },

    /// Acknowledge receipt of a message.
    Ack { ack_id: String },

    /// Graceful teardown.
    Disconnect {
        reason: String,
        code: u32,
        message: String,
    },

    /// Notify the peer that the session was deleted.
    SessionDelete { code: u32, message: String },
}

impl ClientMessage {
    /// Message type used as the plaintext envelope tag.
    pub fn message_type(&self) -> MessageType {
        match self {
            ClientMessage::Proposal(_) => MessageType::Proposal,
            ClientMessage::Approve(_) => MessageType::Approve,
            ClientMessage::Reject { .. } => MessageType::Reject,
            ClientMessage::Request { .. } => MessageType::Request,
            ClientMessage::Response { .. } => MessageType::Response,
            ClientMessage::Ack { .. } => MessageType::Ack,
            ClientMessage::Disconnect { .. } => MessageType::Disconnect,
            ClientMessage::SessionDelete { .. } => MessageType::SessionDelete,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trips() {
        let message = ClientMessage::Request {
            request_id: "req-1".to_owned(),
            request: json!({ "method": "get" }),
        };
        let bytes = message.to_bytes().expect("bytes");
        assert_eq!(ClientMessage::from_bytes(&bytes).expect("parsed"), message);
        assert_eq!(message.message_type(), MessageType::Request);
    }

    #[test]
    fn response_error_variant_round_trips() {
        let message = ClientMessage::Response {
            request_id: "req-1".to_owned(),
            response: None,
            error: Some(json!({ "code": 4001 })),
        };
        let bytes = message.to_bytes().expect("bytes");
        assert_eq!(ClientMessage::from_bytes(&bytes).expect("parsed"), message);
    }
}
