use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

/// Caller-assigned id correlating a request with its response.
pub type RequestId = String;

/// Plaintext application message exchanged over the relay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Propose a session.
    Proposal { proposal: Value },

    /// Approve a session.
    Approve { approval: Value },

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
    /// Serialize to the relay frame payload.
    pub fn to_payload(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse a relay frame payload.
    pub fn from_payload(payload: &str) -> Result<Self> {
        Ok(serde_json::from_str(payload)?)
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
        let payload = message.to_payload().expect("payload");
        assert!(payload.contains("\"type\":\"request\""));
        assert_eq!(
            ClientMessage::from_payload(&payload).expect("parsed"),
            message
        );
    }

    #[test]
    fn response_error_variant_round_trips() {
        let message = ClientMessage::Response {
            request_id: "req-1".to_owned(),
            response: None,
            error: Some(json!({ "code": 4001 })),
        };
        let payload = message.to_payload().expect("payload");
        assert_eq!(
            ClientMessage::from_payload(&payload).expect("parsed"),
            message
        );
    }
}
