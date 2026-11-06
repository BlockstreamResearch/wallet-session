use serde::{Deserialize, Serialize};
use wallet_session_core::{
    message::MessageType,
    payload::{
        AckPayload, ApprovePayload, DisconnectPayload, ProposalPayload, RejectPayload,
        RequestPayload, ResponsePayload, SessionDeletePayload,
    },
};

use crate::error::Result;

/// Caller-assigned id correlating a request with its response.
pub type RequestId = String;

/// Plaintext application message exchanged over the relay.
///
/// The variant bodies are the payload types from `wallet_session_core`, so the
/// wire representation is the one defined by the protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Propose a session.
    Proposal(ProposalPayload),

    /// Approve a session.
    Approve(ApprovePayload),

    /// Reject a proposal.
    Reject(RejectPayload),

    /// Application request.
    Request(RequestPayload),

    /// Application response to a request.
    Response(ResponsePayload),

    /// Acknowledge receipt of a message.
    Ack(AckPayload),

    /// Graceful teardown.
    Disconnect(DisconnectPayload),

    /// Notify the peer that the session was deleted.
    SessionDelete(SessionDeletePayload),
}

impl ClientMessage {
    /// Message type used as the plaintext envelope tag.
    pub fn message_type(&self) -> MessageType {
        match self {
            ClientMessage::Proposal(_) => MessageType::Proposal,
            ClientMessage::Approve(_) => MessageType::Approve,
            ClientMessage::Reject(_) => MessageType::Reject,
            ClientMessage::Request(_) => MessageType::Request,
            ClientMessage::Response(_) => MessageType::Response,
            ClientMessage::Ack(_) => MessageType::Ack,
            ClientMessage::Disconnect(_) => MessageType::Disconnect,
            ClientMessage::SessionDelete(_) => MessageType::SessionDelete,
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
    use wallet_session_core::payload::Opaque;

    #[test]
    fn request_round_trips() {
        let message = ClientMessage::Request(RequestPayload {
            request_id: "req-1".to_owned(),
            request: Opaque(serde_json::to_vec(&json!({ "method": "get" })).expect("json")),
        });
        let bytes = message.to_bytes().expect("bytes");
        assert_eq!(ClientMessage::from_bytes(&bytes).expect("parsed"), message);
        assert_eq!(message.message_type(), MessageType::Request);
    }

    #[test]
    fn response_error_variant_round_trips() {
        let message = ClientMessage::Response(ResponsePayload {
            request_id: "req-1".to_owned(),
            response: None,
            error: Some(Opaque(
                serde_json::to_vec(&json!({ "code": 4001 })).expect("json"),
            )),
        });
        let bytes = message.to_bytes().expect("bytes");
        assert_eq!(ClientMessage::from_bytes(&bytes).expect("parsed"), message);
    }

    #[test]
    fn ack_uses_the_documented_field_name() {
        let message = ClientMessage::Ack(AckPayload {
            ack_id: "frame-1".to_owned(),
        });

        assert_eq!(
            serde_json::to_value(&message).expect("json"),
            json!({ "type": "ack", "ackId": "frame-1" })
        );
        assert_eq!(
            ClientMessage::from_bytes(br#"{"type":"ack","ackId":"frame-1"}"#).expect("parsed"),
            message
        );
    }

    #[test]
    fn request_uses_the_documented_field_names() {
        let message = ClientMessage::Request(RequestPayload {
            request_id: "req-1".to_owned(),
            request: Opaque(vec![1, 2, 3]),
        });
        let value = serde_json::to_value(&message).expect("json");

        assert_eq!(
            value,
            json!({ "type": "request", "requestId": "req-1", "request": "AQID" })
        );
        assert!(value.get("request_id").is_none());
    }

    #[test]
    fn response_uses_the_documented_field_names() {
        let message = ClientMessage::Response(ResponsePayload {
            request_id: "req-1".to_owned(),
            response: Some(Opaque(vec![1, 2, 3])),
            error: None,
        });
        let value = serde_json::to_value(&message).expect("json");

        assert_eq!(value["type"], "response");
        assert_eq!(value["requestId"], "req-1");
        assert_eq!(value["response"], "AQID");
        assert!(value.get("request_id").is_none());
    }
}
