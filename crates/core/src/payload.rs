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

/// Body of a `session_delete` message.
#[derive(Serialize, Deserialize)]
pub struct SessionDeletePayload {
    /// Machine-readable close code.
    pub code: u32,

    /// Human-readable detail.
    pub message: String,
}

/// Typed wrapper over the possible message bodies.
///
/// Tagged by the `type` field, because several bodies (`reject`,
/// `disconnect`, `session_delete`) carry the same fields and an untagged
/// representation decodes one of them as another.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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
    SessionDelete(SessionDeletePayload),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::MessageType;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn bodies_with_the_same_shape_are_distinguished() -> TestResult {
        let rejected: Payload =
            serde_json::from_str(r#"{"type":"reject","code":1,"message":"no"}"#)?;
        assert!(matches!(rejected, Payload::Reject(_)));

        let disconnected: Payload = serde_json::from_str(
            r#"{"type":"disconnect","reason":"bye","code":1,"message":"no"}"#,
        )?;
        assert!(matches!(disconnected, Payload::Disconnect(_)));

        let deleted: Payload =
            serde_json::from_str(r#"{"type":"session_delete","code":1,"message":"gone"}"#)?;
        assert!(matches!(deleted, Payload::SessionDelete(_)));
        Ok(())
    }

    #[test]
    fn empty_bodies_round_trip() -> TestResult {
        for payload in [Payload::Ping, Payload::Pong, Payload::SessionReady] {
            let json = serde_json::to_string(&payload)?;
            let expected = format!("\"type\":\"{}\"", MessageType::from(&payload).as_str());
            assert!(json.contains(&expected), "{json}");

            let decoded: Payload = serde_json::from_str(&json)?;
            assert_eq!(MessageType::from(&decoded), MessageType::from(&payload));
        }
        Ok(())
    }

    #[test]
    fn session_delete_carries_code_and_message() -> TestResult {
        let payload = Payload::SessionDelete(SessionDeletePayload {
            code: 7,
            message: "deleted".to_owned(),
        });

        let json = serde_json::to_string(&payload)?;
        assert!(json.contains("\"type\":\"session_delete\""), "{json}");
        assert!(json.contains("\"code\":7"), "{json}");
        assert!(json.contains("\"message\":\"deleted\""), "{json}");
        Ok(())
    }

    #[test]
    fn unknown_type_is_rejected() {
        let result: Result<Payload, _> = serde_json::from_str(r#"{"type":"sneaky"}"#);
        assert!(result.is_err());
    }
}
