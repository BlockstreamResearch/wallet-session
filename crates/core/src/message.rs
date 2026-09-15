use crate::payload::Payload;
use serde::{Deserialize, Serialize};

/// Encrypted message.
#[derive(Serialize, Deserialize)]
struct Message {
    /// Protocol version.
    #[serde(rename = "v")]
    version: u8,

    /// 16 random bytes, base64url.
    id: String,

    /// Message type.
    #[serde(rename = "type")]
    type_: MessageType,

    /// Subscription topic.
    topic: Topic,

    /// Unix timestamp (seconds).
    ts: u64,

    /// AEAD nonce.
    nonce: Nonce,

    /// Ciphertext (with tag), base64url.
    data: Ciphertext,
}

/// Plaintext frame for the relay.
#[derive(Serialize, Deserialize)]
struct ControlFrame {
    /// Protocol version.
    #[serde(rename = "v")]
    version: u8,

    /// 16 random bytes, base64url.
    id: String,

    /// Message type.
    #[serde(rename = "type")]
    type_: MessageType,

    /// Subscription topic.
    topic: Topic,

    /// The encrypted message.
    payload: Message,
}

/// Message type name.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MessageType {
    Proposal,
    Approve,
    Reject,
    Request,
    Response,
    Ack,
    Ping,
    Pong,
    Disconnect,
    SessionDelete,
    SessionReady,
}

impl From<&Payload> for MessageType {
    fn from(payload: &Payload) -> Self {
        match payload {
            Payload::Proposal(_) => MessageType::Proposal,
            Payload::Approve(_) => MessageType::Approve,
            Payload::Reject(_) => MessageType::Reject,
            Payload::Request(_) => MessageType::Request,
            Payload::Response(_) => MessageType::Response,
            Payload::Ack(_) => MessageType::Ack,
            Payload::Ping => MessageType::Ping,
            Payload::Pong => MessageType::Pong,
            Payload::SessionReady => MessageType::SessionReady,
            Payload::Disconnect(_) => MessageType::Disconnect,
            Payload::SessionDelete => MessageType::SessionDelete,
        }
    }
}

impl From<Payload> for MessageType {
    fn from(payload: Payload) -> Self {
        MessageType::from(&payload)
    }
}

/// 32-byte topic, base64url.
#[derive(Serialize, Deserialize)]
struct Topic(String);

/// AEAD nonce.
#[derive(Serialize, Deserialize)]
struct Nonce(String);

/// Ciphertext (with tag), base64url.
#[derive(Serialize, Deserialize)]
struct Ciphertext(String);
