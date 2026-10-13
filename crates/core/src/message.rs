use crate::codec::{self};
use crate::error::Error;
use crate::payload::Payload;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Encrypted message.
#[derive(Serialize, Deserialize)]
pub struct Message {
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

impl Message {
    pub const VERSION: u8 = 1;

    pub fn new(
        id: impl Into<String>,
        type_: MessageType,
        topic: Topic,
        ts: u64,
        nonce: Nonce,
        data: Ciphertext,
    ) -> Self {
        Self {
            version: Self::VERSION,
            id: id.into(),
            type_,
            topic,
            ts,
            nonce,
            data,
        }
    }
}

/// Plaintext frame for the relay.
#[derive(Serialize, Deserialize)]
pub struct ControlFrame {
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
}

impl ControlFrame {
    pub const VERSION: u8 = 1;

    pub fn new(id: impl Into<String>, type_: MessageType, topic: Topic) -> Self {
        Self {
            version: Self::VERSION,
            id: id.into(),
            type_,
            topic,
        }
    }
}

/// Message type name.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
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

impl MessageType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::Proposal => "proposal",
            MessageType::Approve => "approve",
            MessageType::Reject => "reject",
            MessageType::Request => "request",
            MessageType::Response => "response",
            MessageType::Ack => "ack",
            MessageType::Ping => "ping",
            MessageType::Pong => "pong",
            MessageType::Disconnect => "disconnect",
            MessageType::SessionDelete => "session_delete",
            MessageType::SessionReady => "session_ready",
        }
    }
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
            Payload::SessionDelete(_) => MessageType::SessionDelete,
        }
    }
}

impl From<Payload> for MessageType {
    fn from(payload: Payload) -> Self {
        MessageType::from(&payload)
    }
}

/// 32-byte topic, base64url.
#[derive(Serialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic(#[serde(with = "crate::codec::base64url")] Vec<u8>);

impl<'de> Deserialize<'de> for Topic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        encoded.parse::<Topic>().map_err(serde::de::Error::custom)
    }
}

impl Topic {
    /// Number of bytes in a topic.
    pub const LEN: usize = 32;

    /// Build a topic from raw bytes, rejecting the wrong length.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.len() != Self::LEN {
            return Err(Error::InvalidLength {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&codec::encode(&self.0))
    }
}

impl FromStr for Topic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(codec::decode(s)?)
    }
}

/// AEAD nonce.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Nonce(#[serde(with = "crate::codec::base64url")] Vec<u8>);

impl Nonce {
    /// Number of bytes in a nonce.
    pub const LEN: usize = 24;

    /// Borrow the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let bytes = bytes.into();
        if bytes.len() != Self::LEN {
            return Err(Error::InvalidLength {
                expected: Self::LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&codec::encode(&self.0))
    }
}

impl FromStr for Nonce {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(codec::decode(s)?)
    }
}

/// Ciphertext (with tag), base64url.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(#[serde(with = "crate::codec::base64url")] Vec<u8>);

impl Ciphertext {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the raw ciphertext bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Ciphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&codec::encode(&self.0))
    }
}

impl FromStr for Ciphertext {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(codec::decode(s)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_accepts_32_bytes() {
        assert!(Topic::new([0u8; 32]).is_ok());
    }

    #[test]
    fn topic_rejects_wrong_length() {
        assert!(matches!(
            Topic::new([0u8; 31]),
            Err(Error::InvalidLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn nonce_accepts_24_bytes() {
        assert!(Nonce::new([0u8; 24]).is_ok());
    }

    #[test]
    fn nonce_rejects_wrong_length() {
        assert!(Nonce::new([0u8; 12]).is_err());
    }

    #[test]
    fn topic_base64url_round_trip() {
        let topic = Topic::new([7u8; 32]).unwrap();
        assert_eq!(topic.to_string().parse::<Topic>().unwrap(), topic);
    }

    #[test]
    fn ciphertext_base64url_round_trip() {
        let data = Ciphertext::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(data.to_string().parse::<Ciphertext>().unwrap(), data);
    }

    #[test]
    fn topic_serializes_as_plain_string() {
        let topic = Topic::new([7u8; 32]).unwrap();
        let json = serde_json::to_string(&topic).unwrap();
        assert_eq!(json, format!("\"{topic}\""));
        assert_eq!(serde_json::from_str::<Topic>(&json).unwrap(), topic);
    }

    #[test]
    fn message_round_trips_through_json() {
        let message = Message {
            version: 1,
            id: codec::encode(&[0u8; 16]),
            type_: MessageType::Ping,
            topic: Topic::new([1u8; 32]).unwrap(),
            ts: 1_700_000_000,
            nonce: Nonce::new([2u8; 24]).unwrap(),
            data: Ciphertext::new(vec![9, 8, 7]),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"v\":1"));
        assert!(json.contains("\"type\":\"ping\""));
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.topic, message.topic);
        assert_eq!(back.nonce, message.nonce);
        assert_eq!(back.data, message.data);
    }
}
