use crate::codec::{self};
use crate::did::DidKey;
use crate::error::Error;
use crate::payload::Payload;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Encrypted envelope carried in the `payload` of a `message` relay frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Protocol version.
    pub version: u8,

    /// Message type.
    pub kind: MessageType,

    /// Sender identity.
    pub from: DidKey,

    /// Unix timestamp (seconds).
    pub ts: u64,

    /// AEAD nonce.
    pub nonce: Nonce,

    /// Ciphertext (with tag), base64url.
    pub data: Ciphertext,
}

impl Message {
    pub const VERSION: u8 = 1;

    pub fn new(kind: MessageType, from: DidKey, ts: u64, nonce: Nonce, data: Ciphertext) -> Self {
        Self {
            version: Self::VERSION,
            kind,
            from,
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

    const FROM: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    fn message() -> Message {
        Message::new(
            MessageType::Ping,
            DidKey::parse(FROM).expect("did:key"),
            1_700_000_000,
            Nonce::new([2u8; 24]).unwrap(),
            Ciphertext::new(vec![9, 8, 7]),
        )
    }

    #[test]
    fn decodes_documented_envelope() {
        let json = format!(
            r#"{{
                "version": 1,
                "kind": "request",
                "from": "{FROM}",
                "ts": 1700000000,
                "nonce": "AgICAgICAgICAgICAgICAgICAgICAgIC",
                "data": "CQgH"
            }}"#
        );

        let envelope: Message = serde_json::from_str(&json).expect("documented envelope");
        assert_eq!(envelope.version, Message::VERSION);
        assert_eq!(envelope.kind, MessageType::Request);
        assert_eq!(envelope.from, DidKey::parse(FROM).expect("did:key"));
        assert_eq!(envelope.ts, 1_700_000_000);
        assert_eq!(envelope.nonce, Nonce::new([2u8; 24]).unwrap());
        assert_eq!(envelope.data, Ciphertext::new(vec![9, 8, 7]));
    }

    /// The envelope this crate writes has exactly the documented fields.
    #[test]
    fn serializes_as_documented_envelope() {
        let value = serde_json::to_value(message()).expect("json");

        assert_eq!(
            value,
            serde_json::json!({
                "version": 1,
                "kind": "ping",
                "from": FROM,
                "ts": 1_700_000_000u64,
                "nonce": "AgICAgICAgICAgICAgICAgICAgICAgIC",
                "data": "CQgH",
            })
        );
        // the frame owns these; the envelope must not repeat them.
        for retired in ["v", "type", "id", "topic"] {
            assert!(value.get(retired).is_none(), "{retired} must not appear");
        }
    }

    #[test]
    fn message_round_trips_through_json() {
        let message = message();
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"kind\":\"ping\""));

        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back, message);
    }
}
