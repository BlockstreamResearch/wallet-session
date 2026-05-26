//! Relay topic validation.
//!
//! Relay topics are represented as 32-byte values encoded as 64 lowercase hex
//! characters. The relay server RPC spec uses topics as the subscription and
//! publish routing key.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::encoding::hex_lower;

/// Relay topic size before hex encoding.
pub const RELAY_TOPIC_BYTES: usize = 32;

/// Relay topic size after lowercase hex encoding.
pub const RELAY_TOPIC_HEX: usize = RELAY_TOPIC_BYTES * 2;

/// Relay routing key used by subscribe, publish, and mailbox fetch RPCs.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#definitions>
///
/// > topic - (hex string - 32 bytes) a target topic for the message to be subscribed by the receiver.
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::RelayTopic;
///
/// let topic = RelayTopic::from_hex("00".repeat(32))?;
/// assert_eq!(topic.as_str().len(), 64);
/// assert_eq!(topic.as_str(), "0000000000000000000000000000000000000000000000000000000000000000");
/// # Ok::<(), wc_protocol::relay::RelayTopicError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayTopic(String);

impl RelayTopic {
    /// Creates a topic from a 64-character hex string.
    ///
    /// Uppercase hex is accepted and normalized to lowercase because the relay
    /// treats topics as byte values encoded in hex form.
    pub fn from_hex(value: impl Into<String>) -> Result<Self, RelayTopicError> {
        let value = value.into();
        if value.len() != RELAY_TOPIC_HEX {
            return Err(RelayTopicError::InvalidLength {
                actual: value.len(),
            });
        }

        if let Some((index, character)) = value
            .char_indices()
            .find(|(_, character)| !character.is_ascii_hexdigit())
        {
            return Err(RelayTopicError::InvalidHexCharacter { index, character });
        }

        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Creates a topic from raw bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use wc_protocol::relay::RelayTopic;
    ///
    /// let topic = RelayTopic::from_bytes([0xab; 32]);
    /// assert_eq!(
    ///     topic.as_str(),
    ///     "abababababababababababababababababababababababababababababababab",
    /// );
    /// ```
    #[must_use]
    pub fn from_bytes(bytes: [u8; RELAY_TOPIC_BYTES]) -> Self {
        Self(hex_lower(&bytes))
    }

    /// Lowercase hex form serialized into relay JSON-RPC params.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the normalized topic string into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RelayTopic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for RelayTopic {
    type Err = RelayTopicError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl Serialize for RelayTopic {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RelayTopic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(de::Error::custom)
    }
}

/// Relay topic parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayTopicError {
    /// Relay topics are fixed-width 32-byte values, represented as 64 hex characters.
    #[error("relay topic must be 64 hex characters, got {actual}")]
    InvalidLength {
        /// Input length in bytes.
        actual: usize,
    },

    /// Non-hex input cannot map to a 32-byte relay topic.
    #[error("relay topic contains non-hex character {character:?} at byte index {index}")]
    InvalidHexCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by ASCII hex validation.
        character: char,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_rejects_wrong_length() {
        assert_eq!(
            RelayTopic::from_hex("00").expect_err("topic is too short"),
            RelayTopicError::InvalidLength { actual: 2 }
        );
    }

    #[test]
    fn topic_rejects_non_hex_character() {
        assert_eq!(
            RelayTopic::from_hex(format!("{}g", "0".repeat(63)))
                .expect_err("topic has non-hex character"),
            RelayTopicError::InvalidHexCharacter {
                index: 63,
                character: 'g',
            }
        );
    }

    #[test]
    fn topic_serializes_as_string() {
        let topic = RelayTopic::from_bytes([0x42; RELAY_TOPIC_BYTES]);

        assert_eq!(
            serde_json::to_string(&topic).expect("topic serializes"),
            "\"4242424242424242424242424242424242424242424242424242424242424242\""
        );
    }
}
