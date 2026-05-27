//! Key primitives used by `WalletConnect` protocol messages.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::encoding::{decode_validated_hex, hex_lower};

/// X25519 public key size before hex encoding.
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;

/// X25519 public key size after lowercase hex encoding.
pub const X25519_PUBLIC_KEY_HEX: usize = X25519_PUBLIC_KEY_BYTES * 2;

/// X25519 public key encoded as lowercase base16.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L35-L41>
///
/// > const publicKey = x25519.getPublicKey(privateKey);
/// > publicKey: toString(publicKey, BASE16),
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L49-L55>
///
/// > fromString(publicKeyB, BASE16),
///
/// # Examples
///
/// ```
/// use wc_protocol::key::{X25519PublicKey, X25519_PUBLIC_KEY_HEX};
///
/// let key = X25519PublicKey::from_hex(
///     "051a42272e83b5c59357b55aa04e60a02e70da9caccea1916b62c40b95ed5d50",
/// )?;
///
/// assert_eq!(key.as_str().len(), X25519_PUBLIC_KEY_HEX);
/// assert_eq!(X25519PublicKey::from_bytes(key.to_bytes()), key);
/// # Ok::<(), wc_protocol::key::X25519PublicKeyError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct X25519PublicKey(String);

impl X25519PublicKey {
    /// Creates a key from a 64-character lowercase hex string.
    ///
    /// The maintained JavaScript implementation emits lowercase base16 and
    /// decodes peer keys with `fromString(publicKeyB, BASE16)`.
    pub fn from_hex(value: impl Into<String>) -> Result<Self, X25519PublicKeyError> {
        let value = value.into();
        if value.len() != X25519_PUBLIC_KEY_HEX {
            return Err(X25519PublicKeyError::InvalidLength {
                actual: value.len(),
            });
        }

        if let Some((index, character)) = value
            .char_indices()
            .find(|(_, character)| !matches!(character, '0'..='9' | 'a'..='f'))
        {
            return Err(X25519PublicKeyError::InvalidHexCharacter { index, character });
        }

        Ok(Self(value))
    }

    /// Creates a key from the raw 32-byte X25519 public key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_BYTES]) -> Self {
        Self(hex_lower(&bytes))
    }

    /// Lowercase hex form serialized into Sign API messages.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the normalized key string into caller-owned state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Decodes the key for X25519 shared-secret derivation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_BYTES] {
        let mut bytes = [0_u8; X25519_PUBLIC_KEY_BYTES];
        decode_validated_hex(&self.0, &mut bytes);
        bytes
    }
}

impl fmt::Display for X25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for X25519PublicKey {
    type Err = X25519PublicKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_hex(value)
    }
}

impl Serialize for X25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for X25519PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(value).map_err(de::Error::custom)
    }
}

/// X25519 public-key parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum X25519PublicKeyError {
    /// X25519 public keys are fixed-width 32-byte values encoded as 64 hex characters.
    #[error("X25519 public key must be 64 lowercase hex characters, got {actual}")]
    InvalidLength {
        /// Input length in bytes.
        actual: usize,
    },

    /// Peer key derivation expects lowercase base16 input.
    #[error(
        "X25519 public key contains non-lowercase-hex character {character:?} at byte index {index}"
    )]
    InvalidHexCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by lowercase ASCII hex validation.
        character: char,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn public_key_rejects_wrong_length() {
        assert_eq!(
            X25519PublicKey::from_hex("00").expect_err("key is too short"),
            X25519PublicKeyError::InvalidLength { actual: 2 }
        );
    }

    #[test]
    fn public_key_rejects_non_lowercase_hex() {
        assert_eq!(
            X25519PublicKey::from_hex(format!("{}A", "0".repeat(63)))
                .expect_err("uppercase is not accepted by JS base16 derivation"),
            X25519PublicKeyError::InvalidHexCharacter {
                index: 63,
                character: 'A',
            }
        );
        assert_eq!(
            X25519PublicKey::from_hex(format!("{}g", "0".repeat(63)))
                .expect_err("non-hex character is rejected"),
            X25519PublicKeyError::InvalidHexCharacter {
                index: 63,
                character: 'g',
            }
        );
    }

    #[test]
    fn public_key_serializes_as_string() {
        let key = X25519PublicKey::from_bytes([0x42; X25519_PUBLIC_KEY_BYTES]);

        assert_eq!(
            serde_json::to_value(key).expect("serializes"),
            json!("4242424242424242424242424242424242424242424242424242424242424242")
        );
    }
}
