//! Key primitives used by `WalletConnect` protocol messages.

use std::{fmt, str::FromStr};

use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};
use getrandom::Error as RandomError;
use hkdf::Hkdf;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};

use crate::encoding::{decode_validated_hex, hex_lower};
use crate::{pairing::PairingSymKey, relay::RelayTopic};

/// X25519 public key size before hex encoding.
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;

/// X25519 public key size after lowercase hex encoding.
pub const X25519_PUBLIC_KEY_HEX: usize = X25519_PUBLIC_KEY_BYTES * 2;

/// X25519 private key size before hex encoding.
pub const X25519_PRIVATE_KEY_BYTES: usize = 32;

/// X25519 private key size after lowercase hex encoding.
pub const X25519_PRIVATE_KEY_HEX: usize = X25519_PRIVATE_KEY_BYTES * 2;

/// X25519 private key encoded as lowercase base16.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L35-L41>
///
/// > const privateKey = x25519.utils.randomPrivateKey();
/// > privateKey: toString(privateKey, BASE16),
#[derive(Clone, PartialEq, Eq)]
pub struct X25519PrivateKey(String);

impl X25519PrivateKey {
    /// Creates a key from a 64-character lowercase hex string.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L49-L55>
    ///
    /// > fromString(privateKeyA, BASE16),
    pub fn from_hex(value: impl Into<String>) -> Result<Self, X25519PrivateKeyError> {
        let value = value.into();
        if value.len() != X25519_PRIVATE_KEY_HEX {
            return Err(X25519PrivateKeyError::InvalidLength {
                actual: value.len(),
            });
        }

        if let Some((index, character)) = value
            .char_indices()
            .find(|(_, character)| !matches!(character, '0'..='9' | 'a'..='f'))
        {
            return Err(X25519PrivateKeyError::InvalidHexCharacter { index, character });
        }

        Ok(Self(value))
    }

    /// Creates a key from raw private key bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; X25519_PRIVATE_KEY_BYTES]) -> Self {
        Self(hex_lower(&bytes))
    }

    /// Lowercase hex form used by the `WalletConnect` keychain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the key for X25519 shared-secret derivation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; X25519_PRIVATE_KEY_BYTES] {
        let mut bytes = [0_u8; X25519_PRIVATE_KEY_BYTES];
        decode_validated_hex(&self.0, &mut bytes);
        bytes
    }

    /// Derives the matching X25519 public key.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L35-L41>
    ///
    /// > const publicKey = x25519.getPublicKey(privateKey);
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        let public_key = X25519_BASEPOINT.mul_clamped(self.to_bytes());
        X25519PublicKey::from_bytes(public_key.to_bytes())
    }
}

impl fmt::Debug for X25519PrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("X25519PrivateKey(<redacted>)")
    }
}

/// X25519 key pair used for `WalletConnect` session key agreement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519KeyPair {
    private_key: X25519PrivateKey,
    public_key: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generates a fresh X25519 key pair.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L35-L41>
    ///
    /// > const privateKey = x25519.utils.randomPrivateKey();
    /// > const publicKey = x25519.getPublicKey(privateKey);
    pub fn generate() -> Result<Self, X25519KeyPairError> {
        let mut private_key = [0_u8; X25519_PRIVATE_KEY_BYTES];
        getrandom::fill(&mut private_key).map_err(|error| X25519KeyPairError::Random { error })?;
        Ok(Self::from_private_key(X25519PrivateKey::from_bytes(
            private_key,
        )))
    }

    /// Builds a key pair from private key material.
    #[must_use]
    pub fn from_private_key(private_key: X25519PrivateKey) -> Self {
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Private key retained by the local keychain.
    #[must_use]
    pub const fn private_key(&self) -> &X25519PrivateKey {
        &self.private_key
    }

    /// Public key sent to the peer in proposal/settle DTOs.
    #[must_use]
    pub const fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }
}

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

/// Derives the symmetric key shared by two X25519 peers.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L49-L55>
///
/// > const sharedKey = x25519.getSharedSecret(
/// > const symKey = hkdf(sha256, sharedKey, undefined, undefined, KEY_LENGTH);
///
/// # Examples
///
/// ```
/// use wc_protocol::key::{X25519PrivateKey, X25519PublicKey, derive_shared_sym_key};
///
/// let private_key = X25519PrivateKey::from_hex(
///     "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce",
/// )?;
/// let peer_public_key = X25519PublicKey::from_hex(
///     "80dd64bd6e4c3612ff0f5ccbe9282f1f11ba56ada6a2f9740da063d1ed1f2b20",
/// )?;
///
/// let sym_key = derive_shared_sym_key(&private_key, &peer_public_key);
/// assert_eq!(
///     sym_key.as_str(),
///     "81b30968ad471e842d9936c567429a0ce7c04787ed8d103143cdba785be7ba1a",
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub fn derive_shared_sym_key(
    private_key: &X25519PrivateKey,
    peer_public_key: &X25519PublicKey,
) -> PairingSymKey {
    let shared_secret =
        MontgomeryPoint(peer_public_key.to_bytes()).mul_clamped(private_key.to_bytes());
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut sym_key = [0_u8; crate::pairing::PAIRING_SYM_KEY_BYTES];
    hkdf.expand(&[], &mut sym_key)
        .expect("32-byte HKDF output is within SHA-256 expansion limit");
    PairingSymKey::from_bytes(sym_key)
}

/// Hashes a symmetric key into the topic used for relay routing.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L58-L61>
///
/// > const result = sha256(fromString(key, BASE16));
/// > return toString(result, BASE16);
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/crypto.ts#L81-L85>
///
/// > const topic = overrideTopic || hashKey(symKey);
#[must_use]
pub fn derive_topic_from_sym_key(sym_key: &PairingSymKey) -> RelayTopic {
    RelayTopic::from_bytes(Sha256::digest(sym_key.to_bytes()).into())
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

/// X25519 private-key parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum X25519PrivateKeyError {
    /// X25519 private keys are fixed-width 32-byte values encoded as 64 hex characters.
    #[error("X25519 private key must be 64 lowercase hex characters, got {actual}")]
    InvalidLength {
        /// Input length in bytes.
        actual: usize,
    },

    /// `WalletConnect` key agreement expects lowercase base16 input.
    #[error(
        "X25519 private key contains non-lowercase-hex character {character:?} at byte index {index}"
    )]
    InvalidHexCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by lowercase ASCII hex validation.
        character: char,
    },
}

/// X25519 key-pair generation error.
#[derive(Debug, thiserror::Error)]
pub enum X25519KeyPairError {
    /// OS randomness failed while generating private key material.
    #[error("failed to generate X25519 private key: {error}")]
    Random {
        /// OS randomness failure returned by `getrandom`.
        error: RandomError,
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
