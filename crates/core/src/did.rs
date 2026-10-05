use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Multibase prefix plus multibase code (`z` = base58btc) for `did:key`.
const DID_KEY_PREFIX: &str = "did:key:z";

/// Multicodec prefix for an Ed25519 public key (`ed25519-pub`).
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// An Ed25519 `did:key` identifier.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DidKey([u8; 32]);

/// Failures decoding a `did:key`.
#[derive(Debug, Error)]
pub enum DidError {
    #[error("not a did:key multibase identifier: {0}")]
    Prefix(String),

    #[error("invalid base58btc did:key: {0}")]
    Base58(String),

    #[error("unsupported did:key key type")]
    KeyType,

    #[error("invalid Ed25519 public key length: {0}")]
    Length(usize),
}

impl DidKey {
    pub fn from_ed25519_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_ed25519_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn parse(input: &str) -> Result<Self, DidError> {
        let encoded = input
            .strip_prefix(DID_KEY_PREFIX)
            .ok_or_else(|| DidError::Prefix(input.to_owned()))?;
        let bytes = bs58::decode(encoded)
            .into_vec()
            .map_err(|error| DidError::Base58(error.to_string()))?;

        if !bytes.starts_with(&ED25519_MULTICODEC) {
            return Err(DidError::KeyType);
        }
        let key = &bytes[ED25519_MULTICODEC.len()..];
        let key: [u8; 32] = key.try_into().map_err(|_| DidError::Length(key.len()))?;
        Ok(Self(key))
    }
}

impl fmt::Display for DidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = [0u8; ED25519_MULTICODEC.len() + 32];
        bytes[..ED25519_MULTICODEC.len()].copy_from_slice(&ED25519_MULTICODEC);
        bytes[ED25519_MULTICODEC.len()..].copy_from_slice(&self.0);
        write!(f, "{DID_KEY_PREFIX}{}", bs58::encode(bytes).into_string())
    }
}

impl fmt::Debug for DidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DidKey({self})")
    }
}

impl FromStr for DidKey {
    type Err = DidError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

impl From<DidKey> for String {
    fn from(key: DidKey) -> Self {
        key.to_string()
    }
}

impl TryFrom<String> for DidKey {
    type Error = DidError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl TryFrom<&str> for DidKey {
    type Error = DidError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn parses_and_re_encodes_example() {
        let key = DidKey::parse(EXAMPLE).expect("parse");
        assert_eq!(key.to_string(), EXAMPLE);
    }

    #[test]
    fn bytes_round_trip() {
        let key = DidKey::from_ed25519_bytes([7u8; 32]);
        let parsed = DidKey::parse(&key.to_string()).expect("parse");
        assert_eq!(parsed, key);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(matches!(
            DidKey::parse("did:web:example.com"),
            Err(DidError::Prefix(_))
        ));
    }

    #[test]
    fn rejects_unsupported_multicodec() {
        let mut bytes = vec![0x00, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        assert!(matches!(DidKey::parse(&did), Err(DidError::KeyType)));
    }

    #[test]
    fn rejects_wrong_length() {
        let mut bytes = ED25519_MULTICODEC.to_vec();
        bytes.extend_from_slice(&[0u8; 31]);
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        assert!(matches!(DidKey::parse(&did), Err(DidError::Length(31))));
    }

    #[test]
    fn json_round_trips() -> TestResult {
        let key = DidKey::parse(EXAMPLE)?;
        let json = serde_json::to_string(&key)?;
        assert_eq!(json, format!("\"{EXAMPLE}\""));
        assert_eq!(serde_json::from_str::<DidKey>(&json)?, key);
        Ok(())
    }
}
