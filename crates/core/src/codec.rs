use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serializer};

use crate::error::Error;

/// Encode bytes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url into bytes.
pub fn decode(input: &str) -> Result<Vec<u8>, Error> {
    Ok(URL_SAFE_NO_PAD.decode(input)?)
}

/// `serde` adapter that encodes a byte field as unpadded base64url.
pub mod base64url {
    use super::*;

    /// Serialize bytes as a base64url string.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode(bytes))
    }

    /// Deserialize a base64url string into bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        decode(&encoded).map_err(serde::de::Error::custom)
    }
}
