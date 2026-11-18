use std::fmt;

use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};
use wallet_session_core::{codec, message::Topic};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{error::ClientError, error::Result, random};

const CONNECTION_SCHEME: &str = "bsconnect";

/// 32-byte symmetric pairing key shared out of band
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairingKey([u8; 32]);

impl PairingKey {
    /// Generate a fresh random pairing key.
    pub fn random() -> Result<Self> {
        Ok(Self(random::bytes()?))
    }

    /// Wrap raw pairing key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Pairing topic derived from the key
    pub fn topic(&self) -> Result<Topic> {
        let digest = Sha256::digest(self.0);
        Ok(Topic::new(digest.to_vec())?)
    }

    /// Base64url representation used in the pairing URI
    pub fn to_base64(&self) -> String {
        codec::encode(&self.0)
    }

    /// Parse a base64url pairing key.
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let bytes = Zeroizing::new(codec::decode(encoded)?);
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| ClientError::PairingUri("bad pairing key length".to_owned()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for PairingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairingKey(..)")
    }
}

/// Pairing URI
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingUri {
    /// Symmetric pairing key.
    pub key: PairingKey,

    /// Relay endpoint to connect to.
    pub relay: String,
}

impl PairingUri {
    /// Build a pairing URI for a key and relay endpoint.
    pub fn new(key: PairingKey, relay: impl Into<String>) -> Self {
        Self {
            key,
            relay: relay.into(),
        }
    }

    pub fn parse(uri: &str) -> Result<Self> {
        let url = Url::parse(uri).map_err(|_| ClientError::PairingUri("invalid URI".to_owned()))?;
        if url.scheme() != CONNECTION_SCHEME || url.host_str() != Some("pairing") {
            return Err(ClientError::PairingUri("not a pairing URI".to_owned()));
        }

        let mut key = None;
        let mut relay = None;
        for (name, value) in url.query_pairs() {
            match name.as_ref() {
                "key" => key = Some(PairingKey::from_base64(&value)?),
                "relay" => relay = Some(value.into_owned()),
                _ => {}
            }
        }

        Ok(Self {
            key: key.ok_or_else(|| ClientError::PairingUri("missing pairing key".to_owned()))?,
            relay: relay
                .ok_or_else(|| ClientError::PairingUri("missing relay endpoint".to_owned()))?,
        })
    }
}

impl fmt::Display for PairingUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("key", &self.key.to_base64())
            .append_pair("relay", &self.relay)
            .finish();
        write!(f, "{CONNECTION_SCHEME}://pairing?{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_is_sha256_of_key() {
        let key = PairingKey::from_bytes([3u8; 32]);
        let expected = Topic::new(Sha256::digest([3u8; 32]).to_vec()).expect("topic");
        assert_eq!(key.topic().expect("topic"), expected);
    }

    #[test]
    fn pairing_uri_round_trips() {
        let uri = PairingUri::new(
            PairingKey::from_bytes([9u8; 32]),
            "wss://relay.example.com/",
        );
        let rendered = uri.to_string();
        assert_eq!(PairingUri::parse(&rendered).expect("parsed"), uri);
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(PairingUri::parse("https://example.com").is_err());
    }

    #[test]
    fn errors_do_not_echo_pairing_secrets_or_uris() {
        let key = codec::encode(&[9u8; 32]);
        let uri = format!("https://example.com/?key={key}&relay=wss://relay.example.com");
        let error = PairingUri::parse(&uri).expect_err("wrong scheme");
        let text = error.to_string();
        assert!(!text.contains(&key), "{text}");
        assert!(!text.contains("relay.example.com"), "{text}");

        let short = codec::encode(&[1u8; 31]);
        let error = PairingKey::from_base64(&short).expect_err("short key");
        let text = error.to_string();
        assert!(!text.contains(&short), "{text}");
    }

    #[test]
    fn missing_fields_have_fixed_errors() {
        let error = PairingUri::parse("bsconnect://pairing?relay=wss://relay.example.com")
            .expect_err("missing key");
        assert_eq!(
            error.to_string(),
            "invalid pairing uri: missing pairing key"
        );

        let key = codec::encode(&[0u8; 32]);
        let error = PairingUri::parse(&format!("bsconnect://pairing?key={key}"))
            .expect_err("missing relay");
        assert_eq!(
            error.to_string(),
            "invalid pairing uri: missing relay endpoint"
        );
    }
}
