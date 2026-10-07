use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use wallet_session_core::{codec, message::Topic};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// HKDF info label for the session symmetric key.
const SESSION_KEY_INFO: &[u8] = b"wallet-session/v1/session-key";

/// HKDF info label for the session topic.
const SESSION_TOPIC_INFO: &[u8] = b"wallet-session/v1/session-topic";

/// Symmetric session key derived by both peers.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKey([u8; 32]);

impl SessionKey {
    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// Session topic derived by both peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTopic(Topic);

impl SessionTopic {
    /// Borrow the topic.
    pub fn as_topic(&self) -> &Topic {
        &self.0
    }
}

/// A one-time X25519 keypair for the session handshake.
pub struct EphemeralKeyPair {
    secret: EphemeralSecret,
}

impl EphemeralKeyPair {
    /// Generate a fresh ephemeral keypair.
    pub fn generate() -> Self {
        Self {
            secret: EphemeralSecret::random(),
        }
    }

    /// Raw public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// Base64url-encoded public key for the handshake payload.
    pub fn public_key_encoded(&self) -> String {
        codec::encode(&self.public_key())
    }

    /// Derive the session key and topic from the peer's public key.
    ///
    /// Consumes the keypair: ephemeral secrets are used once.
    pub fn derive(
        self,
        peer_public: &[u8; 32],
    ) -> Result<(SessionKey, SessionTopic), HandshakeError> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        let shared = shared.to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(HandshakeError::WeakKey);
        }

        let hkdf = Hkdf::<Sha256>::new(None, &shared);

        let mut key = [0u8; 32];
        hkdf.expand(SESSION_KEY_INFO, &mut key)
            .map_err(|_| HandshakeError::Derive)?;

        let mut topic = [0u8; 32];
        hkdf.expand(SESSION_TOPIC_INFO, &mut topic)
            .map_err(|_| HandshakeError::Derive)?;
        let topic = Topic::new(topic.to_vec())?;

        Ok((SessionKey(key), SessionTopic(topic)))
    }
}

/// Decode a base64url public key from a handshake payload.
pub fn decode_public_key(encoded: &str) -> Result<[u8; 32], HandshakeError> {
    let bytes = codec::decode(encoded)?;
    bytes.try_into().map_err(|_| HandshakeError::PeerKey)
}

/// Handshake and key-agreement failures.
#[derive(Debug, Error)]
pub enum HandshakeError {
    /// The peer's public key was not a valid 32-byte base64url value.
    #[error("invalid peer public key")]
    PeerKey,

    /// The derived shared secret was all zero (low-order public key).
    #[error("weak peer public key")]
    WeakKey,

    /// HKDF expansion failed.
    #[error("key derivation failed")]
    Derive,

    /// The derived session topic was invalid.
    #[error("invalid session topic: {0}")]
    Topic(#[from] wallet_session_core::error::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_derive_the_same_session() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let (alice_key, alice_topic) = alice.derive(&bob_public).expect("alice derive");
        let (bob_key, bob_topic) = bob.derive(&alice_public).expect("bob derive");

        assert_eq!(alice_key, bob_key);
        assert_eq!(alice_topic, bob_topic);
    }

    #[test]
    fn distinct_pairs_derive_distinct_keys() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();
        let mallory = EphemeralKeyPair::generate();

        let (_, alice_topic) = alice.derive(&bob.public_key()).expect("derive");
        let (_, other_topic) = mallory.derive(&bob.public_key()).expect("derive");
        assert_ne!(alice_topic, other_topic);
    }

    #[test]
    fn decodes_public_key() {
        let pair = EphemeralKeyPair::generate();
        let decoded = decode_public_key(&pair.public_key_encoded()).expect("decode");
        assert_eq!(decoded, pair.public_key());
        assert!(decode_public_key("nope").is_err());
    }
}
