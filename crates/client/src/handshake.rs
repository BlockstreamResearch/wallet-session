use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use wallet_session_core::{codec, message::Topic};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HKDF info label for the session symmetric key.
const SESSION_KEY_INFO: &[u8] = b"wallet-session/v1/session-key";

/// HKDF info label for the session topic.
const SESSION_TOPIC_INFO: &[u8] = b"wallet-session/v1/session-topic";

/// Symmetric session key derived by both peers.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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
        let shared = Zeroizing::new(shared.to_bytes());
        derive_from_shared(&shared)
    }
}

/// Reject a peer public key that would produce an all-zero shared secret.
pub(crate) fn validate_peer_public(peer_public: &[u8; 32]) -> Result<(), HandshakeError> {
    let probe = EphemeralSecret::random();
    let shared = probe.diffie_hellman(&PublicKey::from(*peer_public));
    if shared.was_contributory() {
        Ok(())
    } else {
        Err(HandshakeError::WeakKey)
    }
}

/// Derive the session key and topic from an X25519 shared secret.
fn derive_from_shared(shared: &[u8; 32]) -> Result<(SessionKey, SessionTopic), HandshakeError> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(HandshakeError::WeakKey);
    }

    let hkdf = Hkdf::<Sha256>::new(None, shared);

    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(SESSION_KEY_INFO, key.as_mut())
        .map_err(|_| HandshakeError::Derive)?;

    let mut topic = Zeroizing::new([0u8; 32]);
    hkdf.expand(SESSION_TOPIC_INFO, topic.as_mut())
        .map_err(|_| HandshakeError::Derive)?;
    let topic = Topic::new(topic.to_vec())?;

    Ok((SessionKey(*key), SessionTopic(topic)))
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
    fn session_key_debug_redacts_material() {
        let alice = EphemeralKeyPair::generate();
        let bob = EphemeralKeyPair::generate();
        let (key, _topic) = alice.derive(&bob.public_key()).expect("derive");
        let rendered = format!("{key:?}");

        assert_eq!(rendered, "SessionKey(..)");
        assert!(!rendered.contains(&codec::encode(key.as_bytes())));
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

    #[test]
    fn session_derivation_known_answer() {
        let shared: [u8; 32] = std::array::from_fn(|index| index as u8);
        let (key, topic) = derive_from_shared(&shared).expect("derive");

        let expected_key =
            wallet_session_core::codec::decode("9ftlKHcaDzlqxuX9UqBAt9hnPpJ9JCZ7O9HAWPAEvcg")
                .expect("key vector");
        assert_eq!(key.as_bytes().as_slice(), expected_key.as_slice());
        assert_eq!(
            topic.as_topic().to_string(),
            "V-btxMBvFE8yC3YzeMsNae9_4Zr0Cyw5A8VvKl2C9sE"
        );
    }

    #[test]
    fn rejects_all_zero_shared_secret() {
        assert!(matches!(
            derive_from_shared(&[0u8; 32]),
            Err(HandshakeError::WeakKey)
        ));
    }

    /// libsodium's blocklist: the canonical encodings of the small-order
    /// points (0, 1, the two points of order 8, and p - 1), plus the
    /// non-canonical encodings p and p + 1 of 0 and 1. X25519 maps all of
    /// them to an all-zero shared secret, whatever our scalar.
    const LOW_ORDER: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    fn low_order_points() -> impl Iterator<Item = [u8; 32]> {
        LOW_ORDER.iter().map(|hex| {
            let mut point = [0u8; 32];
            for (byte, pair) in point.iter_mut().zip(hex.as_bytes().chunks(2)) {
                let pair = std::str::from_utf8(pair).expect("ascii");
                *byte = u8::from_str_radix(pair, 16).expect("hex");
            }
            point
        })
    }

    #[test]
    fn derive_rejects_low_order_peer_keys() {
        for point in low_order_points() {
            let keypair = EphemeralKeyPair::generate();
            assert!(
                matches!(keypair.derive(&point), Err(HandshakeError::WeakKey)),
                "{point:02x?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_peer_public_rejects_low_order_keys() {
        for point in low_order_points() {
            assert!(
                matches!(validate_peer_public(&point), Err(HandshakeError::WeakKey)),
                "{point:02x?} must be rejected"
            );
        }
        let peer = EphemeralKeyPair::generate();
        assert!(validate_peer_public(&peer.public_key()).is_ok());
    }
}
