use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Key, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_session_core::{
    crypto::MessageCipher,
    message::{Ciphertext, MessageType, Nonce, Topic},
};

/// Symmetric key length
pub const KEY_LEN: usize = 32;

/// Random per-sender nonce prefix length
pub const SENDER_PREFIX_LEN: usize = 16;

/// AEAD nonce length: sender prefix plus counter
pub const NONCE_LEN: usize = 24;

/// AEAD associated data bound to the plaintext envelope header
///
/// `AAD = version || id || type || topic`.
/// TODO:: add `from` field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aad<'a> {
    /// Protocol version
    pub version: u8,

    /// Envelope id
    pub id: &'a str,

    /// Message type
    pub kind: MessageType,

    /// Subscription topic
    pub topic: &'a Topic,
}

impl<'a> Aad<'a> {
    pub fn new(id: &'a str, kind: MessageType, topic: &'a Topic) -> Self {
        Self {
            version: 1,
            id,
            kind,
            topic,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.version.to_string().as_bytes());
        bytes.extend_from_slice(self.id.as_bytes());
        bytes.extend_from_slice(self.kind.as_str().as_bytes());
        bytes.extend_from_slice(self.topic.to_string().as_bytes());
        bytes
    }
}

/// Cipher output for a single message: nonce plus ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPayload {
    /// AEAD nonce
    pub nonce: Nonce,

    /// Ciphertext with tag
    pub data: Ciphertext,
}

/// Wire payload: plaintext type tag plus the sealed payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// Message type (plaintext, authenticated via the AAD).
    pub kind: MessageType,

    /// AEAD nonce, base64url.
    pub nonce: Nonce,

    /// Ciphertext with tag, base64url.
    pub data: Ciphertext,
}

impl WireEnvelope {
    /// Wrap a sealed payload with its plaintext type tag.
    pub fn new(kind: MessageType, sealed: SealedPayload) -> Self {
        Self {
            kind,
            nonce: sealed.nonce,
            data: sealed.data,
        }
    }

    /// Split into the plaintext type tag and the sealed payload.
    pub fn into_parts(self) -> (MessageType, SealedPayload) {
        (
            self.kind,
            SealedPayload {
                nonce: self.nonce,
                data: self.data,
            },
        )
    }
}

/// Encryption and decryption failures.
#[derive(Debug, Error)]
pub enum CipherError {
    /// Encryption failed.
    #[error("encryption failed")]
    Encrypt,

    /// Decryption failed (bad key, tampered data, or AAD mismatch).
    #[error("decryption failed")]
    Decrypt,

    /// A nonce had the wrong length.
    #[error("invalid nonce length: {0}")]
    NonceLength(usize),

    /// A random source failed.
    #[error("random source failure: {0}")]
    Random(#[from] getrandom::Error),
}

/// XChaCha20-Poly1305 provider
pub struct XChaCha20Poly1305Cipher {
    prefix: [u8; SENDER_PREFIX_LEN],
    counter: u64,
    inner: XChaCha20Poly1305,
}

impl XChaCha20Poly1305Cipher {
    /// Build a cipher with a random sender prefix.
    pub fn new(key: [u8; KEY_LEN]) -> Result<Self, CipherError> {
        let mut prefix = [0u8; SENDER_PREFIX_LEN];
        getrandom::fill(&mut prefix)?;
        Self::with_prefix(key, prefix)
    }

    /// Build a cipher with a fixed sender prefix
    pub fn with_prefix(
        key: [u8; KEY_LEN],
        prefix: [u8; SENDER_PREFIX_LEN],
    ) -> Result<Self, CipherError> {
        Ok(Self {
            prefix,
            counter: 0,
            inner: XChaCha20Poly1305::new_from_slice(&key).map_err(|_| CipherError::Encrypt)?,
        })
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..SENDER_PREFIX_LEN].copy_from_slice(&self.prefix);
        nonce[SENDER_PREFIX_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }
}

impl MessageCipher for XChaCha20Poly1305Cipher {
    type Sealed = SealedPayload;
    type Error = CipherError;
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<SealedPayload, CipherError> {
        let nonce = self.nonce();
        let data = self
            .inner
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CipherError::Encrypt)?;
        self.counter = self.counter.wrapping_add(1);

        let nonce = Nonce::new(nonce.to_vec()).map_err(|_| CipherError::NonceLength(NONCE_LEN))?;
        Ok(SealedPayload {
            nonce,
            data: Ciphertext::new(data),
        })
    }

    fn open(&self, aad: &[u8], sealed: &SealedPayload) -> Result<Vec<u8>, CipherError> {
        let nonce = sealed.nonce.as_bytes();
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CipherError::NonceLength(nonce.len()))?;

        self.inner
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: sealed.data.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| CipherError::Decrypt)
    }

    fn rekey(&mut self, key: &[u8; KEY_LEN]) {
        self.inner = XChaCha20Poly1305::new(&Key::<XChaCha20Poly1305>::from(*key));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn topic() -> Topic {
        Topic::new([1u8; 32]).expect("topic")
    }

    fn aad(kind: MessageType, topic: &Topic) -> Vec<u8> {
        Aad {
            version: 1,
            id: "frame-id",
            kind,
            topic,
        }
        .to_bytes()
    }

    #[test]
    fn round_trips() -> TestResult {
        let topic = topic();
        let aad = aad(MessageType::Request, &topic);
        let mut cipher = XChaCha20Poly1305Cipher::with_prefix([9u8; 32], [3u8; 16])?;

        let sealed = cipher.seal(&aad, b"hello")?;
        assert_eq!(cipher.open(&aad, &sealed)?, b"hello");
        Ok(())
    }

    #[test]
    fn rejects_tampered_aad() -> TestResult {
        let topic = topic();
        let mut cipher = XChaCha20Poly1305Cipher::with_prefix([9u8; 32], [3u8; 16])?;
        let sealed = cipher.seal(&aad(MessageType::Request, &topic), b"hello")?;

        let other = aad(MessageType::Response, &topic);
        assert!(matches!(
            cipher.open(&other, &sealed),
            Err(CipherError::Decrypt)
        ));
        Ok(())
    }

    #[test]
    fn nonce_advances_per_message() -> TestResult {
        let topic = topic();
        let aad = aad(MessageType::Request, &topic);
        let mut cipher = XChaCha20Poly1305Cipher::with_prefix([9u8; 32], [3u8; 16])?;

        let first = cipher.seal(&aad, b"a")?;
        let second = cipher.seal(&aad, b"a")?;
        assert_ne!(first.nonce, second.nonce);
        Ok(())
    }
}
