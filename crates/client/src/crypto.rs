use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Key, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wallet_session_core::{
    connection::Role,
    crypto::MessageCipher,
    did::DidKey,
    message::{Ciphertext, Message, MessageType, Nonce, Topic},
};

/// Symmetric key length
pub const KEY_LEN: usize = 32;

/// Random per-sender nonce prefix length
pub const SENDER_PREFIX_LEN: usize = 16;

/// AEAD nonce length: sender prefix plus counter
pub const NONCE_LEN: usize = 24;

/// AEAD associated data bound to the plaintext envelope header.
///
/// Each field is a UTF-8 string prefixed by its length as a four-byte
/// big-endian integer:
///
/// `AAD = LP(version) || LP(id) || LP(kind) || LP(topic) || LP(from) || LP(ts) || LP(role)`
///
/// The sender uses its own role; the receiver rebuilds the AAD with its
/// counterpart's role, so an envelope returned to its sender does not
/// authenticate.
///
/// TODO: verify `from` against the expected peer identity once it is known.
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

    /// Sender identity
    pub from: &'a DidKey,

    /// Envelope timestamp
    pub ts: u64,

    /// Sender role on the topic
    pub role: Role,
}

impl<'a> Aad<'a> {
    /// Build associated data with the current envelope version.
    pub fn new(
        id: &'a str,
        kind: MessageType,
        topic: &'a Topic,
        from: &'a DidKey,
        ts: u64,
        role: Role,
    ) -> Self {
        Self {
            version: Message::VERSION,
            id,
            kind,
            topic,
            from,
            ts,
            role,
        }
    }

    /// Serialize the associated data as length-prefixed UTF-8 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let version = self.version.to_string();
        let topic = self.topic.to_string();
        let from = self.from.to_string();
        let ts = self.ts.to_string();
        let fields = [
            version.as_str(),
            self.id,
            self.kind.as_str(),
            topic.as_str(),
            from.as_str(),
            ts.as_str(),
            self.role.as_str(),
        ];

        let mut bytes = Vec::new();
        for field in fields {
            let len = u32::try_from(field.len()).expect("AAD field length fits u32");
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
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

    fn did(seed: u8) -> DidKey {
        DidKey::from_ed25519_bytes([seed; 32])
    }

    fn aad(kind: MessageType, topic: &Topic) -> Vec<u8> {
        Aad::new(
            "frame-id",
            kind,
            topic,
            &did(7),
            1_700_000_000,
            Role::Proposer,
        )
        .to_bytes()
    }

    #[test]
    fn aad_is_length_prefixed_and_includes_ts_and_role() {
        let topic = topic();
        let from = did(7);
        let aad = Aad::new(
            "frame-id",
            MessageType::Request,
            &topic,
            &from,
            1_700_000_000,
            Role::Proposer,
        )
        .to_bytes();

        let fields = [
            Message::VERSION.to_string(),
            "frame-id".to_owned(),
            "request".to_owned(),
            topic.to_string(),
            from.to_string(),
            "1700000000".to_owned(),
            "proposer".to_owned(),
        ];
        let mut expected = Vec::new();
        for field in fields {
            expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expected.extend_from_slice(field.as_bytes());
        }

        assert_eq!(aad, expected);
    }

    #[test]
    fn aad_binds_timestamp_and_role() {
        let topic = topic();
        let from = did(7);
        let aad = |ts, role| {
            Aad::new("frame-id", MessageType::Request, &topic, &from, ts, role).to_bytes()
        };

        assert_ne!(
            aad(1_700_000_000, Role::Proposer),
            aad(1_700_000_001, Role::Proposer)
        );
        assert_ne!(
            aad(1_700_000_000, Role::Proposer),
            aad(1_700_000_000, Role::Responder)
        );
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
    fn rejects_tampered_from() -> TestResult {
        let topic = topic();
        let mut cipher = XChaCha20Poly1305Cipher::with_prefix([9u8; 32], [3u8; 16])?;

        let sealed = cipher.seal(
            &Aad::new(
                "frame-id",
                MessageType::Request,
                &topic,
                &did(1),
                1_700_000_000,
                Role::Proposer,
            )
            .to_bytes(),
            b"hello",
        )?;
        let tampered = Aad::new(
            "frame-id",
            MessageType::Request,
            &topic,
            &did(2),
            1_700_000_000,
            Role::Proposer,
        )
        .to_bytes();

        assert!(matches!(
            cipher.open(&tampered, &sealed),
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
