//! Encrypted message envelope decoding.

use std::{str, str::Utf8Error};

use base64::{
    DecodeError, Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Error as AeadError, Key, Nonce,
    aead::{Aead, KeyInit},
};
use getrandom::Error as RandomError;

use crate::key::X25519PublicKey;
use crate::pairing::PairingSymKey;

/// `WalletConnect` envelope type byte.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L17-L19>
///
/// > export const TYPE_0 = 0;
/// > export const TYPE_1 = 1;
/// > export const TYPE_2 = 2;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeType {
    /// Symmetric encrypted envelope: `type || iv || sealed`.
    Type0,
    /// Symmetric encrypted envelope with sender public key: `type || senderPublicKey || iv || sealed`.
    Type1,
    /// Plaintext link-mode envelope: `type || message`.
    Type2,
}

/// Encoded envelope alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeEncoding {
    /// Padded base64 used by relay messages.
    Base64,
    /// Unpadded base64url used by link mode.
    Base64Url,
}

/// Deserialized `WalletConnect` envelope.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L134-L148>
///
/// > concat([params.type, params.iv, params.sealed])
///
/// # Examples
///
/// ```
/// use wc_protocol::{
///     envelope::{Envelope, EnvelopeEncoding},
///     pairing::PairingSymKey,
/// };
///
/// let key = PairingSymKey::from_hex(
///     "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c",
/// )?;
/// let envelope = Envelope::decode(
///     "AHF3ZWNmYWFzZGFkc3paHoQ96/mLAdanVxi17icRXq+jyrqXA8ocVgGmryQZBFMg+uwgc8yLa43EOeY+IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg==",
///     EnvelopeEncoding::Base64,
/// )?;
///
/// let message = envelope.decrypt(&key)?;
/// assert!(message.contains("\"method\":\"test_method\""));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    kind: EnvelopeType,
    iv: Option<[u8; ENVELOPE_IV_BYTES]>,
    sealed: Vec<u8>,
    sender_public_key: Option<[u8; ENVELOPE_PUBLIC_KEY_BYTES]>,
}

impl Envelope {
    /// Encrypts a type 0 envelope with a fresh 12-byte IV.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L96-L104>
    ///
    /// > const iv = typeof params.iv !== "undefined" ? fromString(params.iv, BASE16) : randomBytes(IV_LENGTH);
    /// > const sealed = box.encrypt(fromString(params.message, UTF8));
    ///
    /// TODO(wasm): `getrandom` does not support `wasm32-unknown-unknown`
    /// automatically. Before compiling this crate directly for `wc-wasm`, route
    /// IV generation through the Wasm wrapper/core runtime or enable the
    /// documented `wasm_js` backend in the final Wasm package.
    ///
    /// <https://docs.rs/getrandom/0.3.4/getrandom/#webassembly-support>
    ///
    /// > the `wasm32-unknown-unknown` target ... is not automatically supported
    ///
    /// # Examples
    ///
    /// ```
    /// use wc_protocol::{
    ///     envelope::{Envelope, EnvelopeEncoding, EnvelopeType},
    ///     pairing::PairingSymKey,
    /// };
    ///
    /// let key = PairingSymKey::from_hex(
    ///     "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c",
    /// )?;
    /// let encrypted = Envelope::encrypt_type_0(r#"{"jsonrpc":"2.0"}"#, &key)?;
    /// let encoded = encrypted.encode(EnvelopeEncoding::Base64);
    /// let decoded = Envelope::decode(&encoded, EnvelopeEncoding::Base64)?;
    ///
    /// assert_eq!(decoded.envelope_type(), EnvelopeType::Type0);
    /// assert_eq!(decoded.decrypt(&key)?, r#"{"jsonrpc":"2.0"}"#);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn encrypt_type_0(message: &str, sym_key: &PairingSymKey) -> Result<Self, EnvelopeError> {
        let mut iv = [0_u8; ENVELOPE_IV_BYTES];
        getrandom::fill(&mut iv).map_err(|error| EnvelopeError::Random { error })?;
        Self::encrypt_type_0_with_iv(message, sym_key, iv)
    }

    /// Encrypts a type 1 envelope with a fresh 12-byte IV.
    ///
    /// Type 1 adds the sender public key to the encrypted envelope. The caller
    /// derives the shared symmetric key from the sender private key and receiver
    /// public key before calling this function.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L88-L94>
    ///
    /// > if (validated.type === TYPE_1 && validated.senderPublicKey) {
    /// > senderPublicKey = fromString(validated.senderPublicKey, BASE16);
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L141-L144>
    ///
    /// > return toString(concat([params.type, params.senderPublicKey, params.iv, params.sealed]), BASE64);
    pub fn encrypt_type_1(
        message: &str,
        sym_key: &PairingSymKey,
        sender_public_key: &X25519PublicKey,
    ) -> Result<Self, EnvelopeError> {
        let mut iv = [0_u8; ENVELOPE_IV_BYTES];
        getrandom::fill(&mut iv).map_err(|error| EnvelopeError::Random { error })?;
        Self::encrypt_type_1_with_iv(message, sym_key, sender_public_key, iv)
    }

    /// Decodes base64/base64url and splits envelope fields.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L151-L175>
    ///
    /// > const type = bytes.slice(ZERO_INDEX, TYPE_LENGTH);
    /// > const iv = bytes.slice(slice1, slice2);
    pub fn decode(encoded: &str, encoding: EnvelopeEncoding) -> Result<Self, EnvelopeError> {
        let bytes = decode_bytes(encoded, encoding)?;
        let (&type_byte, body) = bytes.split_first().ok_or(EnvelopeError::Empty)?;

        match type_byte {
            TYPE_0 => decode_type_0(body),
            TYPE_1 => decode_type_1(body),
            TYPE_2 => Ok(Self {
                kind: EnvelopeType::Type2,
                iv: None,
                sealed: body.to_vec(),
                sender_public_key: None,
            }),
            other => Err(EnvelopeError::UnsupportedType(other)),
        }
    }

    /// Serializes the envelope bytes and applies the selected outer encoding.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L134-L148>
    ///
    /// > return toString(concat([params.type, params.iv, params.sealed]), BASE64);
    #[must_use]
    pub fn encode(&self, encoding: EnvelopeEncoding) -> String {
        encode_bytes(&self.to_bytes(), encoding)
    }

    /// Envelope type byte.
    #[must_use]
    pub const fn envelope_type(&self) -> EnvelopeType {
        self.kind
    }

    /// Nonce/IV used by encrypted envelopes.
    #[must_use]
    pub const fn iv(&self) -> Option<&[u8; ENVELOPE_IV_BYTES]> {
        self.iv.as_ref()
    }

    /// Ciphertext plus authentication tag for encrypted envelopes.
    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }

    /// Type 1 sender public key, when present.
    #[must_use]
    pub const fn sender_public_key(&self) -> Option<&[u8; ENVELOPE_PUBLIC_KEY_BYTES]> {
        self.sender_public_key.as_ref()
    }

    /// Decrypts a type 0 or type 1 envelope with the pairing symmetric key.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L105-L111>
    ///
    /// > const box = chacha20poly1305(key, iv);
    /// > const message = box.decrypt(sealed);
    pub fn decrypt(&self, sym_key: &PairingSymKey) -> Result<String, EnvelopeError> {
        let iv = self.iv.ok_or(EnvelopeError::NotEncrypted {
            envelope_type: self.kind,
        })?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key.to_bytes()));
        let message = cipher
            .decrypt(Nonce::from_slice(&iv), self.sealed.as_slice())
            .map_err(|source| EnvelopeError::Decrypt { source })?;

        String::from_utf8(message).map_err(|source| EnvelopeError::Utf8 { source })
    }

    /// Decodes a type 2 plaintext envelope.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L126-L131>
    ///
    /// > const { sealed } = deserialize({ encoded, encoding });
    /// > return toString(sealed, UTF8);
    pub fn plaintext(&self) -> Result<&str, EnvelopeError> {
        if self.kind != EnvelopeType::Type2 {
            return Err(EnvelopeError::Encrypted {
                envelope_type: self.kind,
            });
        }

        str::from_utf8(&self.sealed).map_err(|source| EnvelopeError::PlaintextUtf8 { source })
    }

    /// Encrypts with a caller-provided IV for upstream vector parity tests.
    ///
    /// Public encryption always generates a fresh IV. This helper exists so the
    /// test suite can reproduce maintained JavaScript fixtures byte-for-byte.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L96-L104>
    ///
    /// > const iv = typeof params.iv !== "undefined" ? fromString(params.iv, BASE16) : randomBytes(IV_LENGTH);
    /// > const sealed = box.encrypt(fromString(params.message, UTF8));
    fn encrypt_type_0_with_iv(
        message: &str,
        sym_key: &PairingSymKey,
        iv: [u8; ENVELOPE_IV_BYTES],
    ) -> Result<Self, EnvelopeError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key.to_bytes()));
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), message.as_bytes())
            .map_err(|source| EnvelopeError::Encrypt { source })?;

        Ok(Self {
            kind: EnvelopeType::Type0,
            iv: Some(iv),
            sealed,
            sender_public_key: None,
        })
    }

    /// Encrypts a type 1 envelope with a caller-provided IV for vector tests.
    fn encrypt_type_1_with_iv(
        message: &str,
        sym_key: &PairingSymKey,
        sender_public_key: &X25519PublicKey,
        iv: [u8; ENVELOPE_IV_BYTES],
    ) -> Result<Self, EnvelopeError> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&sym_key.to_bytes()));
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), message.as_bytes())
            .map_err(|source| EnvelopeError::Encrypt { source })?;

        Ok(Self {
            kind: EnvelopeType::Type1,
            iv: Some(iv),
            sealed,
            sender_public_key: Some(sender_public_key.to_bytes()),
        })
    }

    /// Serializes the decoded structure back to `type || key? || iv? || sealed`.
    ///
    /// This keeps decode/encode round trips exact for fixtures and for live relay
    /// messages captured by the xtask harness.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L134-L148>
    ///
    /// > const sealed = params.type === TYPE_2 ? fromString(params.sealed, UTF8) : params.sealed;
    /// > return toString(concat([params.type, params.iv, params.sealed]), BASE64);
    fn to_bytes(&self) -> Vec<u8> {
        let sender_public_key_len = self
            .sender_public_key
            .map_or(0, |_| ENVELOPE_PUBLIC_KEY_BYTES);
        let iv_len = self.iv.map_or(0, |_| ENVELOPE_IV_BYTES);
        let mut bytes = Vec::with_capacity(1 + sender_public_key_len + iv_len + self.sealed.len());
        bytes.push(type_byte(self.kind));

        match self.kind {
            EnvelopeType::Type0 => {
                bytes.extend_from_slice(self.iv.expect("type 0 has IV").as_slice());
                bytes.extend_from_slice(&self.sealed);
            }
            EnvelopeType::Type1 => {
                bytes.extend_from_slice(
                    self.sender_public_key
                        .expect("type 1 has sender public key")
                        .as_slice(),
                );
                bytes.extend_from_slice(self.iv.expect("type 1 has IV").as_slice());
                bytes.extend_from_slice(&self.sealed);
            }
            EnvelopeType::Type2 => {
                bytes.extend_from_slice(&self.sealed);
            }
        }

        bytes
    }
}

/// Envelope decoding/decryption error.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Encoded envelope did not decode as base64/base64url.
    #[error("invalid envelope encoding")]
    Base64 {
        /// Base64 decoder failure.
        #[source]
        source: DecodeError,
    },

    /// Envelope has no type byte.
    #[error("empty envelope")]
    Empty,

    /// Envelope type is not currently supported.
    #[error("unsupported envelope type: {0}")]
    UnsupportedType(u8),

    /// OS randomness failed while generating an encryption IV.
    #[error("failed to generate envelope IV: {error}")]
    Random {
        /// OS randomness failure returned by `getrandom`.
        error: RandomError,
    },

    /// Type 0 envelope is too short to contain a 12-byte IV and auth tag.
    #[error("type 0 envelope is too short: {actual} bytes")]
    Type0TooShort {
        /// Body length after the type byte.
        actual: usize,
    },

    /// Type 1 envelope is too short to contain sender key, IV, and auth tag.
    #[error("type 1 envelope is too short: {actual} bytes")]
    Type1TooShort {
        /// Body length after the type byte.
        actual: usize,
    },

    /// Decryption was requested for a plaintext envelope.
    #[error("envelope type {envelope_type:?} is not encrypted")]
    NotEncrypted {
        /// Envelope type.
        envelope_type: EnvelopeType,
    },

    /// Plaintext extraction was requested for an encrypted envelope.
    #[error("envelope type {envelope_type:?} is encrypted")]
    Encrypted {
        /// Envelope type.
        envelope_type: EnvelopeType,
    },

    /// ChaCha20-Poly1305 authentication or decryption failed.
    #[error("failed to decrypt envelope")]
    Decrypt {
        /// AEAD authentication/decryption failure.
        #[source]
        source: AeadError,
    },

    /// ChaCha20-Poly1305 encryption failed.
    #[error("failed to encrypt envelope")]
    Encrypt {
        /// AEAD encryption failure.
        #[source]
        source: AeadError,
    },

    /// Decrypted bytes are not UTF-8 JSON text.
    #[error("decrypted envelope is not UTF-8")]
    Utf8 {
        /// UTF-8 conversion failure.
        #[source]
        source: std::string::FromUtf8Error,
    },

    /// Type 2 bytes are not UTF-8 text.
    #[error("plaintext envelope is not UTF-8")]
    PlaintextUtf8 {
        /// UTF-8 validation failure.
        #[source]
        source: Utf8Error,
    },
}

const TYPE_0: u8 = 0;
const TYPE_1: u8 = 1;
const TYPE_2: u8 = 2;
const ENVELOPE_IV_BYTES: usize = 12;
const ENVELOPE_PUBLIC_KEY_BYTES: usize = 32;
const CHACHA20POLY1305_TAG_BYTES: usize = 16;

/// Decodes the outer envelope representation.
///
/// Relay messages use padded base64. Link-mode payloads use unpadded base64url,
/// matching the JavaScript `toBase64URL` helper.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L76-L83>
///
/// > return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
fn decode_bytes(encoded: &str, encoding: EnvelopeEncoding) -> Result<Vec<u8>, EnvelopeError> {
    match encoding {
        EnvelopeEncoding::Base64 => STANDARD.decode(encoded),
        EnvelopeEncoding::Base64Url => URL_SAFE_NO_PAD.decode(encoded),
    }
    .map_err(|source| EnvelopeError::Base64 { source })
}

/// Applies the outer envelope representation.
///
/// The maintained JavaScript implementation serializes to padded base64 first
/// and then converts to base64url when requested.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L101-L104>
///
/// > return params.encoding === BASE64URL ? toBase64URL(result) : result;
fn encode_bytes(bytes: &[u8], encoding: EnvelopeEncoding) -> String {
    match encoding {
        EnvelopeEncoding::Base64 => STANDARD.encode(bytes),
        EnvelopeEncoding::Base64Url => URL_SAFE_NO_PAD.encode(bytes),
    }
}

/// Maps the decoded enum back to the wire byte.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L17-L19>
///
/// > export const TYPE_0 = 0;
/// > export const TYPE_1 = 1;
/// > export const TYPE_2 = 2;
const fn type_byte(kind: EnvelopeType) -> u8 {
    match kind {
        EnvelopeType::Type0 => TYPE_0,
        EnvelopeType::Type1 => TYPE_1,
        EnvelopeType::Type2 => TYPE_2,
    }
}

/// Splits a type 0 encrypted envelope into IV and sealed bytes.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L171-L175>
///
/// > const iv = bytes.slice(slice1, slice2);
/// > const sealed = bytes.slice(slice2);
fn decode_type_0(body: &[u8]) -> Result<Envelope, EnvelopeError> {
    if body.len() < ENVELOPE_IV_BYTES + CHACHA20POLY1305_TAG_BYTES {
        return Err(EnvelopeError::Type0TooShort { actual: body.len() });
    }

    let (iv, sealed) = body.split_at(ENVELOPE_IV_BYTES);

    Ok(Envelope {
        kind: EnvelopeType::Type0,
        iv: Some(iv.try_into().expect("split_at returns 12 IV bytes")),
        sealed: sealed.to_vec(),
        sender_public_key: None,
    })
}

/// Splits a type 1 encrypted envelope into sender public key, IV, and sealed bytes.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L157-L163>
///
/// > const senderPublicKey = bytes.slice(slice1, slice2);
/// > const iv = bytes.slice(slice2, slice3);
fn decode_type_1(body: &[u8]) -> Result<Envelope, EnvelopeError> {
    let minimum = ENVELOPE_PUBLIC_KEY_BYTES + ENVELOPE_IV_BYTES + CHACHA20POLY1305_TAG_BYTES;
    if body.len() < minimum {
        return Err(EnvelopeError::Type1TooShort { actual: body.len() });
    }

    let (sender_public_key, rest) = body.split_at(ENVELOPE_PUBLIC_KEY_BYTES);
    let (iv, sealed) = rest.split_at(ENVELOPE_IV_BYTES);

    Ok(Envelope {
        kind: EnvelopeType::Type1,
        iv: Some(iv.try_into().expect("split_at returns 12 IV bytes")),
        sealed: sealed.to_vec(),
        sender_public_key: Some(
            sender_public_key
                .try_into()
                .expect("split_at returns 32 sender public key bytes"),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MESSAGE: &str = r#"{"id":1,"jsonrpc":"2.0","method":"test_method","params":{}}"#;
    const TEST_SYM_KEY: &str = "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c";
    const TEST_SENDER_PUBLIC_KEY: [u8; 32] = [
        255, 122, 125, 87, 103, 195, 98, 176, 161, 122, 217, 34, 153, 235, 219, 120, 49, 220, 189,
        154, 86, 149, 156, 1, 54, 140, 116, 4, 84, 59, 51, 66,
    ];
    const TEST_ENCODED_TYPE_0: &str = "AHF3ZWNmYWFzZGFkc3paHoQ96/mLAdanVxi17icRXq+jyrqXA8ocVgGmryQZBFMg+uwgc8yLa43EOeY+IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg==";
    const TEST_ENCODED_TYPE_0_BASE64URL: &str = "AHF3ZWNmYWFzZGFkc3paHoQ96_mLAdanVxi17icRXq-jyrqXA8ocVgGmryQZBFMg-uwgc8yLa43EOeY-IWEv84g8hn4L3Ncsgz6397sgNKnsNcL7A9k3Mg";
    const TEST_ENCODED_TYPE_1: &str = "Af96fVdnw2KwoXrZIpnr23gx3L2aVpWcATaMdARUOzNCcXdlY2ZhYXNkYWRzeloehD3r+YsB1qdXGLXuJxFer6PKupcDyhxWAaavJBkEUyD67CBzzItrjcQ55j4hYS/ziDyGfgvc1yyDPrf3uyA0qew1wvsD2Tcy";
    const TEST_ENCODED_TYPE_2: &str =
        "AnsiaWQiOjEsImpzb25ycGMiOiIyLjAiLCJtZXRob2QiOiJ0ZXN0X21ldGhvZCIsInBhcmFtcyI6e319";

    fn test_key() -> PairingSymKey {
        PairingSymKey::from_hex(TEST_SYM_KEY).expect("test symKey is valid")
    }

    #[test]
    fn decrypts_upstream_type_0_vector() {
        let envelope =
            Envelope::decode(TEST_ENCODED_TYPE_0, EnvelopeEncoding::Base64).expect("decodes");

        assert_eq!(envelope.envelope_type(), EnvelopeType::Type0);
        assert_eq!(
            envelope.decrypt(&test_key()).expect("decrypts"),
            TEST_MESSAGE
        );
    }

    #[test]
    fn encrypts_type_0_matching_upstream_vector() {
        let upstream =
            Envelope::decode(TEST_ENCODED_TYPE_0, EnvelopeEncoding::Base64).expect("decodes");
        let encrypted =
            Envelope::encrypt_type_0_with_iv(TEST_MESSAGE, &test_key(), *upstream.iv().unwrap())
                .expect("encrypts");

        assert_eq!(
            encrypted.encode(EnvelopeEncoding::Base64),
            TEST_ENCODED_TYPE_0
        );
    }

    #[test]
    fn encrypts_type_1_matching_upstream_vector() {
        let upstream =
            Envelope::decode(TEST_ENCODED_TYPE_1, EnvelopeEncoding::Base64).expect("decodes");
        let sender_public_key = X25519PublicKey::from_bytes(TEST_SENDER_PUBLIC_KEY);
        let encrypted = Envelope::encrypt_type_1_with_iv(
            TEST_MESSAGE,
            &test_key(),
            &sender_public_key,
            *upstream.iv().unwrap(),
        )
        .expect("encrypts");

        assert_eq!(
            encrypted.encode(EnvelopeEncoding::Base64),
            TEST_ENCODED_TYPE_1
        );
    }

    #[test]
    fn encodes_type_0_as_base64url() {
        let upstream =
            Envelope::decode(TEST_ENCODED_TYPE_0, EnvelopeEncoding::Base64).expect("decodes");
        let encrypted =
            Envelope::encrypt_type_0_with_iv(TEST_MESSAGE, &test_key(), *upstream.iv().unwrap())
                .expect("encrypts");

        assert_eq!(
            encrypted.encode(EnvelopeEncoding::Base64Url),
            TEST_ENCODED_TYPE_0_BASE64URL
        );
    }

    #[test]
    fn encrypts_type_0_with_random_iv_and_round_trips() {
        let encrypted = Envelope::encrypt_type_0(TEST_MESSAGE, &test_key()).expect("encrypts");
        let encoded = encrypted.encode(EnvelopeEncoding::Base64);
        let decoded = Envelope::decode(&encoded, EnvelopeEncoding::Base64).expect("decodes");

        assert_eq!(decoded.envelope_type(), EnvelopeType::Type0);
        assert_eq!(
            decoded.decrypt(&test_key()).expect("decrypts"),
            TEST_MESSAGE
        );
    }

    #[test]
    fn decrypt_rejects_tampered_type_0_ciphertext() {
        let mut encrypted = Envelope::encrypt_type_0(TEST_MESSAGE, &test_key()).expect("encrypts");
        encrypted.sealed[0] ^= 1;

        assert!(matches!(
            encrypted
                .decrypt(&test_key())
                .expect_err("tampered ciphertext is rejected"),
            EnvelopeError::Decrypt { .. }
        ));
    }

    #[test]
    fn decrypt_rejects_wrong_symmetric_key() {
        let encrypted = Envelope::encrypt_type_0(TEST_MESSAGE, &test_key()).expect("encrypts");
        let wrong_key = PairingSymKey::from_hex("11".repeat(32)).expect("wrong key is valid");

        assert!(matches!(
            encrypted
                .decrypt(&wrong_key)
                .expect_err("wrong key is rejected"),
            EnvelopeError::Decrypt { .. }
        ));
    }

    #[test]
    fn decrypts_upstream_type_0_base64url_vector() {
        let envelope = Envelope::decode(TEST_ENCODED_TYPE_0_BASE64URL, EnvelopeEncoding::Base64Url)
            .expect("decodes");

        assert_eq!(envelope.envelope_type(), EnvelopeType::Type0);
        assert_eq!(
            envelope.decrypt(&test_key()).expect("decrypts"),
            TEST_MESSAGE
        );
        assert_eq!(
            envelope.encode(EnvelopeEncoding::Base64),
            TEST_ENCODED_TYPE_0
        );
    }

    #[test]
    fn decrypts_upstream_type_1_vector_and_keeps_sender_key() {
        let envelope =
            Envelope::decode(TEST_ENCODED_TYPE_1, EnvelopeEncoding::Base64).expect("decodes");

        assert_eq!(envelope.envelope_type(), EnvelopeType::Type1);
        assert_eq!(envelope.sender_public_key(), Some(&TEST_SENDER_PUBLIC_KEY));
        assert_eq!(
            envelope.decrypt(&test_key()).expect("decrypts"),
            TEST_MESSAGE
        );
    }

    #[test]
    fn decodes_upstream_type_2_vector() {
        let envelope =
            Envelope::decode(TEST_ENCODED_TYPE_2, EnvelopeEncoding::Base64Url).expect("decodes");

        assert_eq!(envelope.envelope_type(), EnvelopeType::Type2);
        assert_eq!(envelope.plaintext().expect("plaintext"), TEST_MESSAGE);
        assert_eq!(
            envelope.encode(EnvelopeEncoding::Base64Url),
            TEST_ENCODED_TYPE_2
        );
    }

    #[test]
    fn rejects_decrypt_for_type_2() {
        let envelope =
            Envelope::decode(TEST_ENCODED_TYPE_2, EnvelopeEncoding::Base64Url).expect("decodes");

        assert!(matches!(
            envelope
                .decrypt(&test_key())
                .expect_err("type 2 is plaintext"),
            EnvelopeError::NotEncrypted {
                envelope_type: EnvelopeType::Type2
            }
        ));
    }

    #[test]
    fn rejects_short_type_0() {
        assert!(matches!(
            Envelope::decode("AA==", EnvelopeEncoding::Base64).expect_err("too short"),
            EnvelopeError::Type0TooShort { actual: 0 }
        ));
    }

    #[test]
    fn rejects_unsupported_type() {
        assert!(matches!(
            Envelope::decode("CQ==", EnvelopeEncoding::Base64).expect_err("unknown type"),
            EnvelopeError::UnsupportedType(9)
        ));
    }
}
