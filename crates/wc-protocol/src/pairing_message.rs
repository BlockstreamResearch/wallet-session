//! Decrypted pairing-topic relay messages.

use serde_json::Value;

use crate::{
    dto::pairing::PairingMethod,
    envelope::{Envelope, EnvelopeEncoding, EnvelopeError, EnvelopeType},
    pairing::PairingSymKey,
    session::SignMethod,
};

/// Encoded envelope delivered on an encrypted pairing relay topic.
///
/// This type keeps relay-topic decode paths separate from plaintext/link-mode
/// envelopes. `Envelope` itself still supports type-2 plaintext envelopes, but
/// pairing relay topics require authenticated encryption with the pairing
/// symmetric key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedRelayEnvelope<'a> {
    encoded_message: &'a str,
}

impl<'a> EncryptedRelayEnvelope<'a> {
    /// Wraps one relay-delivered encoded message for encrypted-topic decoding.
    #[must_use]
    pub const fn new(encoded_message: &'a str) -> Self {
        Self { encoded_message }
    }

    /// Encoded relay message string.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.encoded_message
    }
}

/// Encoded plaintext envelope for explicit link-mode flows.
///
/// No current pairing relay decode path consumes this type; it exists as a
/// separate marker so future link-mode support cannot accidentally reuse the
/// encrypted relay path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaintextLinkModeEnvelope<'a> {
    encoded_message: &'a str,
}

impl<'a> PlaintextLinkModeEnvelope<'a> {
    /// Wraps one encoded link-mode plaintext message.
    #[must_use]
    pub const fn new(encoded_message: &'a str) -> Self {
        Self { encoded_message }
    }

    /// Encoded plaintext message string.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.encoded_message
    }
}

/// Decrypted JSON payload carried by a relay message on a pairing topic.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
///
/// > Used to propose a session through topic A. Requires a success response
/// > with associated data.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L105-L111>
///
/// > const message = box.decrypt(sealed);
///
/// # Examples
///
/// ```
/// use wc_protocol::{
///     envelope::Envelope,
///     pairing::PairingSymKey,
///     pairing_message::{EncryptedRelayEnvelope, PairingMessage, PairingMessageMethod},
///     session::SignMethod,
/// };
///
/// let sym_key = PairingSymKey::from_hex(
///     "0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c",
/// )?;
/// let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{}}"#;
/// let envelope = Envelope::encrypt_type_0(plaintext, &sym_key)?;
///
/// let encoded = envelope.encode(wc_protocol::envelope::EnvelopeEncoding::Base64);
/// let message = PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&encoded), &sym_key)?;
/// assert_eq!(
///     message.method(),
///     &PairingMessageMethod::Sign(SignMethod::SessionPropose),
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingMessage {
    envelope_type: EnvelopeType,
    plaintext: String,
    json: Value,
    method: PairingMessageMethod,
}

impl PairingMessage {
    /// Decodes an encrypted relay `message` and decrypts it with the pairing symmetric key.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/5db94a85db09a6b2a55269032f73262c0f0fd24a/docs/specs/servers/relay/relay-server-rpc.md#subscription>
    ///
    /// > message - (string) the message to be delivered.
    pub fn decode_relay_message(
        relay_envelope: EncryptedRelayEnvelope<'_>,
        sym_key: &PairingSymKey,
    ) -> Result<Self, PairingMessageError> {
        let envelope = Envelope::decode(relay_envelope.as_str(), EnvelopeEncoding::Base64)
            .map_err(|source| PairingMessageError::Envelope { source })?;
        let plaintext = match envelope.envelope_type() {
            EnvelopeType::Type0 | EnvelopeType::Type1 => envelope
                .decrypt(sym_key)
                .map_err(|source| PairingMessageError::Envelope { source })?,
            EnvelopeType::Type2 => {
                return Err(PairingMessageError::UnexpectedPlaintextEnvelope {
                    envelope_type: EnvelopeType::Type2,
                });
            }
        };
        let json = serde_json::from_str::<Value>(&plaintext)
            .map_err(|source| PairingMessageError::Json { source })?;
        let method = classify_pairing_message(&json);

        Ok(Self {
            envelope_type: envelope.envelope_type(),
            plaintext,
            json,
            method,
        })
    }

    /// Envelope type used by the outer encrypted message.
    #[must_use]
    pub const fn envelope_type(&self) -> EnvelopeType {
        self.envelope_type
    }

    /// Decrypted UTF-8 JSON string.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    /// Parsed decrypted JSON value.
    #[must_use]
    pub const fn json(&self) -> &Value {
        &self.json
    }

    /// Classified JSON-RPC method carried by the pairing message.
    #[must_use]
    pub const fn method(&self) -> &PairingMessageMethod {
        &self.method
    }
}

/// Pairing-topic JSON-RPC method classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingMessageMethod {
    /// Sign API method sent on the pairing topic.
    Sign(SignMethod),
    /// Core Pairing API method sent on the pairing topic.
    Pairing(PairingMethod),
    /// JSON-RPC method name is present but not implemented by current DTOs.
    Unknown(String),
    /// JSON has no string `method` field.
    Missing,
}

/// Pairing message decode/decrypt/parse failure.
#[derive(Debug, thiserror::Error)]
pub enum PairingMessageError {
    /// Envelope decoding, plaintext handling, or decryption failed.
    #[error("pairing message envelope failed")]
    Envelope {
        /// Source envelope failure.
        #[source]
        source: EnvelopeError,
    },

    /// Relay-topic pairing messages must be encrypted.
    #[error("pairing message used unexpected plaintext envelope type {envelope_type:?}")]
    UnexpectedPlaintextEnvelope {
        /// Plaintext envelope type observed on an encrypted relay topic.
        envelope_type: EnvelopeType,
    },

    /// Decrypted payload was not JSON.
    #[error("pairing message JSON failed")]
    Json {
        /// Source JSON parser failure.
        #[source]
        source: serde_json::Error,
    },
}

fn classify_pairing_message(json: &Value) -> PairingMessageMethod {
    let Some(method) = json.get("method").and_then(Value::as_str) else {
        return PairingMessageMethod::Missing;
    };

    if let Some(method) = SignMethod::from_wire(method) {
        return PairingMessageMethod::Sign(method);
    }

    if let Some(method) = PairingMethod::from_wire(method) {
        return PairingMessageMethod::Pairing(method);
    }

    PairingMessageMethod::Unknown(method.to_owned())
}
