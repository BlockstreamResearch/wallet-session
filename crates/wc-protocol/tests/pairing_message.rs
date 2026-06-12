//! Pairing-topic message decode/decrypt/classification tests.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::json;
use wc_protocol::{
    dto::pairing::PairingMethod,
    envelope::{Envelope, EnvelopeEncoding},
    pairing::PairingSymKey,
    pairing_message::{
        EncryptedRelayEnvelope, PairingMessage, PairingMessageError, PairingMessageMethod,
    },
    session::SignMethod,
};

fn test_key() -> PairingSymKey {
    PairingSymKey::from_hex("0653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c")
        .expect("test key is valid")
}

fn encrypted_message(value: &serde_json::Value, sym_key: &PairingSymKey) -> String {
    let plaintext = serde_json::to_string(&value).expect("serializes fixture");
    Envelope::encrypt_type_0(&plaintext, sym_key)
        .expect("encrypts fixture")
        .encode(EnvelopeEncoding::Base64)
}

#[test]
fn decrypts_and_classifies_session_proposal_on_pairing_topic() {
    let sym_key = test_key();
    let value = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "wc_sessionPropose",
        "params": {
            "relays": [{"protocol": "irn"}],
            "proposer": {
                "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                "metadata": {
                    "name": "React App",
                    "description": "React App for WalletConnect",
                    "url": "https://example.com",
                    "icons": []
                }
            },
            "requiredNamespaces": {},
            "optionalNamespaces": {}
        }
    });
    let encoded = encrypted_message(&value, &sym_key);

    let message =
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&encoded), &sym_key)
            .expect("message decrypts");

    assert_eq!(
        message.envelope_type(),
        wc_protocol::envelope::EnvelopeType::Type0
    );
    assert_eq!(
        message.method(),
        &PairingMessageMethod::Sign(SignMethod::SessionPropose)
    );
    assert_eq!(message.json(), &value);
    assert!(message.plaintext().contains("wc_sessionPropose"));
}

#[test]
fn decrypts_and_classifies_pairing_ping_on_pairing_topic() {
    let sym_key = test_key();
    let value = json!({
        "id": 2,
        "jsonrpc": "2.0",
        "method": "wc_pairingPing",
        "params": {},
    });
    let encoded = encrypted_message(&value, &sym_key);

    let message =
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&encoded), &sym_key)
            .expect("message decrypts");

    assert_eq!(
        message.method(),
        &PairingMessageMethod::Pairing(PairingMethod::Ping)
    );
}

#[test]
fn preserves_unknown_and_missing_methods() {
    let sym_key = test_key();
    let unknown = encrypted_message(
        &json!({"id": 3, "jsonrpc": "2.0", "method": "wc_futureMethod", "params": {}}),
        &sym_key,
    );
    let missing = encrypted_message(&json!({"id": 4, "jsonrpc": "2.0", "params": {}}), &sym_key);

    assert_eq!(
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&unknown), &sym_key)
            .expect("unknown method decrypts")
            .method(),
        &PairingMessageMethod::Unknown("wc_futureMethod".to_owned())
    );
    assert_eq!(
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&missing), &sym_key)
            .expect("missing method decrypts")
            .method(),
        &PairingMessageMethod::Missing
    );
}

#[test]
fn rejects_wrong_symmetric_key() {
    let sym_key = test_key();
    let wrong_key =
        PairingSymKey::from_hex("1653ca620c7b4990392e1c53c4a51c14a2840cd20f0f1524cf435b17b6fe988c")
            .expect("wrong key is valid");
    let encoded = encrypted_message(
        &json!({"id": 5, "jsonrpc": "2.0", "method": "wc_pairingPing", "params": {}}),
        &sym_key,
    );

    assert!(matches!(
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&encoded), &wrong_key),
        Err(PairingMessageError::Envelope { .. })
    ));
}

#[test]
fn rejects_plaintext_type_two_on_encrypted_pairing_topic() {
    let sym_key = test_key();
    let plaintext = serde_json::to_string(&json!({
        "id": 6,
        "jsonrpc": "2.0",
        "method": "wc_pairingPing",
        "params": {}
    }))
    .expect("serializes fixture");
    let mut envelope_bytes = Vec::with_capacity(plaintext.len() + 1);
    envelope_bytes.push(2);
    envelope_bytes.extend_from_slice(plaintext.as_bytes());
    let encoded = STANDARD.encode(envelope_bytes);

    assert!(matches!(
        PairingMessage::decode_relay_message(EncryptedRelayEnvelope::new(&encoded), &sym_key),
        Err(PairingMessageError::UnexpectedPlaintextEnvelope { .. })
    ));
}
