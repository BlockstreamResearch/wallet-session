//! Integration tests for key primitives.

use serde_json::json;
use wc_protocol::key::{X25519_PUBLIC_KEY_BYTES, X25519PublicKey, X25519PublicKeyError};

const LIVE_JS_GENERATED_PUBLIC_KEY: &str =
    "051a42272e83b5c59357b55aa04e60a02e70da9caccea1916b62c40b95ed5d50";

#[test]
fn parses_live_walletconnect_js_generated_key_shape() {
    let key = X25519PublicKey::from_hex(LIVE_JS_GENERATED_PUBLIC_KEY)
        .expect("live JS generated key parses");

    assert_eq!(key.as_str(), LIVE_JS_GENERATED_PUBLIC_KEY);
    assert_eq!(key.to_bytes().len(), X25519_PUBLIC_KEY_BYTES);
    assert_eq!(
        serde_json::to_value(&key).expect("serializes"),
        json!(LIVE_JS_GENERATED_PUBLIC_KEY)
    );
    assert_eq!(
        serde_json::from_value::<X25519PublicKey>(json!(LIVE_JS_GENERATED_PUBLIC_KEY))
            .expect("deserializes"),
        key
    );
}

#[test]
fn rejects_uppercase_key_like_walletconnect_js_derivation() {
    let uppercase = LIVE_JS_GENERATED_PUBLIC_KEY.to_ascii_uppercase();

    assert_eq!(
        X25519PublicKey::from_hex(uppercase).expect_err("uppercase is rejected"),
        X25519PublicKeyError::InvalidHexCharacter {
            index: 3,
            character: 'A',
        }
    );
}
