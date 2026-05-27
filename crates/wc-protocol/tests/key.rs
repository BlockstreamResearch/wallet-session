//! Integration tests for key primitives.

use serde_json::json;
use wc_protocol::key::{
    X25519_PUBLIC_KEY_BYTES, X25519KeyPair, X25519PrivateKey, X25519PrivateKeyError,
    X25519PublicKey, X25519PublicKeyError, derive_shared_sym_key, derive_topic_from_sym_key,
};

const LIVE_JS_GENERATED_PUBLIC_KEY: &str =
    "051a42272e83b5c59357b55aa04e60a02e70da9caccea1916b62c40b95ed5d50";
const LIVE_JS_A_PRIVATE_KEY: &str =
    "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce";
const LIVE_JS_A_PUBLIC_KEY: &str =
    "5c26bac1fda7c2bf9835b15b2452cf4d4313098ee491465f4904d05225b2d026";
const LIVE_JS_B_PRIVATE_KEY: &str =
    "ffba1f1cec7c9841ad0edf9c8dc0bde4bcbb429204bc63abcd67066f35ee5714";
const LIVE_JS_B_PUBLIC_KEY: &str =
    "80dd64bd6e4c3612ff0f5ccbe9282f1f11ba56ada6a2f9740da063d1ed1f2b20";
const LIVE_JS_SHARED_SYM_KEY: &str =
    "81b30968ad471e842d9936c567429a0ce7c04787ed8d103143cdba785be7ba1a";
const LIVE_JS_DERIVED_TOPIC: &str =
    "e2b00edc48dfe17b2bb8f9eabe52ba1ada4f2a3a651c6b01cb873f74cecfec82";

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

#[test]
fn derives_live_walletconnect_js_shared_key_and_topic() {
    let a_private = X25519PrivateKey::from_hex(LIVE_JS_A_PRIVATE_KEY).expect("private key parses");
    let a_public = X25519PublicKey::from_hex(LIVE_JS_A_PUBLIC_KEY).expect("public key parses");
    let b_private = X25519PrivateKey::from_hex(LIVE_JS_B_PRIVATE_KEY).expect("private key parses");
    let b_public = X25519PublicKey::from_hex(LIVE_JS_B_PUBLIC_KEY).expect("public key parses");

    assert_eq!(a_private.public_key(), a_public);
    assert_eq!(b_private.public_key(), b_public);

    let ab = derive_shared_sym_key(&a_private, &b_public);
    let ba = derive_shared_sym_key(&b_private, &a_public);

    assert_eq!(ab.as_str(), LIVE_JS_SHARED_SYM_KEY);
    assert_eq!(ba, ab);
    assert_eq!(
        derive_topic_from_sym_key(&ab).as_str(),
        LIVE_JS_DERIVED_TOPIC
    );
}

#[test]
fn generated_key_pair_has_walletconnect_shape() {
    let key_pair = X25519KeyPair::generate().expect("generates key pair");

    assert_eq!(key_pair.private_key().as_str().len(), 64);
    assert_eq!(key_pair.public_key().as_str().len(), 64);
    assert_eq!(
        key_pair.private_key().public_key(),
        key_pair.public_key().clone()
    );
}

#[test]
fn private_key_rejects_non_lowercase_hex() {
    assert_eq!(
        X25519PrivateKey::from_hex("00").expect_err("key is too short"),
        X25519PrivateKeyError::InvalidLength { actual: 2 }
    );
    assert_eq!(
        X25519PrivateKey::from_hex(format!("{}A", "0".repeat(63)))
            .expect_err("uppercase is rejected"),
        X25519PrivateKeyError::InvalidHexCharacter {
            index: 63,
            character: 'A',
        }
    );
}
