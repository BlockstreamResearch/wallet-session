//! Verify DTO tests.

use serde_json::json;
use wc_protocol::{
    session::DappMetadata,
    verify::{DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext, VerifyValidation},
};

const LIVE_VERIFY_CONTEXT_UNKNOWN_JSON: &str = r#"{
  "verified": {
    "verifyUrl": "https://verify.walletconnect.org",
    "validation": "UNKNOWN",
    "origin": "https://example.com"
  }
}"#;

#[test]
fn deserializes_live_unknown_verify_context_shape() -> Result<(), Box<dyn std::error::Error>> {
    let context = serde_json::from_str::<VerifyContext>(LIVE_VERIFY_CONTEXT_UNKNOWN_JSON)?;

    assert_eq!(context.verified.origin, "https://example.com");
    assert_eq!(
        context.verified.verify_url,
        "https://verify.walletconnect.org"
    );
    assert_eq!(context.verified.validation, VerifyValidation::Unknown);
    assert_eq!(context.verified.is_scam, None);

    Ok(())
}

#[test]
fn serializes_verify_context_wire_names() {
    let context = VerifyContext::unknown("https://example.com", "https://verify.walletconnect.org");
    let value = serde_json::to_value(context).expect("serializes");

    assert_eq!(value["verified"]["origin"], "https://example.com");
    assert_eq!(value["verified"]["validation"], "UNKNOWN");
    assert_eq!(
        value["verified"]["verifyUrl"],
        "https://verify.walletconnect.org"
    );
    assert!(value["verified"].get("isScam").is_none());
}

#[test]
fn preserves_verify_validation_values() {
    for (wire, parsed) in [
        ("UNKNOWN", VerifyValidation::Unknown),
        ("VALID", VerifyValidation::Valid),
        ("INVALID", VerifyValidation::Invalid),
        ("FUTURE", VerifyValidation::Other("FUTURE".to_owned())),
    ] {
        let value = json!({
            "verified": {
                "origin": "https://example.com",
                "validation": wire,
                "verifyUrl": "https://verify.walletconnect.org"
            }
        });

        let context = serde_json::from_value::<VerifyContext>(value).expect("parses");
        assert_eq!(context.verified.validation, parsed);
        assert_eq!(context.verified.validation.as_str(), wire);
    }
}

#[test]
fn preserves_scam_signal_when_present() {
    let value = json!({
        "verified": {
            "origin": "https://example.com",
            "validation": "VALID",
            "verifyUrl": "https://verify.walletconnect.org",
            "isScam": true
        }
    });

    let context = serde_json::from_value::<VerifyContext>(value).expect("parses");

    assert!(context.verified.is_scam());
}

#[test]
fn unresolved_context_uses_metadata_origin_and_default_verify_url() {
    let metadata = DappMetadata {
        name: "Example".to_owned(),
        description: "Example dapp".to_owned(),
        url: "https://example.com".to_owned(),
        icons: vec![],
        verify_url: None,
        redirect: None,
    };

    let context = VerifyContext::unresolved_from_metadata(&metadata);

    assert_eq!(context.verified.origin, "https://example.com");
    assert_eq!(context.verified.verify_url, DEFAULT_VERIFY_URL);
    assert_eq!(context.verified.validation, VerifyValidation::Unknown);
}

#[test]
fn unresolved_context_preserves_metadata_verify_url_override() {
    let metadata = DappMetadata {
        name: "Example".to_owned(),
        description: "Example dapp".to_owned(),
        url: "https://example.com".to_owned(),
        icons: vec![],
        verify_url: Some("https://verify.example.com".to_owned()),
        redirect: None,
    };

    let context = VerifyContext::unresolved_from_metadata(&metadata);

    assert_eq!(context.verified.origin, "https://example.com");
    assert_eq!(context.verified.verify_url, "https://verify.example.com");
    assert_eq!(context.verified.validation, VerifyValidation::Unknown);
}

#[test]
fn verify_attestation_hash_matches_walletconnect_hash_message() {
    let hash = VerifyAttestationHash::from_message("some");

    assert_eq!(
        hash.as_str(),
        "a6b46dd0d1ae5e86cbc8f37e75ceeb6760230c1ca4ffbcb0c97b96dd7d9c464b"
    );
}

#[test]
fn verify_attestation_hash_rejects_non_lowercase_sha256_hex() {
    assert!(VerifyAttestationHash::parse("abc").is_err());
    assert!(
        VerifyAttestationHash::parse(
            "A6B46DD0D1AE5E86CBC8F37E75CEEB6760230C1CA4FFBCB0C97B96DD7D9C464B",
        )
        .is_err()
    );
    assert!(
        VerifyAttestationHash::parse(
            "zzb46dd0d1ae5e86cbc8f37e75ceeb6760230c1ca4ffbcb0c97b96dd7d9c464b",
        )
        .is_err()
    );
}
