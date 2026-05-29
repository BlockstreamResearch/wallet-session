//! Verify DTO tests.

use serde_json::json;
use wc_protocol::verify::{VerifyContext, VerifyValidation};

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
