//! Verify policy tests.

use serde_json::json;
use wc_core::{VerifyContextRisk, classify_verify_context};
use wc_protocol::verify::VerifyContext;

#[test]
fn classifies_verify_context_policy_matrix() -> Result<(), Box<dyn std::error::Error>> {
    for (value, risk, requires_review, reject_by_default) in [
        (
            verify_context_json("VALID", None),
            VerifyContextRisk::Valid,
            false,
            false,
        ),
        (
            verify_context_json("UNKNOWN", None),
            VerifyContextRisk::Unknown,
            true,
            false,
        ),
        (
            verify_context_json("INVALID", None),
            VerifyContextRisk::Invalid,
            true,
            true,
        ),
        (
            verify_context_json("VALID", Some(true)),
            VerifyContextRisk::Scam,
            true,
            true,
        ),
        (
            verify_context_json("FUTURE", None),
            VerifyContextRisk::Unknown,
            true,
            false,
        ),
    ] {
        let context = serde_json::from_value::<VerifyContext>(value)?;
        let actual = classify_verify_context(&context);

        assert_eq!(actual, risk);
        assert_eq!(actual.requires_explicit_user_review(), requires_review);
        assert_eq!(actual.should_reject_by_default(), reject_by_default);
    }

    Ok(())
}

fn verify_context_json(validation: &str, is_scam: Option<bool>) -> serde_json::Value {
    let mut verified = json!({
        "origin": "https://example.com",
        "validation": validation,
        "verifyUrl": "https://verify.walletconnect.org"
    });

    if let Some(is_scam) = is_scam {
        verified["isScam"] = json!(is_scam);
    }

    json!({ "verified": verified })
}
