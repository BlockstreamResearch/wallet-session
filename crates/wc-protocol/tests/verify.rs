//! Verify DTO tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use wc_protocol::{
    session::DappMetadata,
    verify::{
        DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext, VerifyJwtAttestationError,
        VerifyJwtAttestationJws, VerifyJwtPublicKeyResponse, VerifyValidation,
    },
};

const LIVE_VERIFY_CONTEXT_UNKNOWN_JSON: &str = r#"{
  "verified": {
    "verifyUrl": "https://verify.walletconnect.org",
    "validation": "UNKNOWN",
    "origin": "https://example.com"
  }
}"#;

const VERIFY_JWT_PUBLIC_KEY_JSON: &str = r#"{
  "publicKey": {
    "crv": "P-256",
    "ext": true,
    "key_ops": ["verify"],
    "kty": "EC",
    "x": "CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk",
    "y": "KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0"
  },
  "expiresAt": 1782655613
}"#;

const FIXTURE_ENCRYPTED_ID: &str = "encrypted-id-fixture";
const FIXTURE_VERIFIED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.Nn_tdflpG4kmaUhiQvqeWsWA7weNimHGYgfv58t5r01TWQCgRtQJlFEbj_qzQQf81eqsGyVdAyHIF3rFEl9oXA";
const FIXTURE_SCAM_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V2aWwuZXhhbXBsZSIsImlzU2NhbSI6dHJ1ZSwiaXNWZXJpZmllZCI6dHJ1ZX0.utvR0dCAV5SHJ1CQlnEU5rxZ2VyCJcZ1wpDr4OiDV0U8I_-EOTy-VUi8bMs_bphI5tjNBYSLGOdA4oGK7Unqyw";
const FIXTURE_UNVERIFIED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6ZmFsc2V9.g8Yxh5anoCXhJeM1xoIKAtGmJZ_rRdbZIh_fZJEqinOOPEkpMv2KMx3dj9G6Y2Ni47Q_i3WASnlyhhq7BsSCRQ";
const FIXTURE_EXPIRED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.fhwRjn-F6zAUUNQYmsddR0z6Z_RysXKP3atkCctychBcXEBCIqLtmwilJ8fe4Q9eZuPQ_bk2VZnqW6Gnf1AJ7A";

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

#[test]
fn parses_live_verify_v3_public_key_shape() -> Result<(), Box<dyn std::error::Error>> {
    let response = serde_json::from_str::<VerifyJwtPublicKeyResponse>(VERIFY_JWT_PUBLIC_KEY_JSON)?;

    assert_eq!(
        response.public_key.x,
        "CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk"
    );
    assert_eq!(response.expires_at, 1_782_655_613);
    let sec1 = response.public_key.sec1_bytes()?;
    assert_eq!(sec1.len(), 65);
    assert_eq!(sec1[0], 0x04);

    Ok(())
}

#[test]
fn decodes_verify_jwt_attestation_matches_walletconnect_js_fixture()
-> Result<(), Box<dyn std::error::Error>> {
    let jws = VerifyJwtAttestationJws::decode(FIXTURE_VERIFIED_JWT)?;
    let payload = jws.payload();

    assert_eq!(payload.exp, 4_102_444_800);
    assert_eq!(payload.id, FIXTURE_ENCRYPTED_ID);
    assert_eq!(payload.origin, "https://example.com");
    assert!(!payload.is_scam);
    assert!(payload.is_verified);
    assert_eq!(jws.signature().len(), 64);
    assert!(jws.signing_input().contains(&b'.'));

    Ok(())
}

#[test]
fn decodes_verify_jwt_attestation_preserves_scam_signal() -> Result<(), Box<dyn std::error::Error>>
{
    let jws = VerifyJwtAttestationJws::decode(FIXTURE_SCAM_JWT)?;
    let payload = jws.payload();

    assert_eq!(payload.origin, "https://evil.example");
    assert!(payload.is_scam);
    assert!(payload.is_verified);

    Ok(())
}

#[test]
fn decodes_verify_jwt_attestation_preserves_unverified_signal()
-> Result<(), Box<dyn std::error::Error>> {
    let jws = VerifyJwtAttestationJws::decode(FIXTURE_UNVERIFIED_JWT)?;
    let payload = jws.payload();

    assert_eq!(payload.origin, "https://example.com");
    assert!(!payload.is_scam);
    assert!(!payload.is_verified);

    Ok(())
}

#[test]
fn decoded_verify_jwt_attestation_reports_expired_payload() -> Result<(), Box<dyn std::error::Error>>
{
    let jws = VerifyJwtAttestationJws::decode(FIXTURE_EXPIRED_JWT)?;

    assert!(jws.payload().is_expired_at(1_700_000_000));
    assert!(!jws.payload().is_expired_at(0));

    Ok(())
}

#[test]
fn verify_jwt_attestation_rejects_unsupported_alg() {
    let token = token_with_header(FIXTURE_VERIFIED_JWT, r#"{"alg":"none","typ":"JWT"}"#);
    let error = VerifyJwtAttestationJws::decode(&token)
        .expect_err("unsupported algorithm should be rejected");

    assert!(matches!(
        error,
        VerifyJwtAttestationError::UnsupportedAlgorithm { alg } if alg == "none"
    ));
}

fn token_with_header(token: &str, header: &str) -> String {
    let mut parts = token.split('.');
    let _old_header = parts.next().expect("fixture has header");
    let payload = parts.next().expect("fixture has payload");
    let signature = parts.next().expect("fixture has signature");
    format!(
        "{}.{payload}.{signature}",
        URL_SAFE_NO_PAD.encode(header.as_bytes())
    )
}
