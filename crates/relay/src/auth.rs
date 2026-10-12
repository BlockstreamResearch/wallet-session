use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;
use wallet_session_core::{auth::RelayAuthToken, codec, did::DidKey};

/// JWT `alg` accepted for the identity signature
const JWT_ALGORITHM: &str = "EdDSA";

/// Tolerance applied to `iat`/`exp` checks, in seconds
const TOKEN_LEEWAY_SECS: u64 = 60;

/// Maximum accepted length of the auth token string.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Default maximum accepted lifetime of an auth token.
pub const DEFAULT_MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Identity established by a verified connection token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `did:key` derived from the identity public key.
    pub did: DidKey,

    /// Session identifier.
    pub session: String,
}

/// Failures decoding or verifying a connection token.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("auth token is malformed")]
    MalformedToken,

    #[error("auth token is not valid base64url: {0}")]
    Decode(#[from] wallet_session_core::error::Error),

    #[error("auth token is not valid JSON: {0}")]
    Token(#[from] serde_json::Error),

    #[error("unsupported JWT algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid did:key: {0}")]
    DidKey(String),

    #[error("invalid token signature")]
    Signature(#[from] ed25519_dalek::ed25519::signature::Error),

    #[error("token audience mismatch")]
    Audience,

    #[error("token has expired")]
    Expired,

    #[error("token lifetime exceeds the allowed maximum")]
    ExpiryTooLong,

    #[error("token is not yet valid")]
    NotYetValid,

    #[error("auth token exceeds the maximum length")]
    TooLong,
}

/// Current Unix time in seconds, saturating at 0 before the epoch.
pub fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

impl Identity {
    /// Verify a signed JWT and build the peer identity.
    pub fn verify_token(auth: &str, audience: &str, now: u64) -> Result<Self, IdentityError> {
        Self::verify_token_with_lifetime(auth, audience, now, DEFAULT_MAX_TOKEN_LIFETIME)
    }

    /// Verify a signed JWT, rejecting tokens whose lifetime exceeds `max_lifetime`.
    pub fn verify_token_with_lifetime(
        auth: &str,
        audience: &str,
        now: u64,
        max_lifetime: Duration,
    ) -> Result<Self, IdentityError> {
        if auth.len() > MAX_TOKEN_BYTES {
            return Err(IdentityError::TooLong);
        }

        let mut segments = auth.split('.');
        let header_b64 = segments.next().ok_or(IdentityError::MalformedToken)?;
        let payload_b64 = segments.next().ok_or(IdentityError::MalformedToken)?;
        let signature_b64 = segments.next().ok_or(IdentityError::MalformedToken)?;
        if segments.next().is_some() {
            return Err(IdentityError::MalformedToken);
        }

        let header: JwtHeader = serde_json::from_slice(&codec::decode(header_b64)?)?;
        if header.alg != JWT_ALGORITHM {
            return Err(IdentityError::UnsupportedAlgorithm(header.alg));
        }

        let token: RelayAuthToken = serde_json::from_slice(&codec::decode(payload_b64)?)?;
        let key = VerifyingKey::from_bytes(&token.iss.to_ed25519_bytes())
            .map_err(|error| IdentityError::DidKey(error.to_string()))?;

        let signature = Signature::from_slice(&codec::decode(signature_b64)?)?;
        let signing_input = format!("{header_b64}.{payload_b64}");

        key.verify_strict(signing_input.as_bytes(), &signature)?;

        if token.aud != audience {
            return Err(IdentityError::Audience);
        }
        if token.exp <= now {
            return Err(IdentityError::Expired);
        }
        if token.exp.saturating_sub(now) > max_lifetime.as_secs() {
            return Err(IdentityError::ExpiryTooLong);
        }
        if token.iat > now.saturating_add(TOKEN_LEEWAY_SECS) {
            return Err(IdentityError::NotYetValid);
        }

        Ok(Self {
            did: token.iss,
            session: token.sub,
        })
    }
}

#[derive(serde::Deserialize)]
struct JwtHeader {
    alg: String,
}

#[cfg(test)]
pub(crate) mod test_utils {
    use ed25519_dalek::{Signer, SigningKey};
    use wallet_session_core::{codec, did::DidKey};

    pub(crate) fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn did_key(signing_key: &SigningKey) -> DidKey {
        DidKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes())
    }

    /// Build a validly signed token with the given audience and timestamps.
    pub(crate) fn token(signing_key: &SigningKey, aud: &str, iat: u64, exp: u64) -> String {
        token_with_alg(signing_key, "EdDSA", aud, iat, exp)
    }

    /// Build a signed token with a custom `alg` header.
    pub(crate) fn token_with_alg(
        signing_key: &SigningKey,
        alg: &str,
        aud: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        let iss = did_key(signing_key);
        build_token(signing_key, alg, &iss.to_string(), aud, iat, exp)
    }

    pub(crate) fn token_with_iss(
        signing_key: &SigningKey,
        iss: &DidKey,
        aud: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        build_token(signing_key, "EdDSA", &iss.to_string(), aud, iat, exp)
    }

    pub(crate) fn raw_token_with_iss(
        signing_key: &SigningKey,
        iss: &str,
        aud: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        build_token(signing_key, "EdDSA", iss, aud, iat, exp)
    }

    fn build_token(
        signing_key: &SigningKey,
        alg: &str,
        iss: &str,
        aud: &str,
        iat: u64,
        exp: u64,
    ) -> String {
        let header = codec::encode(format!(r#"{{"alg":"{alg}","typ":"JWT"}}"#).as_bytes());
        let payload = codec::encode(
            format!(r#"{{"iss":"{iss}","sub":"session","aud":"{aud}","iat":{iat},"exp":{exp}}}"#)
                .as_bytes(),
        );
        let signing_input = format!("{header}.{payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature = codec::encode(&signature.to_bytes());
        format!("{signing_input}.{signature}")
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::{self, signing_key};
    use super::*;

    const AUDIENCE: &str = "wss://relay.example.com";
    const NOW: u64 = 1_700_000_000;

    fn valid_token() -> String {
        test_utils::token(&signing_key(1), AUDIENCE, NOW, NOW + 3600)
    }

    #[test]
    fn verifies_valid_token() {
        let key = signing_key(1);
        let identity = Identity::verify_token(&valid_token(), AUDIENCE, NOW).ok();
        assert_eq!(
            identity,
            Some(Identity {
                did: test_utils::did_key(&key),
                session: "session".to_owned(),
            })
        );
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = test_utils::token(&signing_key(1), "wss://other", NOW, NOW + 3600);
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::Audience)
        ));
    }

    #[test]
    fn rejects_expired_token() {
        let token = test_utils::token(&signing_key(1), AUDIENCE, NOW - 7200, NOW - 3600);
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::Expired)
        ));
    }

    #[test]
    fn rejects_token_from_the_future() {
        let token = test_utils::token(
            &signing_key(1),
            AUDIENCE,
            NOW + TOKEN_LEEWAY_SECS + 1,
            NOW + 3600,
        );
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::NotYetValid)
        ));
    }

    #[test]
    fn tolerates_small_clock_skew() {
        let token = test_utils::token(
            &signing_key(1),
            AUDIENCE,
            NOW + TOKEN_LEEWAY_SECS - 1,
            NOW + 3600,
        );
        assert!(Identity::verify_token(&token, AUDIENCE, NOW).is_ok());
    }

    #[test]
    fn rejects_tampered_signature() {
        let token = valid_token();
        let mut segments: Vec<&str> = token.split('.').collect();
        segments[2] = "AAAA";
        let tampered = segments.join(".");
        assert!(matches!(
            Identity::verify_token(&tampered, AUDIENCE, NOW),
            Err(IdentityError::Signature(..))
        ));
    }

    #[test]
    fn rejects_unsupported_algorithm() {
        let token = test_utils::token_with_alg(&signing_key(1), "none", AUDIENCE, NOW, NOW + 3600);
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::UnsupportedAlgorithm(alg)) if alg == "none"
        ));
    }

    #[test]
    fn rejects_non_did_key_issuer() {
        let token = test_utils::raw_token_with_iss(
            &signing_key(1),
            "did:web:example.com",
            AUDIENCE,
            NOW,
            NOW + 3600,
        );
        // The malformed issuer fails while deserializing the payload.
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::Token(_))
        ));
    }

    #[test]
    fn rejects_wrong_key_did() {
        let token = test_utils::token_with_iss(
            &signing_key(1),
            &test_utils::did_key(&signing_key(2)),
            AUDIENCE,
            NOW,
            NOW + 3600,
        );
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::Signature(..))
        ));
    }

    #[test]
    fn rejects_token_lifetime_over_cap() {
        let token = test_utils::token(&signing_key(1), AUDIENCE, NOW, NOW + 7 * 24 * 3600);
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::ExpiryTooLong)
        ));
    }

    #[test]
    fn accepts_token_within_lifetime_cap() {
        let token = test_utils::token(&signing_key(1), AUDIENCE, NOW, NOW + 23 * 3600);
        assert!(Identity::verify_token(&token, AUDIENCE, NOW).is_ok());
    }

    #[test]
    fn rejects_oversized_token() {
        let token = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert!(matches!(
            Identity::verify_token(&token, AUDIENCE, NOW),
            Err(IdentityError::TooLong)
        ));
    }

    #[test]
    fn rejects_malformed_token() {
        assert!(matches!(
            Identity::verify_token("no-dots", AUDIENCE, NOW),
            Err(IdentityError::MalformedToken)
        ));
    }
}
