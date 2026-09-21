use thiserror::Error;
use wallet_session_core::{auth::RelayAuthToken, codec};

/// Identity established by a verified connection token (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `did:key` derived from the identity public key.
    pub did: String,

    /// Session identifier.
    pub session: String,
}

/// Failures decoding a connection token.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("auth token is missing its payload segment")]
    MalformedToken,

    #[error("auth token payload is not valid base64url: {0}")]
    Decode(#[from] wallet_session_core::error::Error),

    #[error("auth token payload is not a relay auth token: {0}")]
    Token(#[from] serde_json::Error),
}

impl Identity {
    /// Build an identity from the `auth` query parameter.
    ///
    /// TODO: verify the Ed25519 signature, `aud`, and `exp`.
    pub fn from_auth_token(auth: &str) -> Result<Self, IdentityError> {
        let payload = auth
            .split('.')
            .nth(1)
            .ok_or(IdentityError::MalformedToken)?;
        let bytes = codec::decode(payload)?;
        let token: RelayAuthToken = serde_json::from_slice(&bytes)?;

        Ok(Self {
            did: token.iss,
            session: token.sub,
        })
    }
}
