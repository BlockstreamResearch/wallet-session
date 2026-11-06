use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use wallet_session_core::{auth::RelayAuthToken, codec, did::DidKey};

use crate::{error::Result, random};

/// Long-term identity seed, persisted across reconnects and restarts.
#[derive(Clone)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random seed.
    pub fn random() -> Result<Self> {
        Ok(Self(random::bytes()?))
    }

    /// Borrow the raw seed bytes for persistence.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Ed25519 identity used to sign connection tokens.
#[derive(Clone)]
pub struct IdentityKey(SigningKey);

impl IdentityKey {
    /// Derive the identity key from a persisted seed.
    pub fn from_seed(seed: &Seed) -> Self {
        Self(SigningKey::from_bytes(seed.as_bytes()))
    }

    /// Generate a fresh identity key from a random seed.
    pub fn random() -> Result<Self> {
        Ok(Self::from_seed(&Seed::random()?))
    }

    /// `did:key` identifier derived from the identity public key.
    pub fn did(&self) -> DidKey {
        DidKey::from_ed25519_bytes(self.0.verifying_key().to_bytes())
    }

    /// Sign a connection token for the given relay session and audience.
    pub fn connection_token(
        &self,
        session_id: &str,
        audience: &str,
        ttl: Duration,
    ) -> Result<String> {
        let now = unix_now();
        let token = RelayAuthToken {
            iss: self.did(),
            sub: session_id.to_owned(),
            aud: audience.to_owned(),
            iat: now,
            exp: now.saturating_add(ttl.as_secs()),
        };

        let header = codec::encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = codec::encode(&serde_json::to_vec(&token)?);
        let signing_input = format!("{header}.{payload}");
        let signature = self.0.sign(signing_input.as_bytes());
        let signature = codec::encode(&signature.to_bytes());

        Ok(format!("{signing_input}.{signature}"))
    }
}

/// Current Unix time in seconds, saturating at 0 before the epoch.
pub fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_is_stable_for_a_seed() {
        let seed = Seed::from_bytes([7u8; 32]);
        let first = IdentityKey::from_seed(&seed).did();
        let second = IdentityKey::from_seed(&seed).did();
        assert_eq!(first, second);
        assert!(first.to_string().starts_with("did:key:z"));
    }

    #[test]
    fn connection_token_has_three_segments() {
        let identity = IdentityKey::from_seed(&Seed::from_bytes([1u8; 32]));
        let token = identity
            .connection_token("session", "wss://relay", Duration::from_secs(60))
            .expect("token");
        assert_eq!(token.split('.').count(), 3);
    }
}
