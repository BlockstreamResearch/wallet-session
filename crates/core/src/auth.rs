use serde::{Deserialize, Serialize};

use crate::did::DidKey;

/// JWT token for authentication.
#[derive(Serialize, Deserialize)]
pub struct RelayAuthToken {
    // did:key derived from the identity public key
    pub iss: DidKey,

    // random session identifier
    pub sub: String,

    // relay URL
    pub aud: String,

    // issued-at timestamp
    pub iat: u64,

    // expiry
    pub exp: u64,
}
