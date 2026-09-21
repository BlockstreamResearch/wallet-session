use serde::{Deserialize, Serialize};

/// JWT token for authentication.
#[derive(Serialize, Deserialize)]
pub struct RelayAuthToken {
    // did:key derived from the identity public key
    pub iss: String,

    // random session identifier
    pub sub: String,

    // relay URL
    pub aud: String,

    // issued-at timestamp
    pub iat: u64,

    // expiry
    pub exp: u64,
}
