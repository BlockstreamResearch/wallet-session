use serde::{Deserialize, Serialize};

/// JWT token for authentication.
#[derive(Serialize, Deserialize)]
struct RelayAuthToken {
    // did:key derived from the identity public key
    iss: String,

    // random session identifier
    sub: String,

    // relay URL
    aud: String,

    // issued-at timestamp
    iat: u64,

    // expiry
    exp: u64,
}
