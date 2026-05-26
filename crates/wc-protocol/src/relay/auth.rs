//! Relay Auth JWT and WebSocket connection URL primitives.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;

use crate::encoding::{base64url_bytes, base64url_json, query_escape};

/// Default `WalletConnect` relay WebSocket endpoint.
pub const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.com/";

const MULTICODEC_ED25519_HEADER: [u8; 2] = [0xed, 0x01];

/// Relay Auth JWT carried in the WebSocket `auth` query parameter.
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::RelayAuthToken;
///
/// let token = RelayAuthToken::sign_with_seed(
///     &[7; 32],
///     "client-subject",
///     "wss://relay.walletconnect.com",
///     1_700_000_000,
///     60,
/// )?;
///
/// assert_eq!(token.as_str().split('.').count(), 3);
/// # Ok::<(), wc_protocol::relay::RelayAuthError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RelayAuthToken(String);

impl RelayAuthToken {
    /// Derives an Ed25519 signing key from `seed`, then signs a Relay Auth JWT.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/core/src/controllers/crypto.ts#L81-L88>
    ///
    /// > const keyPair = relayAuth.generateKeyPair(seed);
    pub fn sign_with_seed(
        seed: &[u8; 32],
        subject: &str,
        audience: &str,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, RelayAuthError> {
        let signing_key = SigningKey::from_bytes(seed);
        Self::sign_with_signing_key(&signing_key, subject, audience, issued_at, ttl_seconds)
    }

    /// Signs the Relay Auth JWT with an Ed25519 signing key.
    ///
    /// `audience` should be the relay endpoint without query parameters and
    /// without a trailing slash, for example `wss://relay.walletconnect.com`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#specification>
    ///
    /// > Additionally we describe how we can construct and sign a JWT using a client-side generated unique id as subject
    ///
    /// The same spec also lists:
    ///
    /// > `act` - description of action intent. Must be equal to "client_auth"
    ///
    /// The maintained JavaScript implementation omits `act`; this follows that
    /// payload for deployed-client compatibility.
    ///
    /// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-auth/src/api.ts#L23-L36>
    ///
    /// > const payload = { iss, sub, aud, iat, exp };
    pub fn sign_with_signing_key(
        signing_key: &SigningKey,
        subject: &str,
        audience: &str,
        issued_at: u64,
        ttl_seconds: u64,
    ) -> Result<Self, RelayAuthError> {
        let expires_at = issued_at
            .checked_add(ttl_seconds)
            .ok_or(RelayAuthError::ExpirationOverflow)?;
        let public_key = signing_key.verifying_key().to_bytes();

        let header = JwtHeader {
            alg: "EdDSA",
            typ: "JWT",
        };
        let claims = RelayAuthClaims {
            iss: ed25519_did_key(&public_key),
            sub: subject,
            aud: audience,
            iat: issued_at,
            exp: expires_at,
        };
        let encoded_header = base64url_json(&header)?;
        let encoded_claims = base64url_json(&claims)?;
        let data = format!("{encoded_header}.{encoded_claims}");
        let signature = signing_key.sign(data.as_bytes());

        Ok(Self(format!(
            "{data}.{}",
            base64url_bytes(signature.to_bytes())
        )))
    }

    /// Compact JWT form used as the relay `auth` query parameter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the compact JWT into caller-owned URL or storage state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RelayAuthToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Relay auth token signing error.
#[derive(Debug, thiserror::Error)]
pub enum RelayAuthError {
    /// `issued_at + ttl_seconds` cannot be represented in the JWT `exp` claim.
    #[error("relay auth expiration overflow")]
    ExpirationOverflow,

    /// Header or claim JSON could not be encoded before signing.
    #[error("relay auth json serialization failed")]
    Json {
        /// Serialization failure from the JWT header or claims segment.
        #[from]
        source: serde_json::Error,
    },
}

/// Encodes an Ed25519 public key as a `did:key` identifier.
///
/// <https://w3c-ccg.github.io/did-key-spec/#did-key-identifier-syntax>
///
/// > The format for the `did:key` method conforms to the DID specification and is simple.
/// > It consists of the `did:key` prefix, followed by a Multibase base58-btc or base64-url
/// > encoded value that is a concatenation of the Multikey identifier for the public key
/// > type and the raw bytes associated with the public key format.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-auth/src/utils.ts#L33-L37>
///
/// > return [DID_PREFIX, DID_METHOD, multicodec].join(DID_DELIMITER);
///
/// # Examples
///
/// ```
/// use ed25519_dalek::SigningKey;
/// use wc_protocol::relay::ed25519_did_key;
///
/// let mut seed = [0_u8; 32];
/// for (index, byte) in seed.iter_mut().enumerate() {
///     *byte = u8::try_from(index)?;
/// }
///
/// let signing_key = SigningKey::from_bytes(&seed);
/// let public_key = signing_key.verifying_key().to_bytes();
///
/// assert_eq!(
///     ed25519_did_key(&public_key),
///     "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
/// );
/// # Ok::<(), std::num::TryFromIntError>(())
/// ```
#[must_use]
pub fn ed25519_did_key(public_key: &[u8; 32]) -> String {
    let mut multicodec = Vec::with_capacity(MULTICODEC_ED25519_HEADER.len() + public_key.len());
    multicodec.extend_from_slice(&MULTICODEC_ED25519_HEADER);
    multicodec.extend_from_slice(public_key);

    format!("did:key:z{}", bs58::encode(multicodec).into_string())
}

/// A relay WebSocket URL containing auth, project ID, and user agent params.
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::RelayConnectionUrl;
///
/// let url = RelayConnectionUrl::new(
///     "wss://relay.walletconnect.com",
///     "project",
///     "header.claims.signature",
///     "wc-2/rust-poc-0.1.0/macos/native",
/// );
///
/// let expected = concat!(
///     "wss://relay.walletconnect.com/",
///     "?auth=header.claims.signature",
///     "&projectId=project",
///     "&ua=wc-2%2Frust-poc-0.1.0%2Fmacos%2Fnative",
/// );
/// assert_eq!(
///     url.as_str(),
///     expected,
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayConnectionUrl(String);

impl RelayConnectionUrl {
    /// Builds a relay connection URL.
    ///
    /// If the base URL has no path, this normalizes it to `/` before adding
    /// query parameters because the live relay accepts
    /// `wss://relay.walletconnect.com/?...`.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
    ///
    /// > Where websocket headers are not supported i.e. browsers, use the URL query param `?auth=<signed jwt>`.
    ///
    /// <https://docs.walletconnect.network/wallet-sdk/web/cloud/relay#project-id>
    ///
    /// > The Project ID is consumed through URL parameters.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/misc.ts#L206-L226>
    ///
    /// > auth,
    /// > ua,
    /// > projectId,
    #[must_use]
    pub fn new(relay_url: &str, project_id: &str, auth: &str, user_agent: &str) -> Self {
        let relay_url = relay_url_with_path(relay_url);
        let separator = if relay_url.contains('?') { '&' } else { '?' };
        Self(format!(
            "{relay_url}{separator}auth={}&projectId={}&ua={}",
            query_escape(auth),
            query_escape(project_id),
            query_escape(user_agent)
        ))
    }

    /// Full WebSocket URL passed to a relay transport.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Moves the URL into caller-owned transport state.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for RelayConnectionUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Relay endpoint value placed in the Relay Auth JWT `aud` claim.
///
/// Query parameters and one trailing slash are removed before signing.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#specification>
///
/// > aud - relay server URL
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::relay_auth_audience;
///
/// assert_eq!(
///     relay_auth_audience("wss://relay.walletconnect.com/?projectId=abc"),
///     "wss://relay.walletconnect.com"
/// );
/// ```
#[must_use]
pub fn relay_auth_audience(relay_url: &str) -> &str {
    relay_url
        .split('?')
        .next()
        .unwrap_or(relay_url)
        .trim_end_matches('/')
}

#[derive(Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct RelayAuthClaims<'a> {
    iss: String,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

/// Adds an explicit `/` path before an existing query on authority-only URLs.
///
/// `RelayConnectionUrl::new` appends query pairs with string formatting. This
/// keeps `wss://relay.walletconnect.com?x=1` in the canonical
/// `wss://relay.walletconnect.com/?x=1` shape before adding relay params.
fn relay_url_with_path(relay_url: &str) -> String {
    let Some(scheme_end) = relay_url.find("://") else {
        return relay_url.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = relay_url[authority_start..]
        .find(['/', '?'])
        .map_or(relay_url.len(), |index| authority_start + index);

    if relay_url[authority_end..].starts_with('/') {
        relay_url.to_owned()
    } else {
        let (base, query) = relay_url.split_at(authority_end);
        format!("{base}/{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_jwt_matches_walletconnect_relay_auth_claims_vector() {
        let mut seed = [0_u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("test seed index fits in u8");
        }

        let jwt = RelayAuthToken::sign_with_seed(
            &seed,
            "sub",
            "wss://relay.walletconnect.com",
            1_700_000_000,
            60,
        )
        .expect("jwt is generated");

        assert_eq!(
            jwt.as_str(),
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.\
             eyJpc3MiOiJkaWQ6a2V5Ono2TWtlaFJnZjd5SmJnYUdmWXNkb0FzS2RCUEUzZGoyQ1lob3dRZGNqcVNKZ3ZWZCIsInN1YiI6InN1YiIsImF1ZCI6IndzczovL3JlbGF5LndhbGxldGNvbm5lY3QuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDAwNjB9.\
             x2lbadyJJB5GiaCXCp5VY-kKjBPak4oblHd-BhfZjRtuknFDQ8PXGlKWXbweONjWwzlbKZKk2s25-7Q1Dy_xCg"
        );
    }

    #[test]
    fn relay_url_inserts_missing_path_before_query() {
        let url = RelayConnectionUrl::new(
            "wss://relay.walletconnect.com?existing=true",
            "project",
            "jwt",
            "ua",
        );

        assert_eq!(
            url.as_str(),
            "wss://relay.walletconnect.com/?existing=true&auth=jwt&projectId=project&ua=ua"
        );
    }

    #[test]
    fn relay_url_percent_encodes_user_agent() {
        let url = RelayConnectionUrl::new(
            DEFAULT_RELAY_URL,
            "project",
            "jwt",
            "wc-2/rust-poc-0.1.0/macos/native",
        );

        assert!(
            url.as_str()
                .contains("ua=wc-2%2Frust-poc-0.1.0%2Fmacos%2Fnative")
        );
    }
}
