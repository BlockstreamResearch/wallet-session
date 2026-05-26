//! Session authentication DTOs.

use serde::{Deserialize, Serialize};

use super::SessionParticipant;

/// Decrypted `wc_sessionAuthenticate` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionauthenticate>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionauthenticate>
///
/// > // wc_sessionAuthenticate payload params
/// > {
/// > "requester": Participant;
/// > "authPayload": PayloadParams;
/// > "expiryTimestamp": number;
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L161-L165>
///
/// > interface SessionAuthenticateRequestParams {
/// > requester: Participant;
/// > authPayload: PayloadParams;
/// > expiryTimestamp: number;
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1026-L1042>
///
/// > const request: AuthTypes.SessionAuthenticateRequestParams = {
/// > authPayload: {
/// > type: type ?? "caip122",
/// > chains,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionAuthenticateParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionAuthenticate",
///   "params": {
///     "requester": {
///       "publicKey": "351b54461d6075e0bcc0084f3f901cb7cdf4b16135e8ffa46a3a7193c6125b2e",
///       "metadata": {
///         "name": "Dapp",
///         "description": "Dapp",
///         "url": "https://example.com",
///         "icons": []
///       }
///     },
///     "authPayload": {
///       "type": "caip122",
///       "chains": ["eip155:1"],
///       "aud": "https://example.com/login",
///       "domain": "example.com",
///       "version": "1",
///       "nonce": "1234567890",
///       "iat": "2026-05-26T17:16:14.225Z"
///     },
///     "expiryTimestamp": 1779819374
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionAuthenticateParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionAuthenticate);
/// assert_eq!(request.params.auth_payload.domain, "example.com");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuthenticateParams {
    /// Authentication requester public key and metadata.
    pub requester: SessionParticipant,
    /// CAIP-122/CACAO payload requested for signing.
    #[serde(rename = "authPayload")]
    pub auth_payload: AuthPayload,
    /// Request expiry timestamp in unix seconds.
    #[serde(rename = "expiryTimestamp")]
    pub expiry_timestamp: u64,
}

impl SessionAuthenticateParams {
    /// Compares `expiryTimestamp` to a caller-provided unix timestamp.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp <= now_unix_seconds
    }
}

/// CAIP-122 payload carried inside `wc_sessionAuthenticate`.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > Header uniquely identifies the payload format:
/// > ...
/// > The header type will be `caip122` in reference to the [CAIP-122]
/// > specification for the SIWx data model.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > The payload structure must be presented as follows:
/// > ...
/// > domain String // =domain
/// > iss String // = DID pkh
/// > aud String // =uri
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L104-L107>
///
/// > type PayloadParams = {
/// > version: string;
/// > iat: string;
/// > } & RequestParams;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPayload {
    /// Payload type, normally `caip122`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Requested CAIP-2 chains.
    pub chains: Vec<String>,
    /// URI identifying the authentication audience.
    pub aud: String,
    /// Domain requesting authentication.
    pub domain: String,
    /// Payload version.
    pub version: String,
    /// Randomized token used by the dapp.
    pub nonce: String,
    /// Issued-at timestamp.
    pub iat: String,
    /// Human-readable statement to sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Expiration timestamp in RFC 3339 format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    /// Not-before timestamp in RFC 3339 format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    /// System-specific request identifier.
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Resource URIs, including Recap URNs when methods are requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
}
