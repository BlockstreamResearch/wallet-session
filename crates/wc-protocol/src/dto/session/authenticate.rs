//! Session authentication DTOs.

use serde::{Deserialize, Serialize};

use super::SessionParticipant;
use crate::caip::Caip2ChainId;

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
    pub chains: Vec<Caip2ChainId>,
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

/// CACAO header type value.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > The header type will be `caip122` in reference to the [CAIP-122]
/// > specification for the SIWx data model.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L113-L115>
///
/// > interface CacaoHeader {
/// > t: "caip122";
/// > }
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacaoHeaderType {
    /// Current CAIP-74 header value used by `WalletConnect` Sign authentication.
    Caip122,
    /// Older CAIP-74 header value used by SIWE-only implementations.
    Eip4361,
    /// Unrecognized header value preserved for compatibility.
    Other(String),
}

impl CacaoHeaderType {
    /// Wire value stored in the CACAO header `t` field.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Caip122 => "caip122",
            Self::Eip4361 => "eip4361",
            Self::Other(value) => value,
        }
    }
}

impl Serialize for CacaoHeaderType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CacaoHeaderType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "caip122" => Self::Caip122,
            "eip4361" => Self::Eip4361,
            _ => Self::Other(value),
        })
    }
}

/// CACAO header.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > Header uniquely identifies the payload format:
/// >
/// > type Header struct {
/// > t String // specifies format of the payload
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/cacao.ts#L130-L133>
///
/// > const authObject: AuthTypes.Cacao = {
/// > h: {
/// > t: "caip122",
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoHeader {
    /// Payload format identifier serialized as `t`.
    #[serde(rename = "t")]
    pub kind: CacaoHeaderType,
}

/// CACAO payload.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > type Payload struct {
/// > domain String // =domain
/// > iss String // = DID pkh
/// > aud String // =uri
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/cacao.ts#L134-L146>
///
/// > p: {
/// > iss,
/// > domain: requestPayload.domain,
/// > aud: requestPayload.aud,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoPayload {
    /// DID PKH issuer containing the account namespace, reference, and address.
    pub iss: String,
    /// Domain requesting authentication.
    pub domain: String,
    /// URI identifying the authentication audience.
    pub aud: String,
    /// Payload version.
    pub version: String,
    /// Randomized token used by the dapp.
    pub nonce: String,
    /// Issued-at timestamp.
    pub iat: String,
    /// Human-readable statement signed by the account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// Expiration timestamp in RFC 3339 format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    /// Not-before timestamp in RFC 3339 format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<String>,
    /// System-specific request identifier serialized as `requestId`.
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Resource URIs signed into the authentication payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
}

/// CACAO signature type value.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#signature-verification>
///
/// > Signature verification goes according to `t` in `SignatureMeta`:
/// > For example,
/// >
/// > - `eip191`: use [EIP-191](https://eips.ethereum.org/EIPS/eip-191),
/// > - `eip1271`: use [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271).
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L117-L120>
///
/// > interface CacaoSignature {
/// > t: "eip191" | "eip1271";
/// > s: string;
/// > m?: string;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CacaoSignatureType {
    /// EIP-191 message signature.
    Eip191,
    /// EIP-1271 contract signature.
    Eip1271,
    /// Unrecognized signature type preserved for compatibility.
    Other(String),
}

impl CacaoSignatureType {
    /// Wire value stored in the CACAO signature `t` field.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Eip191 => "eip191",
            Self::Eip1271 => "eip1271",
            Self::Other(value) => value,
        }
    }
}

impl Serialize for CacaoSignatureType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CacaoSignatureType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "eip191" => Self::Eip191,
            "eip1271" => Self::Eip1271,
            _ => Self::Other(value),
        })
    }
}

/// CACAO signature.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-74.md#specification>
///
/// > type Signature struct {
/// > t String
/// > m optional SignatureMeta
/// > s Bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoSignature {
    /// Signature verification type serialized as `t`.
    #[serde(rename = "t")]
    pub kind: CacaoSignatureType,
    /// Signature bytes encoded as the SDK wire string `s`.
    #[serde(rename = "s")]
    pub signature: String,
    /// Optional signature metadata serialized as `m`.
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<String>,
}

/// Chain-agnostic account authentication object.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionauthenticate>
///
/// > // Success result (array of signed CACAOs)
/// > [{
/// > "h": CacaoHeader,
/// > "p": CacaoPayload,
/// > "s": CacaoSignature
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L123-L127>
///
/// > interface Cacao {
/// > h: CacaoHeader;
/// > p: CacaoPayload;
/// > s: CacaoSignature;
/// > }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cacao {
    /// CACAO header serialized as `h`.
    pub h: CacaoHeader,
    /// CACAO payload serialized as `p`.
    pub p: CacaoPayload,
    /// CACAO signature serialized as `s`.
    pub s: CacaoSignature,
}

/// Current SDK JSON-RPC result for approved `wc_sessionAuthenticate`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L144-L147>
///
/// > interface SessionAuthenticateResponseParams {
/// > responder: Participant;
/// > cacaos: Cacao[];
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1405-L1415>
///
/// > await this.sendResult<"wc_sessionAuthenticate">({
/// > topic: responseTopic,
/// > id,
/// > result: {
/// > cacaos: auths,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAuthenticateResult {
    /// Wallet public key and metadata that signed the CACAO response.
    pub responder: SessionParticipant,
    /// Signed CACAOs returned by the wallet.
    pub cacaos: Vec<Cacao>,
}
