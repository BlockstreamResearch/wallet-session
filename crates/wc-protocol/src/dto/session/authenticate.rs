//! Session authentication DTOs.

mod cacao;

use serde::{Deserialize, Serialize};

use super::SessionParticipant;
use crate::{caip::Caip2ChainId, did::DidPkh};

pub use cacao::{
    Cacao, CacaoBuildError, CacaoHeader, CacaoHeaderType, CacaoMessageError, CacaoPayload,
    CacaoSignature, CacaoSignatureType, CacaoSignatureValue, CacaoValidationError, Recap,
    RecapParseError, decode_recap, recap_from_resources,
};

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
/// assert_eq!(request.params.auth_payload.kind.as_str(), "caip122");
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
    /// Payload format requested for the authentication message.
    ///
    /// Current Sign clients default this field to `caip122`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1026-L1039>
    ///
    /// > authPayload: {
    /// > type: type ?? "caip122",
    ///
    /// The public TypeScript API still accepts a string, so unknown values are
    /// preserved.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L77-L91>
    ///
    /// > interface BaseAuthRequestParams {
    /// > type?: string;
    #[serde(rename = "type")]
    pub kind: CacaoHeaderType,
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

impl AuthPayload {
    /// Builds the `WalletConnect` auth message that a wallet signs for this payload.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L69-L119>
    ///
    /// > export const formatMessage = (cacao: AuthTypes.FormatMessageParams, iss: string) => {
    /// > const header = `${cacao.domain} wants you to sign in with your ${getNamespaceNameFromNamespace(didNamespace)} account:`;
    /// > const message = [
    ///
    /// `WalletConnect`'s helper derives the displayed address and chain reference
    /// from `iss`, not from `authPayload.chains`.
    ///
    /// # Examples
    ///
    /// ```
    /// use wc_protocol::{did::DidPkh, session::{AuthPayload, CacaoHeaderType}};
    ///
    /// let payload = AuthPayload {
    ///     kind: CacaoHeaderType::Caip122,
    ///     chains: vec!["eip155:1".parse()?],
    ///     aud: "https://example.com/login".to_owned(),
    ///     domain: "example.com".to_owned(),
    ///     version: "1".to_owned(),
    ///     nonce: "1234567890".to_owned(),
    ///     iat: "2026-05-29T10:42:19.478Z".to_owned(),
    ///     statement: Some("Sign in to Example".to_owned()),
    ///     exp: None,
    ///     nbf: None,
    ///     request_id: None,
    ///     resources: Vec::new(),
    /// };
    /// let issuer = DidPkh::parse(
    ///     "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
    /// )?;
    ///
    /// let message = payload.format_message(&issuer)?;
    /// assert!(message.starts_with("example.com wants you to sign in with your Ethereum account:"));
    /// assert!(message.contains("Chain ID: 1"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn format_message(&self, issuer: &DidPkh) -> Result<String, CacaoMessageError> {
        CacaoPayload::copy_from_auth_payload(self, issuer).format_message()
    }

    /// Copies the auth request fields into the CACAO payload shape.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L121-L149>
    ///
    /// > const authObject: AuthTypes.Cacao = {
    /// > h: {
    /// > t: "caip122",
    /// > },
    /// > p: {
    /// > iss,
    /// > domain: requestPayload.domain,
    ///
    /// The request's `chains` list is authorization input; it is not copied
    /// into `CacaoPayload`.
    pub fn to_cacao_payload(&self, issuer: &DidPkh) -> Result<CacaoPayload, CacaoBuildError> {
        CacaoPayload::from_auth_payload(self, issuer)
    }

    /// Builds a signed CACAO object from caller-provided signature bytes.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L121-L149>
    ///
    /// > s: signature,
    ///
    /// Signing remains outside this crate. This helper only builds the object
    /// that wraps an already-produced signature.
    pub fn to_cacao(
        &self,
        issuer: &DidPkh,
        signature: CacaoSignature,
    ) -> Result<Cacao, CacaoBuildError> {
        Ok(Cacao {
            h: CacaoHeader {
                kind: CacaoHeaderType::Caip122,
            },
            p: self.to_cacao_payload(issuer)?,
            s: signature,
        })
    }
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
