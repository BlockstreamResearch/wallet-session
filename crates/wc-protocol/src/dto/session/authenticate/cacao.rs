//! CACAO DTOs and message helpers.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::AuthPayload;
use crate::{caip::Caip2ChainId, did::DidPkh};

const RECAP_PREFIX: &str = "urn:recap:";
const RECAP_STATEMENT_PREFIX: &str =
    "I further authorize the stated URI to perform the following actions on my behalf: ";

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

    /// Converts a wire value into a known type or a lossless fallback.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "caip122" => Self::Caip122,
            "eip4361" => Self::Eip4361,
            _ => Self::Other(value),
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
        Ok(Self::from_wire(value))
    }
}

impl fmt::Display for CacaoHeaderType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-74.md#specification>
///
/// > type Payload struct {
/// > domain String // =domain
/// > iss String // = DID pkh
/// > aud String // =uri
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-74.md#specification>
///
/// > issuer here is [did:pkh](https://github.com/w3c-ccg/did-pkh/blob/main/did-pkh-method-draft.md), which includes both blockchain address and blockchain network information.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L121-L128>
///
/// > if (!iss.includes("did:pkh:")) {
/// > iss = `did:pkh:${iss}`;
/// > }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacaoPayload {
    /// DID PKH issuer containing the account namespace, reference, and address.
    pub iss: DidPkh,
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

impl CacaoPayload {
    /// Builds a CACAO payload from an auth request and a DID PKH issuer.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L121-L149>
    ///
    /// > if (!iss.includes("did:pkh:")) {
    /// > iss = `did:pkh:${iss}`;
    /// > }
    /// > p: {
    /// > iss,
    /// > domain: requestPayload.domain,
    ///
    /// The issuer chain must be one of the requested `authPayload.chains`; the
    /// JS helper accepts strings and validates the signature later, while this
    /// typed builder can reject a mismatched issuer before a response is sent.
    pub fn from_auth_payload(
        auth_payload: &AuthPayload,
        issuer: &DidPkh,
    ) -> Result<Self, CacaoBuildError> {
        let issuer_chain = issuer.chain_id();
        if !auth_payload
            .chains
            .iter()
            .any(|chain| chain == &issuer_chain)
        {
            return Err(CacaoBuildError::IssuerChainNotRequested { issuer_chain });
        }

        Ok(Self::copy_from_auth_payload(auth_payload, issuer))
    }

    /// Formats the SIWE-like message represented by this CACAO payload.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L69-L119>
    ///
    /// > const uri = `URI: ${cacao.aud || cacao.uri}`;
    /// > const chainId = `Chain ID: ${getDidChainId(iss)}`;
    /// > const resources = cacao.resources
    /// > ? `Resources:${cacao.resources.map((resource) => `\n- ${resource}`).join("")}`
    ///
    /// Empty `resources` are treated as absent because the Rust DTO normalizes
    /// missing and empty arrays to the same `Vec`.
    pub fn format_message(&self) -> Result<String, CacaoMessageError> {
        let mut statement = self.statement.as_deref().filter(|value| !value.is_empty());
        let owned_statement;

        if let Some(recap) = recap_from_resources(&self.resources) {
            owned_statement = format_statement_from_recap(statement.unwrap_or_default(), recap)
                .map_err(|source| CacaoMessageError::InvalidRecapResource { source })?;
            statement = Some(&owned_statement);
        }

        let mut lines = vec![
            format!(
                "{} wants you to sign in with your {} account:",
                self.domain,
                namespace_display_name(self.iss.account_id().namespace())
            ),
            self.iss.address().to_owned(),
            String::new(),
        ];

        if let Some(statement) = statement {
            lines.push(statement.to_owned());
        }

        lines.extend([
            String::new(),
            format!("URI: {}", self.aud),
            format!("Version: {}", self.version),
            format!("Chain ID: {}", self.iss.account_id().reference()),
            format!("Nonce: {}", self.nonce),
            format!("Issued At: {}", self.iat),
        ]);

        if let Some(exp) = &self.exp {
            lines.push(format!("Expiration Time: {exp}"));
        }
        if let Some(nbf) = &self.nbf {
            lines.push(format!("Not Before: {nbf}"));
        }
        if let Some(request_id) = &self.request_id {
            lines.push(format!("Request ID: {request_id}"));
        }
        if !self.resources.is_empty() {
            lines.push(format!(
                "Resources:{}",
                format_resource_lines(&self.resources)
            ));
        }

        Ok(lines.join("\n"))
    }

    pub(super) fn copy_from_auth_payload(auth_payload: &AuthPayload, issuer: &DidPkh) -> Self {
        Self {
            iss: issuer.clone(),
            domain: auth_payload.domain.clone(),
            aud: auth_payload.aud.clone(),
            version: auth_payload.version.clone(),
            nonce: auth_payload.nonce.clone(),
            iat: auth_payload.iat.clone(),
            statement: auth_payload.statement.clone(),
            exp: auth_payload.exp.clone(),
            nbf: auth_payload.nbf.clone(),
            request_id: auth_payload.request_id.clone(),
            resources: auth_payload.resources.clone(),
        }
    }
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

    /// Converts a wire value into a known type or a lossless fallback.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "eip191" => Self::Eip191,
            "eip1271" => Self::Eip1271,
            _ => Self::Other(value),
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
        Ok(Self::from_wire(value))
    }
}

/// CACAO signature bytes as represented by the `WalletConnect` Sign wire format.
///
/// CAIP-74 models the field as bytes.
///
/// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-74.md#specification>
///
/// > type Signature struct {
/// > t String
/// > m optional SignatureMeta
/// > s Bytes
///
/// `WalletConnect`'s current public type carries those bytes as a string.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L117-L120>
///
/// > interface CacaoSignature {
/// > t: "eip191" | "eip1271";
/// > s: string;
///
/// The maintained helper passes the signature object through unchanged, so this
/// type preserves the wire string instead of assuming a single hex convention.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/cacao.ts#L121-L149>
///
/// > s: signature,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::CacaoSignatureValue;
///
/// let live = CacaoSignatureValue::from_wire("0x5851cc642b66ba30");
/// assert_eq!(live.as_str(), "0x5851cc642b66ba30");
///
/// let caip_example = CacaoSignatureValue::from_wire("5ccb134ad3d874c");
/// assert_eq!(caip_example.to_string(), "5ccb134ad3d874c");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CacaoSignatureValue(String);

impl CacaoSignatureValue {
    /// Stores the SDK wire signature string without normalization.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the preserved wire signature.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the preserved wire signature.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CacaoSignatureValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
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
    pub signature: CacaoSignatureValue,
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

impl Cacao {
    /// Reconstructs the message that should be verified against `s`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L53-L67>
    ///
    /// > const reconstructed = formatMessage(payload, payload.iss);
    /// > const walletAddress = getDidAddress(payload.iss) as string;
    pub fn format_message(&self) -> Result<String, CacaoMessageError> {
        self.p.format_message()
    }

    /// Checks that a CACAO mirrors the auth payload it answers.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L121-L149>
    ///
    /// > domain: requestPayload.domain,
    /// > aud: requestPayload.aud,
    /// > version: requestPayload.version,
    /// > nonce: requestPayload.nonce,
    ///
    /// Cryptographic signature verification is separate; this is the structural
    /// check before handing the message to a chain-specific verifier.
    pub fn validate_against_auth_payload(
        &self,
        auth_payload: &AuthPayload,
    ) -> Result<(), CacaoValidationError> {
        if self.h.kind != CacaoHeaderType::Caip122 {
            return Err(CacaoValidationError::UnexpectedHeader {
                actual: self.h.kind.clone(),
            });
        }

        let issuer_chain = self.p.iss.chain_id();
        if !auth_payload
            .chains
            .iter()
            .any(|chain| chain == &issuer_chain)
        {
            return Err(CacaoValidationError::IssuerChainNotRequested { issuer_chain });
        }

        if self.p.domain != auth_payload.domain {
            return Err(CacaoValidationError::DomainMismatch);
        }
        if self.p.aud != auth_payload.aud {
            return Err(CacaoValidationError::AudienceMismatch);
        }
        if self.p.version != auth_payload.version {
            return Err(CacaoValidationError::VersionMismatch);
        }
        if self.p.nonce != auth_payload.nonce {
            return Err(CacaoValidationError::NonceMismatch);
        }
        if self.p.iat != auth_payload.iat {
            return Err(CacaoValidationError::IssuedAtMismatch);
        }
        if self.p.statement != auth_payload.statement {
            return Err(CacaoValidationError::StatementMismatch);
        }
        if self.p.exp != auth_payload.exp {
            return Err(CacaoValidationError::ExpirationMismatch);
        }
        if self.p.nbf != auth_payload.nbf {
            return Err(CacaoValidationError::NotBeforeMismatch);
        }
        if self.p.request_id != auth_payload.request_id {
            return Err(CacaoValidationError::RequestIdMismatch);
        }
        if self.p.resources != auth_payload.resources {
            return Err(CacaoValidationError::ResourcesMismatch);
        }

        Ok(())
    }
}

/// CACAO construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacaoBuildError {
    /// The DID PKH issuer chain is not in `authPayload.chains`.
    #[error("CACAO issuer chain was not requested: {issuer_chain}")]
    IssuerChainNotRequested {
        /// Chain from the DID PKH issuer.
        issuer_chain: Caip2ChainId,
    },
}

/// CACAO message formatting error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacaoMessageError {
    /// The last resource looked like a Recap URN but could not be decoded.
    #[error("CACAO Recap resource is invalid")]
    InvalidRecapResource {
        /// Recap parse failure.
        #[source]
        source: RecapParseError,
    },
}

/// CACAO structural validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CacaoValidationError {
    /// CACAO header is not the current `caip122` header emitted by the SDK.
    #[error("unexpected CACAO header type: {actual}")]
    UnexpectedHeader {
        /// Wire header value.
        actual: CacaoHeaderType,
    },

    /// The DID PKH issuer chain is not in `authPayload.chains`.
    #[error("CACAO issuer chain was not requested: {issuer_chain}")]
    IssuerChainNotRequested {
        /// Chain from the DID PKH issuer.
        issuer_chain: Caip2ChainId,
    },

    /// CACAO `domain` differs from `authPayload.domain`.
    #[error("CACAO domain does not match auth payload")]
    DomainMismatch,

    /// CACAO `aud` differs from `authPayload.aud`.
    #[error("CACAO audience does not match auth payload")]
    AudienceMismatch,

    /// CACAO `version` differs from `authPayload.version`.
    #[error("CACAO version does not match auth payload")]
    VersionMismatch,

    /// CACAO `nonce` differs from `authPayload.nonce`.
    #[error("CACAO nonce does not match auth payload")]
    NonceMismatch,

    /// CACAO `iat` differs from `authPayload.iat`.
    #[error("CACAO issued-at timestamp does not match auth payload")]
    IssuedAtMismatch,

    /// CACAO `statement` differs from `authPayload.statement`.
    #[error("CACAO statement does not match auth payload")]
    StatementMismatch,

    /// CACAO `exp` differs from `authPayload.exp`.
    #[error("CACAO expiration timestamp does not match auth payload")]
    ExpirationMismatch,

    /// CACAO `nbf` differs from `authPayload.nbf`.
    #[error("CACAO not-before timestamp does not match auth payload")]
    NotBeforeMismatch,

    /// CACAO `requestId` differs from `authPayload.requestId`.
    #[error("CACAO request id does not match auth payload")]
    RequestIdMismatch,

    /// CACAO `resources` differ from `authPayload.resources`.
    #[error("CACAO resources do not match auth payload")]
    ResourcesMismatch,
}

/// Recap parse error used while reconstructing CACAO auth messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecapParseError {
    /// Recap base64 payload could not be decoded.
    #[error("Recap base64 payload is invalid")]
    InvalidBase64 {
        /// Base64 decode failure.
        #[source]
        source: base64::DecodeError,
    },

    /// Decoded Recap bytes were not valid JSON.
    #[error("Recap JSON payload is invalid")]
    InvalidJson {
        /// JSON decode failure.
        #[source]
        source: RecapJsonError,
    },

    /// Recap JSON is missing the `att` object.
    #[error("Recap missing att object")]
    MissingAtt,

    /// Recap `att` object has no resources.
    #[error("Recap att object is empty")]
    EmptyAtt,

    /// Recap resource entry is not an object.
    #[error("Recap resource entry is not an object")]
    ResourceNotObject,

    /// Recap resource object has no abilities.
    #[error("Recap resource object is empty")]
    ResourceEmpty,

    /// Recap ability limits are not an array.
    #[error("Recap ability limits are not an array")]
    AbilityLimitsNotArray,

    /// Recap ability limits array is empty.
    #[error("Recap ability limits array is empty")]
    AbilityLimitsEmpty,

    /// Recap ability limit is not an object.
    #[error("Recap ability limit is not an object")]
    AbilityLimitNotObject,
}

/// Decoded Recap authorization data.
///
/// `WalletConnect` carries `Recap` grants in the final `resources` entry as a
/// `urn:recap:` value. The JSON shape is validated before this wrapper is
/// constructed: `att` must be a non-empty object whose resource entries contain
/// non-empty ability arrays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recap {
    att: Map<String, Value>,
}

impl Recap {
    /// Recap `att` resource map.
    #[must_use]
    pub const fn att(&self) -> &Map<String, Value> {
        &self.att
    }

    /// Moves the decoded Recap resource map into caller-owned state.
    #[must_use]
    pub fn into_att(self) -> Map<String, Value> {
        self.att
    }
}

/// Cloneable source error for Recap JSON decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecapJsonError {
    message: String,
}

impl RecapJsonError {
    fn new(source: &serde_json::Error) -> Self {
        Self {
            message: source.to_string(),
        }
    }
}

impl fmt::Display for RecapJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for RecapJsonError {}

fn namespace_display_name(namespace: &str) -> &str {
    // WalletConnect's formatter uses a small hard-coded display map so the
    // signed text says "Ethereum account" instead of the CAIP namespace
    // `eip155`.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L4-L15
    match namespace {
        "eip155" => "Ethereum",
        "solana" => "Solana",
        "bip122" => "Bitcoin",
        _ => namespace,
    }
}

fn format_resource_lines(resources: &[String]) -> String {
    use std::fmt::Write as _;

    // The maintained helper appends every resource as a newline-prefixed bullet
    // inside one `Resources:` line.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L90-L92
    let mut output = String::new();
    for resource in resources {
        write!(output, "\n- {resource}").expect("writing to String cannot fail");
    }
    output
}

/// Returns the final resource when it is a `WalletConnect` Recap URN.
///
/// The maintained JavaScript helper treats only the last `resources` entry as a
/// Recap candidate.
#[must_use]
pub fn recap_from_resources(resources: &[String]) -> Option<&str> {
    // WalletConnect treats the last resource as Recap when it contains the
    // `urn:recap:` marker.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L433-L438
    resources
        .last()
        .and_then(|resource| resource.contains(RECAP_PREFIX).then_some(resource.as_str()))
}

fn format_statement_from_recap(statement: &str, recap: &str) -> Result<String, RecapParseError> {
    // Recap permissions are rendered into the statement before signing. This
    // mirrors `formatStatementFromRecap` so the signed bytes match the JS SDK.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L363-L400
    let recap = decode_recap_att(recap)?;
    if statement.contains(RECAP_STATEMENT_PREFIX) {
        return Ok(statement.to_owned());
    }

    let mut current_counter = 0;
    let mut sections = Vec::new();
    for (resource, abilities) in recap {
        let abilities = abilities
            .as_object()
            .expect("validate_recap returns object resource entries");
        let mut actions = Vec::with_capacity(abilities.len());
        for ability in abilities.keys() {
            let (ability, action) = ability
                .split_once('/')
                .map_or((ability.as_str(), "undefined"), |(ability, action)| {
                    (ability, action)
                });
            actions.push((ability.to_owned(), action.to_owned()));
        }
        actions.sort_by(|left, right| left.1.cmp(&right.1));

        let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
        for (ability, action) in actions {
            if let Some((_, values)) = grouped
                .iter_mut()
                .find(|(existing_ability, _)| existing_ability == &ability)
            {
                values.push(action);
            } else {
                grouped.push((ability, vec![action]));
            }
        }

        let abilities = grouped
            .into_iter()
            .map(|(ability, actions)| {
                current_counter += 1;
                format!(
                    "({current_counter}) '{ability}': '{}' for '{resource}'.",
                    actions.join("', '")
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
            .replace(".,", ".");
        sections.push(abilities);
    }

    let recap_statement = format!("{RECAP_STATEMENT_PREFIX}{}", sections.join(" "));
    if statement.is_empty() {
        Ok(recap_statement)
    } else {
        Ok(format!("{statement} {recap_statement}"))
    }
}

/// Decodes and validates a `urn:recap:` resource.
pub fn decode_recap(recap: &str) -> Result<Recap, RecapParseError> {
    decode_recap_att(recap).map(|att| Recap { att })
}

fn decode_recap_att(recap: &str) -> Result<Map<String, Value>, RecapParseError> {
    // `encodeRecap` removes standard-base64 padding; the JS decoder restores it
    // before `atob`.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L313-L323
    let encoded = recap.replacen(RECAP_PREFIX, "", 1);
    let padded = padded_base64(&encoded);
    let bytes = STANDARD
        .decode(padded)
        .map_err(|source| RecapParseError::InvalidBase64 { source })?;
    let value =
        serde_json::from_slice::<Value>(&bytes).map_err(|source| RecapParseError::InvalidJson {
            source: RecapJsonError::new(&source),
        })?;
    validate_recap(&value)
}

fn padded_base64(value: &str) -> String {
    // `btoa` output is standard base64. Recap removes `=` padding, so decode
    // restores the minimal padding required by base64's 4-byte grouping.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L237-L244
    let mut padded = value.to_owned();
    padded.extend(std::iter::repeat_n('=', (4 - (value.len() % 4)) % 4));
    padded
}

fn validate_recap(value: &Value) -> Result<Map<String, Value>, RecapParseError> {
    // The JS validator only needs enough structure to format abilities:
    // `att` -> resource object -> ability object -> non-empty array of objects.
    //
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/e1491f9e54a6417c9b9742ac0d6fa6d710e81561/packages/utils/src/cacao.ts#L247-L275
    let mut object = value
        .as_object()
        .cloned()
        .ok_or(RecapParseError::MissingAtt)?;
    let att = object
        .remove("att")
        .and_then(|value| value.as_object().cloned())
        .ok_or(RecapParseError::MissingAtt)?;
    if att.is_empty() {
        return Err(RecapParseError::EmptyAtt);
    }

    for resource_abilities in att.values() {
        let abilities = resource_abilities
            .as_object()
            .ok_or(RecapParseError::ResourceNotObject)?;
        if abilities.is_empty() {
            return Err(RecapParseError::ResourceEmpty);
        }

        for limits in abilities.values() {
            let limits = limits
                .as_array()
                .ok_or(RecapParseError::AbilityLimitsNotArray)?;
            if limits.is_empty() {
                return Err(RecapParseError::AbilityLimitsEmpty);
            }
            if limits.iter().any(|limit| !limit.is_object()) {
                return Err(RecapParseError::AbilityLimitNotObject);
            }
        }
    }

    Ok(att)
}
