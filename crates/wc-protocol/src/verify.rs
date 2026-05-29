//! Verify API DTOs.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::session::DappMetadata;

/// Default Verify endpoint used when dapp metadata has no `verifyUrl`.
///
/// The maintained Sign Client seeds `Verify.Context` with
/// `metadata.verifyUrl || VERIFY_SERVER` before calling the Verify resolver.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3289-L3295>
///
/// > verifyUrl: metadata.verifyUrl || VERIFY_SERVER,
///
/// A live `@walletconnect/sign-client` `session_proposal` probe observed this
/// concrete URL when no metadata override was supplied.
pub const DEFAULT_VERIFY_URL: &str = "https://verify.walletconnect.org";

/// Verify v3 endpoint used for JWT attestation public keys.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L171-L178>
///
/// > const url = `${VERIFY_SERVER_V3}/public-key`;
/// > const response = await fetch(url);
pub const DEFAULT_VERIFY_V3_URL: &str = "https://verify.walletconnect.org/v3";

/// Alternate trusted Verify endpoint accepted by the maintained SDK.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/constants/verify.ts#L3-L8>
///
/// ```text
/// const VERIFY_SERVER_COM = "https://verify.walletconnect.com";
/// const VERIFY_SERVER_ORG = "https://verify.walletconnect.org";
/// export const TRUSTED_VERIFY_URLS = [VERIFY_SERVER_COM, VERIFY_SERVER_ORG];
/// ```
pub const ALTERNATE_VERIFY_URL: &str = "https://verify.walletconnect.com";

/// `WalletConnect` Verify context attached to approval-sensitive events.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/verify.ts#L5-L13>
///
/// > export declare namespace Verify {
/// > export interface Context {
/// > verified: {
/// > origin: string;
/// > validation: "UNKNOWN" | "VALID" | "INVALID";
///
/// `session_proposal`, `session_request`, and `session_authenticate` events
/// carry this object in the maintained Sign Client.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/client.ts#L33-L61>
///
/// > session_proposal: {
/// > verifyContext: Verify.Context;
/// > } & Omit<BaseEventArgs<ProposalTypes.Struct>, "topic">;
///
/// # Examples
///
/// ```
/// use wc_protocol::verify::{VerifyContext, VerifyValidation};
///
/// let json = r#"{
///   "verified": {
///     "verifyUrl": "https://verify.walletconnect.org",
///     "validation": "UNKNOWN",
///     "origin": "https://example.com"
///   }
/// }"#;
///
/// let context = serde_json::from_str::<VerifyContext>(json)?;
/// assert_eq!(context.verified.origin, "https://example.com");
/// assert_eq!(context.verified.validation, VerifyValidation::Unknown);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyContext {
    /// Verified origin data returned by or derived from the Verify API.
    pub verified: VerifiedOrigin,
}

impl VerifyContext {
    /// Builds the default unresolved context used by the maintained Sign Client.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3289-L3295>
    ///
    /// > const context: Verify.Context = {
    /// > verified: {
    /// > verifyUrl: metadata.verifyUrl || VERIFY_SERVER,
    /// > validation: "UNKNOWN",
    /// > origin: metadata.url || "",
    #[must_use]
    pub fn unknown(origin: impl Into<String>, verify_url: impl Into<String>) -> Self {
        Self {
            verified: VerifiedOrigin {
                origin: origin.into(),
                validation: VerifyValidation::Unknown,
                verify_url: verify_url.into(),
                is_scam: None,
            },
        }
    }

    /// Builds the unresolved Verify context from peer metadata.
    ///
    /// This mirrors the SDK state before `core.verify.resolve(...)` completes:
    /// origin comes from `metadata.url`, the Verify endpoint comes from
    /// `metadata.verifyUrl` or the default Verify server, and validation remains
    /// `UNKNOWN`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3289-L3309>
    ///
    /// > validation: "UNKNOWN",
    /// > origin: metadata.url || "",
    /// > verifyUrl: metadata.verifyUrl,
    ///
    /// # Examples
    ///
    /// ```
    /// use wc_protocol::{
    ///     session::DappMetadata,
    ///     verify::{DEFAULT_VERIFY_URL, VerifyContext, VerifyValidation},
    /// };
    ///
    /// let metadata = DappMetadata {
    ///     name: "Example".to_owned(),
    ///     description: "Example dapp".to_owned(),
    ///     url: "https://example.com".to_owned(),
    ///     icons: vec![],
    ///     verify_url: None,
    ///     redirect: None,
    /// };
    /// let context = VerifyContext::unresolved_from_metadata(&metadata);
    ///
    /// assert_eq!(context.verified.origin, "https://example.com");
    /// assert_eq!(context.verified.verify_url, DEFAULT_VERIFY_URL);
    /// assert_eq!(context.verified.validation, VerifyValidation::Unknown);
    /// ```
    #[must_use]
    pub fn unresolved_from_metadata(metadata: &DappMetadata) -> Self {
        Self::unknown(
            metadata.url.clone(),
            metadata.verify_url.as_deref().unwrap_or(DEFAULT_VERIFY_URL),
        )
    }
}

/// Origin verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedOrigin {
    /// Origin associated with the dapp after Verify API resolution.
    pub origin: String,
    /// Validation result comparing the verified origin with dapp metadata.
    pub validation: VerifyValidation,
    /// Verify API endpoint used for resolution.
    #[serde(rename = "verifyUrl")]
    pub verify_url: String,
    /// Threat signal returned by the Verify API.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3310-L3315>
    ///
    /// > context.verified.origin = result.origin;
    /// > context.verified.isScam = result.isScam;
    /// > context.verified.validation =
    #[serde(rename = "isScam", default, skip_serializing_if = "Option::is_none")]
    pub is_scam: Option<bool>,
}

impl VerifiedOrigin {
    /// Treats absent `isScam` as no scam signal.
    #[must_use]
    pub const fn is_scam(&self) -> bool {
        matches!(self.is_scam, Some(true))
    }
}

/// Verify v3 public-key response.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L171-L178>
///
/// > return await response.json();
///
/// # Examples
///
/// ```
/// use wc_protocol::verify::VerifyJwtPublicKeyResponse;
///
/// let json = r#"{
///   "publicKey": {
///     "x": "CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk",
///     "y": "KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0"
///   },
///   "expiresAt": 1782655613
/// }"#;
/// let response = serde_json::from_str::<VerifyJwtPublicKeyResponse>(json)?;
///
/// assert_eq!(response.expires_at, 1_782_655_613);
/// assert_eq!(response.public_key.x.len(), 43);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyJwtPublicKeyResponse {
    /// P-256 public key used to verify JWT attestations.
    #[serde(rename = "publicKey")]
    pub public_key: VerifyP256PublicKey,
    /// Public-key expiry timestamp returned by Verify v3.
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
}

/// P-256 JWK public key coordinates used by Verify JWT attestations.
///
/// The maintained SDK converts `x` and `y` from base64url into an uncompressed
/// SEC1 public key.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L226-L230>
///
/// > const xBytes = fromString(fromBase64URL(keyData.x), BASE64);
/// > const yBytes = fromString(fromBase64URL(keyData.y), BASE64);
/// > return concat([new Uint8Array([0x04]), xBytes, yBytes]);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyP256PublicKey {
    /// Base64url-encoded P-256 `x` coordinate.
    pub x: String,
    /// Base64url-encoded P-256 `y` coordinate.
    pub y: String,
}

/// Verified JWT attestation payload.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L249-L255>
///
/// > origin: validation.payload.origin,
/// > isScam: validation.payload.isScam,
/// > isVerified: validation.payload.isVerified,
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VerifyJwtAttestation {
    /// Expiry timestamp in unix seconds.
    pub exp: u64,
    /// Encrypted attestation ID matched against the relay-provided `encryptedId`.
    pub id: String,
    /// Origin resolved by the Verify attestation.
    pub origin: String,
    /// Threat signal returned by Verify.
    #[serde(rename = "isScam")]
    pub is_scam: bool,
    /// Whether Verify considers the origin verified.
    #[serde(rename = "isVerified")]
    pub is_verified: bool,
}

impl VerifyP256PublicKey {
    /// Decodes `x` and `y` into the uncompressed SEC1 public key bytes.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L226-L230>
    ///
    /// > return concat([new Uint8Array([0x04]), xBytes, yBytes]);
    pub fn sec1_bytes(&self) -> Result<Vec<u8>, VerifyP256PublicKeyError> {
        let x = decode_coordinate(&self.x, P256Coordinate::X)?;
        let y = decode_coordinate(&self.y, P256Coordinate::Y)?;
        let mut bytes = Vec::with_capacity(65);
        bytes.push(0x04);
        bytes.extend_from_slice(&x);
        bytes.extend_from_slice(&y);
        Ok(bytes)
    }
}

impl VerifyJwtAttestation {
    /// Compares `exp` to a caller-provided unix timestamp.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.exp <= now_unix_seconds
    }
}

/// Decoded compact JWS for a Verify JWT attestation.
///
/// The signature is not validated at this layer. The core resolver verifies the
/// returned signing input and raw `r || s` signature with its crypto provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyJwtAttestationJws {
    signing_input: String,
    signature: Vec<u8>,
    payload: VerifyJwtAttestation,
}

impl VerifyJwtAttestationJws {
    /// Decodes the compact JWS envelope without trusting the payload.
    ///
    /// The maintained SDK first splits the JWT into three base64url parts and
    /// expects ES256 raw `r || s` signatures.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L233-L256>
    ///
    /// > const [headerBase64Url, payloadBase64Url, signatureBase64Url] = token.split(".");
    /// > if (signatureBytes.length !== 64) throw new Error("Invalid signature length");
    pub fn decode(token: &str) -> Result<Self, VerifyJwtAttestationError> {
        let parts = JwtParts::parse(token)?;
        let header = decode_jwt_json::<VerifyJwtHeader>(parts.header, JwtPart::Header)?;
        if header.alg != "ES256" {
            return Err(VerifyJwtAttestationError::UnsupportedAlgorithm { alg: header.alg });
        }

        let payload = decode_jwt_json::<VerifyJwtAttestation>(parts.payload, JwtPart::Payload)?;
        let signature = decode_base64_url(parts.signature, JwtPart::Signature)?;
        if signature.len() != 64 {
            return Err(VerifyJwtAttestationError::SignatureLength {
                actual: signature.len(),
            });
        }

        Ok(Self {
            signing_input: parts.signing_input(),
            signature,
            payload,
        })
    }

    /// Exact `header.payload` byte string covered by the JWS signature.
    #[must_use]
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    /// Raw ES256 `r || s` signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Attestation payload decoded from the compact JWS.
    #[must_use]
    pub const fn payload(&self) -> &VerifyJwtAttestation {
        &self.payload
    }

    /// Consumes the JWS and returns the decoded payload.
    #[must_use]
    pub fn into_payload(self) -> VerifyJwtAttestation {
        self.payload
    }
}

/// Verify JWT attestation payload decode error.
///
/// The error covers compact-JWS parsing only. Signature validation happens in
/// `wc-core` so it can reuse the runtime crypto provider without adding a
/// second P-256 dependency to the protocol crate.
#[derive(Debug, thiserror::Error)]
pub enum VerifyJwtAttestationError {
    /// JWT did not have exactly three non-empty compact-serialization parts.
    #[error("verify JWT must use compact serialization with three non-empty parts")]
    MalformedCompact,

    /// JWT part was not valid unpadded base64url.
    #[error("verify JWT {part} base64url decoding failed")]
    Base64 {
        /// Rejected JWT part.
        part: JwtPart,
        /// Source base64 decoder error.
        #[source]
        source: base64::DecodeError,
    },

    /// JWT part did not contain the expected JSON object.
    #[error("verify JWT {part} JSON decoding failed")]
    Json {
        /// Rejected JWT part.
        part: JwtPart,
        /// Source JSON decoder error.
        #[source]
        source: serde_json::Error,
    },

    /// JWT algorithm was not the ES256 algorithm used by Verify.
    #[error("verify JWT uses unsupported algorithm: {alg}")]
    UnsupportedAlgorithm {
        /// Header `alg` value.
        alg: String,
    },

    /// ES256 compact JWS signatures use raw 64-byte `r || s`.
    #[error("verify JWT signature must be 64 bytes, got {actual}")]
    SignatureLength {
        /// Decoded byte length.
        actual: usize,
    },
}

/// P-256 JWK decode error.
#[derive(Debug, thiserror::Error)]
pub enum VerifyP256PublicKeyError {
    /// Public key coordinate was not valid unpadded base64url.
    #[error("verify JWT public key coordinate {coordinate} base64url decoding failed")]
    Base64 {
        /// Rejected coordinate.
        coordinate: P256Coordinate,
        /// Source base64 decoder error.
        #[source]
        source: base64::DecodeError,
    },

    /// P-256 coordinates are 32 bytes.
    #[error("verify JWT public key coordinate {coordinate} must be 32 bytes, got {actual}")]
    CoordinateLength {
        /// Rejected coordinate.
        coordinate: P256Coordinate,
        /// Decoded byte length.
        actual: usize,
    },
}

#[derive(Debug, Deserialize)]
struct VerifyJwtHeader {
    alg: String,
}

/// Borrowed compact-JWS parts.
struct JwtParts<'a> {
    header: &'a str,
    payload: &'a str,
    signature: &'a str,
}

impl<'a> JwtParts<'a> {
    /// Splits compact serialization and rejects missing or extra parts.
    fn parse(token: &'a str) -> Result<Self, VerifyJwtAttestationError> {
        let mut parts = token.split('.');
        let Some(header) = parts.next().filter(|part| !part.is_empty()) else {
            return Err(VerifyJwtAttestationError::MalformedCompact);
        };
        let Some(payload) = parts.next().filter(|part| !part.is_empty()) else {
            return Err(VerifyJwtAttestationError::MalformedCompact);
        };
        let Some(signature) = parts.next().filter(|part| !part.is_empty()) else {
            return Err(VerifyJwtAttestationError::MalformedCompact);
        };
        if parts.next().is_some() {
            return Err(VerifyJwtAttestationError::MalformedCompact);
        }

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// Reconstructs the signed input without normalizing either JSON part.
    fn signing_input(&self) -> String {
        format!("{}.{}", self.header, self.payload)
    }
}

/// Decodes one base64url JWT part.
fn decode_base64_url(value: &str, part: JwtPart) -> Result<Vec<u8>, VerifyJwtAttestationError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|source| VerifyJwtAttestationError::Base64 { part, source })
}

/// Decodes one JWT JSON part after base64url decoding.
fn decode_jwt_json<T>(value: &str, part: JwtPart) -> Result<T, VerifyJwtAttestationError>
where
    T: for<'de> Deserialize<'de>,
{
    let bytes = decode_base64_url(value, part)?;
    serde_json::from_slice(&bytes)
        .map_err(|source| VerifyJwtAttestationError::Json { part, source })
}

/// Decodes and length-checks one P-256 coordinate.
fn decode_coordinate(
    value: &str,
    coordinate: P256Coordinate,
) -> Result<Vec<u8>, VerifyP256PublicKeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|source| VerifyP256PublicKeyError::Base64 { coordinate, source })?;
    if bytes.len() != 32 {
        return Err(VerifyP256PublicKeyError::CoordinateLength {
            coordinate,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// JWT compact-serialization part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtPart {
    /// JOSE header.
    Header,
    /// JWS payload.
    Payload,
    /// JWS signature.
    Signature,
}

impl fmt::Display for JwtPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Header => "header",
            Self::Payload => "payload",
            Self::Signature => "signature",
        })
    }
}

/// P-256 JWK coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P256Coordinate {
    /// `x` coordinate.
    X,
    /// `y` coordinate.
    Y,
}

impl fmt::Display for P256Coordinate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::X => "x",
            Self::Y => "y",
        })
    }
}

/// Verify validation value.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/verify.ts#L7-L11>
///
/// > verified: {
/// > origin: string;
/// > validation: "UNKNOWN" | "VALID" | "INVALID";
/// > verifyUrl: string;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VerifyValidation {
    /// The origin has not been verified.
    Unknown,
    /// The verified origin matches the dapp metadata origin.
    Valid,
    /// The verified origin does not match the dapp metadata origin.
    Invalid,
    /// Unrecognized validation value preserved for forward compatibility.
    Other(String),
}

impl VerifyValidation {
    /// Wire value used by the TypeScript SDK.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Valid => "VALID",
            Self::Invalid => "INVALID",
            Self::Other(value) => value,
        }
    }

    /// Converts a wire value into a known validation state or lossless fallback.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "UNKNOWN" => Self::Unknown,
            "VALID" => Self::Valid,
            "INVALID" => Self::Invalid,
            _ => Self::Other(value),
        }
    }
}

impl Serialize for VerifyValidation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for VerifyValidation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::from_wire(value))
    }
}

impl fmt::Display for VerifyValidation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// SHA-256 attestation hash used by the Verify resolver.
///
/// The maintained Sign Client passes `hashMessage(JSON.stringify(payload))` to
/// `core.verify.resolve(...)` for proposal, authentication, and session-request
/// verification.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L63-L66>
///
/// > export function hashMessage(message: string): string {
/// > const result = sha256(fromString(message, UTF8));
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2128-L2133>
///
/// > hash: hashMessage(JSON.stringify(payload)),
///
/// # Examples
///
/// ```
/// use wc_protocol::verify::VerifyAttestationHash;
///
/// let hash = VerifyAttestationHash::from_message("some");
/// assert_eq!(
///     hash.as_str(),
///     "a6b46dd0d1ae5e86cbc8f37e75ceeb6760230c1ca4ffbcb0c97b96dd7d9c464b",
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VerifyAttestationHash(String);

impl VerifyAttestationHash {
    /// Hashes a UTF-8 message with SHA-256 and lowercase hex encoding.
    #[must_use]
    pub fn from_message(message: &str) -> Self {
        let digest = Sha256::digest(message.as_bytes());
        Self(hex_lower(&digest))
    }

    /// Parses an already-computed Verify attestation hash.
    pub fn parse(value: impl Into<String>) -> Result<Self, VerifyAttestationHashError> {
        let value = value.into();
        if value.len() != 64 {
            return Err(VerifyAttestationHashError::WrongLength {
                actual: value.len(),
            });
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(VerifyAttestationHashError::InvalidHex);
        }

        Ok(Self(value))
    }

    /// Lowercase hex hash string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VerifyAttestationHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl TryFrom<String> for VerifyAttestationHash {
    type Error = VerifyAttestationHashError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<VerifyAttestationHash> for String {
    fn from(value: VerifyAttestationHash) -> Self {
        value.0
    }
}

/// Verify attestation hash parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyAttestationHashError {
    /// Verify attestation hashes are SHA-256 hex strings.
    #[error("verify attestation hash must be 64 lowercase hex characters, got {actual}")]
    WrongLength {
        /// Number of characters in the rejected value.
        actual: usize,
    },

    /// Hash contained a non-hex or uppercase character.
    #[error("verify attestation hash must be lowercase hex")]
    InvalidHex,
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}
