//! Verify API DTOs.

use std::fmt;

use serde::{Deserialize, Serialize};

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
