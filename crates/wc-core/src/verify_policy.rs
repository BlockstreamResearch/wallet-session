//! Verify context policy helpers.

use wc_protocol::verify::{VerifyContext, VerifyValidation};

/// Wallet-facing Verify risk classification.
///
/// The maintained Sign Client emits `verifyContext` for session proposals,
/// session requests, and authentication requests; this helper keeps the wallet
/// policy branch explicit instead of hiding it inside approval calls.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/client.ts#L33-L61>
///
/// > session_proposal: {
/// > verifyContext: Verify.Context;
/// > } & Omit<BaseEventArgs<ProposalTypes.Struct>, "topic">;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3289-L3315>
///
/// > validation: "UNKNOWN",
/// > origin: metadata.url || "",
/// > context.verified.isScam = result.isScam;
///
/// # Examples
///
/// ```
/// use wc_core::{VerifyContextRisk, classify_verify_context};
/// use wc_protocol::verify::VerifyContext;
///
/// let context = VerifyContext::unknown(
///     "https://example.com",
///     "https://verify.walletconnect.org",
/// );
///
/// let risk = classify_verify_context(&context);
/// assert_eq!(risk, VerifyContextRisk::Unknown);
/// assert!(risk.requires_explicit_user_review());
/// assert!(!risk.should_reject_by_default());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyContextRisk {
    /// Verified origin matches dapp metadata and no scam signal is present.
    Valid,
    /// Verify did not establish a trusted origin.
    Unknown,
    /// Verify found an origin mismatch.
    Invalid,
    /// Verify returned a threat signal.
    Scam,
}

impl VerifyContextRisk {
    /// Whether the wallet UI should display an explicit Verify warning.
    #[must_use]
    pub const fn requires_explicit_user_review(self) -> bool {
        !matches!(self, Self::Valid)
    }

    /// Whether a conservative wallet should reject without further approval UI.
    #[must_use]
    pub const fn should_reject_by_default(self) -> bool {
        matches!(self, Self::Invalid | Self::Scam)
    }
}

/// Classifies a Verify context into a wallet policy signal.
///
/// `isScam` has priority over validation because a threat signal remains
/// security-relevant even when the origin comparison is otherwise valid.
#[must_use]
pub const fn classify_verify_context(context: &VerifyContext) -> VerifyContextRisk {
    if context.verified.is_scam() {
        return VerifyContextRisk::Scam;
    }

    match context.verified.validation {
        VerifyValidation::Valid => VerifyContextRisk::Valid,
        VerifyValidation::Invalid => VerifyContextRisk::Invalid,
        VerifyValidation::Unknown | VerifyValidation::Other(_) => VerifyContextRisk::Unknown,
    }
}
