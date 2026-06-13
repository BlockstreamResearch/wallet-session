//! Verify context policy helpers.

use std::fmt;

use wc_protocol::{
    relay::RelayTopic,
    verify::{VerifyAttestationHash, VerifyContext, VerifyValidation},
};

/// Wallet action that requires Verify risk to be surfaced before proceeding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyRiskSurface {
    /// `wc_sessionPropose` approval.
    SessionProposalApproval,
    /// `wc_sessionAuthenticate` approval with CACAO auth objects.
    SessionAuthenticateApproval,
    /// `wc_sessionRequest` success response that can carry a signing result.
    SessionRequestSigning,
}

/// Wallet-facing Verify risk review required by approval/signing APIs.
///
/// This value is a deliberate API boundary: callers obtain it from the
/// proposal/auth/request review object they are about to present to policy/UI,
/// then pass the same value into the approval or success-response method. That
/// keeps the `VALID`/`UNKNOWN`/`INVALID`/scam signal visible in the type-level
/// workflow instead of leaving it as an optional side lookup.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyRiskReview {
    surface: VerifyRiskSurface,
    topic: RelayTopic,
    request_id: u64,
    payload_hash: Option<VerifyAttestationHash>,
    verify_context: VerifyContext,
    risk: VerifyContextRisk,
}

impl fmt::Debug for VerifyRiskReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyRiskReview")
            .field("surface", &self.surface)
            .field("topic", &self.topic)
            .field("request_id", &self.request_id)
            .field("payload_hash", &self.payload_hash)
            .field(
                "verify_context",
                &RedactedVerifyContextDebug(&self.verify_context),
            )
            .field("risk", &self.risk)
            .finish()
    }
}

struct RedactedVerifyContextDebug<'a>(&'a VerifyContext);

impl fmt::Debug for RedactedVerifyContextDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyContext")
            .field("risk", &classify_verify_context(self.0))
            .finish_non_exhaustive()
    }
}

impl VerifyRiskReview {
    pub(crate) const fn new(
        surface: VerifyRiskSurface,
        topic: RelayTopic,
        request_id: u64,
        payload_hash: Option<VerifyAttestationHash>,
        verify_context: VerifyContext,
    ) -> Self {
        let risk = classify_verify_context(&verify_context);
        Self {
            surface,
            topic,
            request_id,
            payload_hash,
            verify_context,
            risk,
        }
    }

    /// Approval/signing surface this review authorizes.
    #[must_use]
    pub const fn surface(&self) -> VerifyRiskSurface {
        self.surface
    }

    /// Pairing or session topic associated with the reviewed request.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request id associated with the reviewed request.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Verify hash of the exact reviewed payload, when retained.
    #[must_use]
    pub const fn payload_hash(&self) -> Option<&VerifyAttestationHash> {
        self.payload_hash.as_ref()
    }

    /// Verify context that should be surfaced to wallet policy/UI.
    #[must_use]
    pub const fn verify_context(&self) -> &VerifyContext {
        &self.verify_context
    }

    /// Classified Verify risk that should be surfaced to wallet policy/UI.
    #[must_use]
    pub const fn risk(&self) -> VerifyContextRisk {
        self.risk
    }

    /// Whether the wallet UI should display an explicit Verify warning.
    #[must_use]
    pub const fn requires_explicit_user_review(&self) -> bool {
        self.risk.requires_explicit_user_review()
    }

    /// Whether a conservative wallet should reject without further approval UI.
    #[must_use]
    pub const fn should_reject_by_default(&self) -> bool {
        self.risk.should_reject_by_default()
    }
}

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
