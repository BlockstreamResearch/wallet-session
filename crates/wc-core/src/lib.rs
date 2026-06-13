//! Core `WalletConnect` single-session client behavior.

mod capabilities;
mod client;
mod pairing;
mod redirect;
mod session_authenticate;
mod session_request;
mod session_update;
mod verify_policy;
mod verify_resolver;

#[cfg(feature = "testkit")]
pub mod testkit {
    //! Deterministic harnesses for fuzzing and integration tests.
    //!
    //! These helpers exercise internal state primitives without opening a relay
    //! socket. They are feature-gated because wallet applications should use
    //! `SingleSessionClient` directly.

    pub use crate::client::testkit::*;
}

pub use capabilities::{
    ProposalPlanningError, SessionUpdateApprovalError, WalletCapabilities, WalletCapabilityError,
    WalletChainCapability,
};
pub use client::{
    DEFAULT_SINGLE_SESSION_CLIENT_EVENT_QUEUE_CAPACITY,
    DEFAULT_SINGLE_SESSION_CLIENT_RECEIVE_TIMEOUTS_BEFORE_RECONNECT,
    DEFAULT_SINGLE_SESSION_CLIENT_RECONNECT_COOLDOWN, SessionAuthenticateApprovalOutcome,
    SessionAuthenticateRequestExpired, SessionExpired, SessionProposalExpired,
    SingleSessionAuthenticate, SingleSessionClient, SingleSessionClientConfig,
    SingleSessionClientConnectionState, SingleSessionClientError, SingleSessionClientEvent,
    SingleSessionPendingApproval, SingleSessionProposal,
};
pub use pairing::{
    DEFAULT_PAIRING_RECEIVE_TIMEOUT, DEFAULT_SESSION_EXPIRY_SECONDS,
    PairingClientConfig as SingleSessionRelayConfig, PairingClientError, PairingPayload,
    PairingReceivedMessage, RelayAuthSeed, SessionClientEvent, SessionLifecycleRequest,
    SessionLifecycleResponseMessage, SessionLifecycleResponsePayload, SessionPayload,
    SessionProposalApproval, SessionReceivedMessage, SessionRequestRejection,
};
pub use redirect::{
    WalletRedirectOrigin, WalletRedirectReview, WalletRedirectTarget, WalletRedirectTargetKind,
};
pub use session_authenticate::{
    SessionAuthenticateAccountReview, SessionAuthenticateAccountStatus,
    SessionAuthenticateApproval, SessionAuthenticateApprovalError,
    SessionAuthenticatePayloadReview, SessionAuthenticateReview, SessionAuthenticateReviewError,
};
pub use session_request::{
    SessionRequestAccountConstraint, SessionRequestAccountConstraintStatus,
    SessionRequestChainConstraint, SessionRequestChainConstraintStatus, SessionRequestMethodReview,
    SessionRequestMethodReviewError, SessionRequestReview, SessionRequestReviewError,
    SessionRequestVerifyResolutionError, SigningRequestKind, SigningRequestReview,
    TransactionRequestReview, WalletCallChainConstraint, WalletCallChainConstraintStatus,
    WalletCallReview, WalletCallStatusReview, WalletGetCapabilitiesReview, WalletSendCallsReview,
};
pub use session_update::{
    SessionNamespacePermissionSet, SessionNamespacePermissions, SessionNamespacesDiff,
    SessionUpdateReview, diff_session_namespaces,
};
pub use verify_policy::{
    VerifyContextRisk, VerifyRiskReview, VerifyRiskSurface, classify_verify_context,
};
pub use verify_resolver::{
    DEFAULT_VERIFY_RESOLVER_TIMEOUT, VerifyAttestation, VerifyResolver, VerifyResolverError,
    trusted_verify_url,
};
pub use wc_transport::RelayReconnectConfig;

/// Lower-level pairing and session primitives used by live harnesses.
///
/// Wallet applications should prefer `SingleSessionClient`. The items in this
/// module expose protocol steps directly and can bypass the single-session
/// runtime boundary when composed incorrectly.
pub mod low_level {
    pub use crate::pairing::{
        ApprovedSession, PAIRING_PING_RESPONSE_TAG, PAIRING_PING_RESPONSE_TTL_SECONDS,
        PairingClient, PairingClientConfig, PairingSubscription, RelayAuthSeed,
        SESSION_AUTHENTICATE_REJECT_TAG, SESSION_AUTHENTICATE_REJECT_TTL_SECONDS,
        SESSION_AUTHENTICATE_RESPONSE_TAG, SESSION_AUTHENTICATE_RESPONSE_TTL_SECONDS,
        SESSION_DELETE_REQUEST_TAG, SESSION_DELETE_REQUEST_TTL_SECONDS,
        SESSION_DELETE_RESPONSE_TAG, SESSION_DELETE_RESPONSE_TTL_SECONDS,
        SESSION_EVENT_REQUEST_TAG, SESSION_EVENT_REQUEST_TTL_SECONDS, SESSION_EVENT_RESPONSE_TAG,
        SESSION_EVENT_RESPONSE_TTL_SECONDS, SESSION_EXTEND_REQUEST_TAG,
        SESSION_EXTEND_REQUEST_TTL_SECONDS, SESSION_EXTEND_RESPONSE_TAG,
        SESSION_EXTEND_RESPONSE_TTL_SECONDS, SESSION_PROPOSE_REJECT_TAG,
        SESSION_PROPOSE_REJECT_TTL_SECONDS, SESSION_PROPOSE_RESPONSE_TAG,
        SESSION_PROPOSE_RESPONSE_TTL_SECONDS, SESSION_REQUEST_RESPONSE_TAG,
        SESSION_REQUEST_RESPONSE_TTL_SECONDS, SESSION_SETTLE_REQUEST_TAG,
        SESSION_SETTLE_REQUEST_TTL_SECONDS, SESSION_SETTLE_RESPONSE_TAG,
        SESSION_SETTLE_RESPONSE_TTL_SECONDS, SESSION_UPDATE_REQUEST_TAG,
        SESSION_UPDATE_REQUEST_TTL_SECONDS, SESSION_UPDATE_RESPONSE_TAG,
        SESSION_UPDATE_RESPONSE_TTL_SECONDS, SessionMessageOutcome, SessionSettleResponseMessage,
        SessionSettleResponsePayload, SessionSubscription,
    };
}
