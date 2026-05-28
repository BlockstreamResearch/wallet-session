//! Core `WalletConnect` client behavior.

mod pairing;

pub use pairing::{
    ApprovedSession, DEFAULT_PAIRING_RECEIVE_TIMEOUT, DEFAULT_SESSION_EXPIRY_SECONDS,
    PairingClient, PairingClientConfig, PairingClientError, PairingPayload, PairingReceivedMessage,
    PairingSubscription, SESSION_PROPOSE_REJECT_TAG, SESSION_PROPOSE_REJECT_TTL_SECONDS,
    SESSION_PROPOSE_RESPONSE_TAG, SESSION_PROPOSE_RESPONSE_TTL_SECONDS, SESSION_SETTLE_REQUEST_TAG,
    SESSION_SETTLE_REQUEST_TTL_SECONDS, SESSION_SETTLE_RESPONSE_TAG,
    SESSION_SETTLE_RESPONSE_TTL_SECONDS, SessionPayload, SessionProposalApproval,
    SessionReceivedMessage, SessionSettleResponseMessage, SessionSettleResponsePayload,
    SessionSubscription,
};
