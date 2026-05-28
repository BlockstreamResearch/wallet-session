//! Core `WalletConnect` client behavior.

mod client;
mod pairing;

pub use client::{Client, ClientConfig, ClientError, ClientEvent, ClientSessionProposal};
pub use pairing::{
    ApprovedSession, DEFAULT_PAIRING_RECEIVE_TIMEOUT, DEFAULT_SESSION_EXPIRY_SECONDS,
    PairingClient, PairingClientConfig, PairingClientError, PairingPayload, PairingReceivedMessage,
    PairingSubscription, SESSION_EVENT_REQUEST_TAG, SESSION_EVENT_REQUEST_TTL_SECONDS,
    SESSION_EVENT_RESPONSE_TAG, SESSION_EVENT_RESPONSE_TTL_SECONDS, SESSION_EXTEND_REQUEST_TAG,
    SESSION_EXTEND_REQUEST_TTL_SECONDS, SESSION_EXTEND_RESPONSE_TAG,
    SESSION_EXTEND_RESPONSE_TTL_SECONDS, SESSION_PROPOSE_REJECT_TAG,
    SESSION_PROPOSE_REJECT_TTL_SECONDS, SESSION_PROPOSE_RESPONSE_TAG,
    SESSION_PROPOSE_RESPONSE_TTL_SECONDS, SESSION_REQUEST_RESPONSE_TAG,
    SESSION_REQUEST_RESPONSE_TTL_SECONDS, SESSION_SETTLE_REQUEST_TAG,
    SESSION_SETTLE_REQUEST_TTL_SECONDS, SESSION_SETTLE_RESPONSE_TAG,
    SESSION_SETTLE_RESPONSE_TTL_SECONDS, SESSION_UPDATE_REQUEST_TAG,
    SESSION_UPDATE_REQUEST_TTL_SECONDS, SESSION_UPDATE_RESPONSE_TAG,
    SESSION_UPDATE_RESPONSE_TTL_SECONDS, SessionClientEvent, SessionLifecycleRequest,
    SessionLifecycleResponseMessage, SessionLifecycleResponsePayload, SessionMessageOutcome,
    SessionPayload, SessionProposalApproval, SessionReceivedMessage, SessionRequestRejection,
    SessionSettleResponseMessage, SessionSettleResponsePayload, SessionSubscription,
};
