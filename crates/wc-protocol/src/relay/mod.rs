//! Relay protocol primitives.
//!
//! - authenticated WebSocket URL construction
//! - `did:key`/Ed25519 Relay Auth JWT signing
//! - topic validation
//! - JSON-RPC request/response envelopes
//! - `irn_subscribe`, `irn_publish`, `irn_subscription`,
//!   `irn_fetchMessages`, and `irn_unsubscribe` DTOs

pub mod auth;
pub mod rpc;
pub mod topic;

pub use auth::{
    DEFAULT_RELAY_URL, RelayAuthError, RelayAuthToken, RelayConnectionUrl, ed25519_did_key,
    relay_auth_audience,
};
pub use rpc::{
    IrnFetchMessages, IrnFetchMessagesResponse, IrnPublish, IrnSubscribe, IrnSubscription,
    IrnSubscriptionData, IrnUnsubscribe, JSON_RPC_VERSION, RelayJsonRpcErrorData,
    RelayJsonRpcErrorResponse, RelayJsonRpcRequest, RelayJsonRpcResponse, RelayJsonRpcSuccess,
    RelayRequest, RelayRpcId, RelayRpcIdError,
};
pub use topic::{RelayTopic, RelayTopicError};
