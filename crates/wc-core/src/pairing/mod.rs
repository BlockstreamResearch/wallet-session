//! Pairing and first session-topic client behavior.

use std::time::Duration;

mod approval;
mod client;
mod codec;
mod error;
mod publish;
mod session_lifecycle;
mod session_request;
mod types;

#[cfg(test)]
mod tests;

pub use client::{PairingClient, PairingClientConfig};
pub use error::PairingClientError;
pub use types::{
    ApprovedSession, PairingPayload, PairingReceivedMessage, PairingSubscription,
    SessionMessageOutcome, SessionPayload, SessionProposalApproval, SessionReceivedMessage,
    SessionRequestRejection, SessionSettleResponseMessage, SessionSettleResponsePayload,
    SessionSubscription,
};

/// Default wait time for one live pairing-topic message.
pub const DEFAULT_PAIRING_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default session lifetime used by the first approval primitive.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/constants/session.ts#L1-L5>
///
/// > export const SESSION_EXPIRY = SEVEN_DAYS;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L482-L486>
///
/// > const sessionSettle = {
/// > relay: { protocol: relayProtocol ?? "irn" },
/// > namespaces,
/// > expiry: calcExpiry(SESSION_EXPIRY),
pub const DEFAULT_SESSION_EXPIRY_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Relay tag used for approved `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L13-L17>
///
/// > res: { ttl: FIVE_MINUTES, prompt: false, tag: 1101 }
pub const SESSION_PROPOSE_RESPONSE_TAG: u64 = 1101;

/// Relay tag used for rejected `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L18-L22>
///
/// > reject: { ttl: FIVE_MINUTES, prompt: false, tag: 1120 }
pub const SESSION_PROPOSE_REJECT_TAG: u64 = 1120;

/// Relay tag used for `wc_sessionSettle` requests.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L29-L34>
///
/// > req: { ttl: FIVE_MINUTES, prompt: false, tag: 1102 }
pub const SESSION_SETTLE_REQUEST_TAG: u64 = 1102;

/// Relay tag used for `wc_sessionSettle` responses.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > // Success result
/// > true
/// > Tag     | 1103
pub const SESSION_SETTLE_RESPONSE_TAG: u64 = 1103;

/// Relay retention window for approved `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L13-L17>
///
/// > res: { ttl: FIVE_MINUTES, prompt: false, tag: 1101 }
pub const SESSION_PROPOSE_RESPONSE_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for rejected `wc_sessionPropose` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L18-L22>
///
/// > reject: { ttl: FIVE_MINUTES, prompt: false, tag: 1120 }
pub const SESSION_PROPOSE_REJECT_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for `wc_sessionSettle` requests.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L29-L34>
///
/// > req: { ttl: FIVE_MINUTES, prompt: false, tag: 1102 }
pub const SESSION_SETTLE_REQUEST_TTL_SECONDS: u64 = 5 * 60;

/// Relay retention window for `wc_sessionSettle` responses.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > TTL     | 300
/// > Tag     | 1103
pub const SESSION_SETTLE_RESPONSE_TTL_SECONDS: u64 = 5 * 60;

/// Relay tag used for `wc_sessionRequest` responses.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
///
/// > // Success result
/// > any
/// > TTL     | 300
/// > Tag     | 1109
pub const SESSION_REQUEST_RESPONSE_TAG: u64 = 1109;

/// Relay retention window for `wc_sessionRequest` responses.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
///
/// > TTL     | 300
/// > Tag     | 1109
pub const SESSION_REQUEST_RESPONSE_TTL_SECONDS: u64 = 5 * 60;

/// Relay tag used for `wc_sessionDelete` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L90-L100>
///
/// > wc_sessionDelete: {
/// > res: {
/// > tag: 1113,
pub const SESSION_DELETE_RESPONSE_TAG: u64 = 1113;

/// Relay retention window for `wc_sessionDelete` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L90-L100>
///
/// > ttl: ONE_DAY,
/// > tag: 1113,
pub const SESSION_DELETE_RESPONSE_TTL_SECONDS: u64 = 24 * 60 * 60;

/// Relay tag used for `wc_sessionPing` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L102-L112>
///
/// > wc_sessionPing: {
/// > res: {
/// > tag: 1115,
pub const SESSION_PING_RESPONSE_TAG: u64 = 1115;

/// Relay retention window for `wc_sessionPing` responses.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/cf822b5691a43ab1c2cce9daf5f070f7fbae7149/packages/sign-client/src/constants/engine.ts#L102-L112>
///
/// > ttl: ONE_DAY,
/// > tag: 1115,
pub const SESSION_PING_RESPONSE_TTL_SECONDS: u64 = 24 * 60 * 60;
