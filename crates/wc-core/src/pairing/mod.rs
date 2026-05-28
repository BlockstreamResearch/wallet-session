//! Pairing and first session-topic client behavior.

use std::time::Duration;

mod approval;
mod client;
mod codec;
mod error;
mod types;

#[cfg(test)]
mod tests;

pub use client::{PairingClient, PairingClientConfig};
pub use error::PairingClientError;
pub use types::{
    ApprovedSession, PairingPayload, PairingReceivedMessage, PairingSubscription, SessionPayload,
    SessionProposalApproval, SessionReceivedMessage, SessionSettleResponseMessage,
    SessionSettleResponsePayload, SessionSubscription,
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
