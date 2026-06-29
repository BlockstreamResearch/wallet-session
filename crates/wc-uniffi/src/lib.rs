//! `UniFFI` bindings for Android wallet integration.
//!
//! The exported API keeps Rust as the protocol authority: Kotlin receives
//! stable review records and JSON payloads for wallet UI/policy, while Rust
//! retains the opaque pending messages required to approve, reject, or answer
//! `WalletConnect` requests without reconstructing protocol state.

#![allow(
    clippy::needless_pass_by_value,
    reason = "UniFFI exported functions use owned ABI values."
)]
#![allow(
    clippy::significant_drop_tightening,
    reason = "Exported methods intentionally hold the single client mutex across protocol mutations."
)]

pub(crate) mod bitcoin;
pub(crate) mod capabilities;
pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod exports;
pub(crate) mod outcome;
pub(crate) mod review;
#[cfg(test)]
mod tests;
pub(crate) mod types;
pub(crate) mod util;

pub use bitcoin::{
    wc_bitcoin_addresses_changed_event_params_json, wc_bitcoin_session_properties_json,
};
pub use client::WcClient;
pub use config::WcClientConfig;
pub use error::WcUniFfiError;
pub use exports::{
    wc_canonical_account_id, wc_canonical_chain_id, wc_generate_relay_auth_seed_hex,
};
pub use types::{
    WcCapabilities, WcChainCapability, WcEvent, WcEventKind, WcJsonPayload, WcPendingApproval,
    WcPendingApprovalKind, WcSessionAuthenticateOutcome, WcSessionInfo, WcWalletMetadata,
};

uniffi::setup_scaffolding!();
