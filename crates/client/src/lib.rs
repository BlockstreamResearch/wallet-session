//! Client for the wallet-session relay protocol.
//!
//! A [`Client`] owns one pairing topic and, after the handshake, one derived
//! session topic. Its counterpart, replay memory, and outstanding reliability
//! state are in memory for the lifetime of that client instance. Creating a
//! new client with the same pairing key starts with empty replay state and no
//! counterpart, so long-lived applications should reuse the existing client.
//!
//! Inbound work, including acknowledgements and relay lifecycle events, is
//! driven by [`Client::recv`], [`Client::next_event`], and
//! [`Client::wait_session_ready`]. Applications should keep one of those
//! futures pending while the session is active.

mod client;
mod config;
mod error;
mod identity;
mod messages;
mod pairing;
mod random;
mod relay;
mod reliability;
mod replay;
mod session;
mod tls;

pub mod crypto;
pub mod handshake;

pub use client::Client;
pub use config::ClientConfig;
pub use crypto::XChaCha20Poly1305Cipher;
pub use error::{ClientError, Result};
pub use identity::{IdentityKey, Seed};
pub use messages::{ClientMessage, RequestId};
pub use pairing::{PairingKey, PairingUri};
pub use reliability::ClientEvent;
pub use session::{Role, Session, SessionState};
pub use wallet_session_core::payload::{
    AckPayload, ApprovePayload, DisconnectPayload, Opaque, ProposalPayload, RejectPayload,
    RequestPayload, ResponsePayload, SessionDeletePayload,
};
