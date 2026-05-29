//! `WalletConnect` protocol DTOs, parsers, and validation primitives.

pub mod caip;
pub mod did;
pub mod dto;
mod encoding;
pub mod envelope;
pub mod key;
pub mod namespaces;
pub mod pairing;
pub mod pairing_message;
pub mod relay;
pub mod verify;

pub use dto::session;
