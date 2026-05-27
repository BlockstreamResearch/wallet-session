//! `WalletConnect` protocol DTOs, parsers, and validation primitives.

pub mod caip;
pub mod dto;
mod encoding;
pub mod envelope;
pub mod pairing;
pub mod relay;

pub use dto::session;
