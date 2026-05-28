//! Core `WalletConnect` client behavior.

mod pairing;

pub use pairing::{
    DEFAULT_PAIRING_RECEIVE_TIMEOUT, PairingClient, PairingClientConfig, PairingClientError,
    PairingPayload, PairingReceivedMessage, PairingSubscription,
};
