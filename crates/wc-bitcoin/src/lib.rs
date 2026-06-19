//! `WalletConnect` Bitcoin chain support primitives.
//!
//! This crate implements the JSON shape and wallet-facing review boundaries
//! described by the `WalletConnect` Bitcoin chain support page. It uses
//! `rust-bitcoin` behind WalletConnect-specific newtypes for protocol value
//! validation; wallets still need their own signing, address ownership, UTXO,
//! and PSBT backends before approving a request.

mod account;
mod constants;
mod dto;
mod error;
mod method;
mod request;
mod value;

pub use account::{BitcoinAccountScope, BitcoinConnectedAccount};
pub use constants::{
    BITCOIN_MAINNET_CHAIN_ID, BITCOIN_MAINNET_CHAIN_REFERENCE, BITCOIN_NAMESPACE,
    GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY, bitcoin_mainnet_chain_id, is_bitcoin_chain_id,
};
pub use dto::{
    BitcoinAccountAddress, BitcoinAccountAddresses, GetAccountAddressesParams, SendTransferParams,
    SendTransferResult, SignMessageParams, SignMessageProtocol, SignMessageResult, SignPsbtInput,
    SignPsbtParams, SignPsbtResult,
};
pub use error::{BitcoinAccountScopeError, BitcoinRequestError, BitcoinValueError};
pub use method::{BitcoinEvent, BitcoinMethod};
pub use request::{
    BitcoinAccountAuthorization, BitcoinAccountScopedReview, BitcoinRequest, BitcoinRequestReview,
    BitcoinWalletAddressRole,
};
pub use value::{
    BitcoinAddress, BitcoinAmountSats, BitcoinDerivationPath, BitcoinMemo, BitcoinPsbt,
    BitcoinPublicKey, BitcoinTxid, HexBytes,
};
