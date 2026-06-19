use wc_protocol::caip::Caip2ChainId;

/// CAIP namespace used by BIP-122 Bitcoin chain identifiers.
pub const BITCOIN_NAMESPACE: &str = "bip122";

/// `WalletConnect` Bitcoin mainnet BIP-122 chain reference.
pub const BITCOIN_MAINNET_CHAIN_REFERENCE: &str = "000000000019d6689c085ae165831e93";

/// `WalletConnect` Bitcoin mainnet CAIP-2 chain identifier.
pub const BITCOIN_MAINNET_CHAIN_ID: &str = "bip122:000000000019d6689c085ae165831e93";

/// Session property key recommended for serialized `getAccountAddresses` data.
pub const GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY: &str = "bip122_getAccountAddresses";

/// Returns whether a CAIP-2 chain identifier targets the Bitcoin namespace.
#[must_use]
pub fn is_bitcoin_chain_id(chain_id: &Caip2ChainId) -> bool {
    chain_id.namespace() == BITCOIN_NAMESPACE
}

/// Parses the `WalletConnect` Bitcoin mainnet chain identifier.
pub fn bitcoin_mainnet_chain_id() -> Result<Caip2ChainId, wc_protocol::caip::CaipParseError> {
    BITCOIN_MAINNET_CHAIN_ID.parse()
}
