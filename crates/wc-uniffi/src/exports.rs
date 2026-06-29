use wc_protocol::caip::{Caip2ChainId, Caip10AccountId};

use crate::{
    error::WcUniFfiError,
    util::{hex_lower, invalid_error, operation_error},
};

#[uniffi::export]
/// Generates a lowercase 32-byte relay authentication seed as hex.
pub fn wc_generate_relay_auth_seed_hex() -> Result<String, WcUniFfiError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(operation_error)?;
    Ok(hex_lower(&seed))
}

/// Validates and canonicalizes a CAIP-2 chain ID.
#[uniffi::export]
pub fn wc_canonical_chain_id(chain_id: String) -> Result<String, WcUniFfiError> {
    Ok(Caip2ChainId::parse(chain_id)
        .map_err(invalid_error)?
        .to_string())
}

/// Validates and canonicalizes a CAIP-10 account ID.
#[uniffi::export]
pub fn wc_canonical_account_id(account_id: String) -> Result<String, WcUniFfiError> {
    Ok(Caip10AccountId::parse(account_id)
        .map_err(invalid_error)?
        .to_string())
}
