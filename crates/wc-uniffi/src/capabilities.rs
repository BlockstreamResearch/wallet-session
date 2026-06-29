use wc_core::{WalletCapabilities, WalletChainCapability};
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId},
    session::{DappMetadata, DappRedirect, SessionEventName, SessionMethod, SessionNamespaces},
};

use crate::{
    error::WcUniFfiError,
    types::{WcCapabilities, WcChainCapability, WcWalletMetadata},
    util::{invalid_error, invalid_input, non_empty, operation_error, parse_json_object},
};

pub fn wallet_capabilities(input: WcCapabilities) -> Result<WalletCapabilities, WcUniFfiError> {
    let chains = input
        .chains
        .into_iter()
        .map(wallet_chain_capability)
        .collect::<Result<Vec<_>, _>>()?;
    let mut capabilities = WalletCapabilities::new(chains).map_err(operation_error)?;
    if let Some(json) = input.session_properties_json {
        capabilities = capabilities.with_session_properties(parse_json_object(&json)?);
    }
    if let Some(json) = input.scoped_properties_json {
        capabilities = capabilities.with_scoped_properties(parse_json_object(&json)?);
    }
    Ok(capabilities)
}

pub fn optional_session_namespaces(
    input: Option<WcCapabilities>,
) -> Result<Option<SessionNamespaces>, WcUniFfiError> {
    input.map(required_session_namespaces).transpose()
}

pub fn required_session_namespaces(
    input: WcCapabilities,
) -> Result<SessionNamespaces, WcUniFfiError> {
    let capabilities = wallet_capabilities(input)?;
    let namespaces = capabilities.to_session_namespaces();
    if namespaces.is_empty() {
        return Err(invalid_input("session namespaces must not be empty"));
    }
    capabilities
        .validate_session_update_namespaces(&namespaces)
        .map_err(operation_error)?;
    Ok(namespaces)
}

fn wallet_chain_capability(
    input: WcChainCapability,
) -> Result<WalletChainCapability, WcUniFfiError> {
    let chain = Caip2ChainId::parse(input.chain_id).map_err(invalid_error)?;
    let accounts = input
        .accounts
        .into_iter()
        .map(Caip10AccountId::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_error)?;
    let methods = input
        .methods
        .into_iter()
        .map(SessionMethod::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_error)?;
    let events = input
        .events
        .into_iter()
        .map(SessionEventName::parse)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_error)?;
    WalletChainCapability::new(chain, accounts, methods, events).map_err(operation_error)
}

impl TryFrom<WcWalletMetadata> for DappMetadata {
    type Error = WcUniFfiError;

    fn try_from(value: WcWalletMetadata) -> Result<Self, Self::Error> {
        Ok(Self {
            name: non_empty("wallet_metadata.name", value.name)?,
            description: value.description,
            url: non_empty("wallet_metadata.url", value.url)?,
            icons: value.icons,
            verify_url: value.verify_url,
            redirect: (value.redirect_native.is_some()
                || value.redirect_universal.is_some()
                || value.redirect_link_mode.is_some())
            .then_some(DappRedirect {
                native: value.redirect_native,
                universal: value.redirect_universal,
                link_mode: value.redirect_link_mode,
            }),
        })
    }
}
