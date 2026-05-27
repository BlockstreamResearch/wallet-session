//! Namespace validation primitives.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    caip::{Caip2ChainId, Caip10AccountId, CaipNamespace, NamespaceKey},
    session::{ProposalNamespace, ProposalNamespaces, SessionNamespaces},
};

/// Validates that approved session namespaces satisfy required proposal namespaces.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response>
///
/// > All required namespaces MUST be satisfied by a wallet
///
/// The maintained JavaScript utility normalizes proposal and approved namespaces
/// by chain before comparing them.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L380-L447>
///
/// > const parsedRequired = parseNamespaces(requiredNamespaces);
/// > const parsedApproved = parseApprovedNamespaces(namespaces);
///
/// Coverage is an all-required-values check, not a partial overlap.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/misc.ts#L259-L262>
///
/// > return matches.length === a.length;
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
///
/// use wc_protocol::{
///     caip::{Caip10AccountId, Caip2ChainId, NamespaceKey},
///     namespaces::validate_approved_namespaces,
///     session::{ProposalNamespace, SessionNamespace},
/// };
///
/// let mut required = BTreeMap::new();
/// required.insert(
///     NamespaceKey::parse("eip155")?,
///     ProposalNamespace {
///         chains: Some(vec![Caip2ChainId::parse("eip155:1")?]),
///         methods: vec!["personal_sign".to_owned()],
///         events: vec!["accountsChanged".to_owned()],
///     },
/// );
///
/// let mut approved = BTreeMap::new();
/// approved.insert(
///     NamespaceKey::parse("eip155")?,
///     SessionNamespace {
///         chains: Some(vec![Caip2ChainId::parse("eip155:1")?]),
///         accounts: vec![Caip10AccountId::parse(
///             "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
///         )?],
///         methods: vec!["personal_sign".to_owned()],
///         events: vec!["accountsChanged".to_owned()],
///     },
/// );
///
/// validate_approved_namespaces(&required, &approved)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_approved_namespaces(
    required: &ProposalNamespaces,
    approved: &SessionNamespaces,
) -> Result<(), NamespaceValidationError> {
    validate_required_namespaces(required)?;

    let required_namespaces = required_namespace_components(required);
    let approved_namespaces = approved_namespace_components(approved);
    if let Some(namespace) = required_namespaces
        .iter()
        .find(|namespace| !approved_namespaces.contains(*namespace))
    {
        return Err(NamespaceValidationError::MissingRequiredNamespace {
            namespace: namespace.clone(),
        });
    }

    let required_by_chain = proposal_requirements_by_chain(required)?;
    let approved_by_chain = approved_permissions_by_chain(approved)?;

    for (chain_id, required_chain) in required_by_chain {
        let Some(approved_chain) = approved_by_chain.get(&chain_id) else {
            return Err(NamespaceValidationError::MissingAccountForChain { chain_id });
        };

        for method in &required_chain.methods {
            if !approved_chain.methods.contains(method) {
                return Err(NamespaceValidationError::MissingMethod {
                    chain_id,
                    method: method.clone(),
                });
            }
        }

        for event in &required_chain.events {
            if !approved_chain.events.contains(event) {
                return Err(NamespaceValidationError::MissingEvent {
                    chain_id,
                    event: event.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Validates proposal namespace chain shape before approval.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#proposal-namespace>
///
/// > Chains MIGHT be omitted if the CAIP-2 is defined in the index
///
/// The JavaScript utility follows the same key-or-`chains` rule.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/caip.ts#L107-L113>
///
/// > return namespace.includes(":") ? [namespace] : namespaceProps.chains || [];
pub fn validate_required_namespaces(
    required: &ProposalNamespaces,
) -> Result<(), NamespaceValidationError> {
    for (key, namespace) in required {
        let chains = proposal_chains(key, namespace)?;
        for chain_id in chains {
            if chain_id.namespace() != key.namespace() {
                return Err(NamespaceValidationError::ChainNamespaceMismatch {
                    namespace: namespace_component(key),
                    chain_id: chain_id.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Checks whether a session namespace authorizes a CAIP-2 chain.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L352-L358>
///
/// > const chains = getNamespacesChains(namespaces);
/// > if (!chains.includes(chainId)) return false;
#[must_use]
pub fn is_chain_authorized(namespaces: &SessionNamespaces, chain_id: &Caip2ChainId) -> bool {
    approved_permissions_by_chain(namespaces).is_ok_and(|permissions| {
        permissions
            .get(chain_id)
            .is_some_and(|permission| permission.account_count > 0)
    })
}

/// Checks whether a session namespace authorizes a method for a CAIP-2 chain.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L360-L368>
///
/// > const methods = getNamespacesMethodsForChainId(namespaces, chainId);
/// > return methods.includes(method);
#[must_use]
pub fn is_method_authorized(
    namespaces: &SessionNamespaces,
    chain_id: &Caip2ChainId,
    method: &str,
) -> bool {
    approved_permissions_by_chain(namespaces).is_ok_and(|permissions| {
        permissions
            .get(chain_id)
            .is_some_and(|permission| permission.methods.contains(method))
    })
}

/// Checks whether a session namespace authorizes an event for a CAIP-2 chain.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L370-L378>
///
/// > const events = getNamespacesEventsForChainId(namespaces, chainId);
/// > return events.includes(eventName);
#[must_use]
pub fn is_event_authorized(
    namespaces: &SessionNamespaces,
    chain_id: &Caip2ChainId,
    event: &str,
) -> bool {
    approved_permissions_by_chain(namespaces).is_ok_and(|permissions| {
        permissions
            .get(chain_id)
            .is_some_and(|permission| permission.events.contains(event))
    })
}

/// Namespace validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NamespaceValidationError {
    /// A bare proposal namespace has no `chains`.
    #[error("proposal namespace {namespace} must define chains or use CAIP-2 keys")]
    MissingChains {
        /// Namespace missing chain definitions.
        namespace: CaipNamespace,
    },

    /// A requested chain does not match its proposal namespace key.
    #[error("chain {chain_id} does not match proposal namespace {namespace}")]
    ChainNamespaceMismatch {
        /// Proposal namespace key component.
        namespace: CaipNamespace,
        /// Chain listed under the wrong namespace.
        chain_id: Caip2ChainId,
    },

    /// An approved namespace map omits a required namespace key component.
    #[error("approved namespaces are missing required namespace {namespace}")]
    MissingRequiredNamespace {
        /// Missing namespace component.
        namespace: CaipNamespace,
    },

    /// A required chain has no approved CAIP-10 account.
    #[error("approved namespaces are missing an account for chain {chain_id}")]
    MissingAccountForChain {
        /// Required chain without an account.
        chain_id: Caip2ChainId,
    },

    /// An approved namespace contains no accounts.
    #[error("approved namespace {namespace} must include at least one account")]
    EmptyAccounts {
        /// Namespace with no accounts.
        namespace: NamespaceKey,
    },

    /// An approved account is stored under a namespace with a different prefix.
    #[error("account {account} does not match approved namespace {namespace}")]
    AccountNamespaceMismatch {
        /// Approved namespace key.
        namespace: NamespaceKey,
        /// Account stored under the wrong namespace.
        account: Caip10AccountId,
    },

    /// A required method is not present in the approved chain permissions.
    #[error("approved namespaces are missing method {method} for chain {chain_id}")]
    MissingMethod {
        /// Chain whose method set is incomplete.
        chain_id: Caip2ChainId,
        /// Missing JSON-RPC method.
        method: String,
    },

    /// A required event is not present in the approved chain permissions.
    #[error("approved namespaces are missing event {event} for chain {chain_id}")]
    MissingEvent {
        /// Chain whose event set is incomplete.
        chain_id: Caip2ChainId,
        /// Missing session event.
        event: String,
    },
}

#[derive(Debug, Default)]
struct ChainRequirements {
    methods: BTreeSet<String>,
    events: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct ChainPermissions {
    account_count: usize,
    methods: BTreeSet<String>,
    events: BTreeSet<String>,
}

fn proposal_requirements_by_chain(
    namespaces: &ProposalNamespaces,
) -> Result<BTreeMap<Caip2ChainId, ChainRequirements>, NamespaceValidationError> {
    let mut requirements = BTreeMap::new();
    for (key, namespace) in namespaces {
        for chain_id in proposal_chains(key, namespace)? {
            let entry = requirements
                .entry(chain_id.clone())
                .or_insert_with(ChainRequirements::default);
            entry.methods.extend(namespace.methods.iter().cloned());
            entry.events.extend(namespace.events.iter().cloned());
        }
    }
    Ok(requirements)
}

fn approved_permissions_by_chain(
    namespaces: &SessionNamespaces,
) -> Result<BTreeMap<Caip2ChainId, ChainPermissions>, NamespaceValidationError> {
    let mut permissions = BTreeMap::new();
    for (key, namespace) in namespaces {
        if namespace.accounts.is_empty() {
            return Err(NamespaceValidationError::EmptyAccounts {
                namespace: key.clone(),
            });
        }

        let mut key_chain_accounts = 0_usize;
        for account in &namespace.accounts {
            if account.namespace() != key.namespace() {
                return Err(NamespaceValidationError::AccountNamespaceMismatch {
                    namespace: key.clone(),
                    account: account.clone(),
                });
            }

            let chain_id = account.chain_id();
            if key
                .chain_id()
                .is_some_and(|key_chain| key_chain == &chain_id)
            {
                key_chain_accounts += 1;
            }

            let entry = permissions
                .entry(chain_id)
                .or_insert_with(ChainPermissions::default);
            entry.account_count += 1;
            entry.methods.extend(namespace.methods.iter().cloned());
            entry.events.extend(namespace.events.iter().cloned());
        }

        if let Some(chain_id) = key.chain_id()
            && key_chain_accounts == 0
        {
            return Err(NamespaceValidationError::MissingAccountForChain {
                chain_id: chain_id.clone(),
            });
        }
    }

    Ok(permissions)
}

fn proposal_chains<'a>(
    key: &'a NamespaceKey,
    namespace: &'a ProposalNamespace,
) -> Result<Vec<&'a Caip2ChainId>, NamespaceValidationError> {
    match key {
        NamespaceKey::ChainId(chain_id) => Ok(vec![chain_id]),
        NamespaceKey::Namespace(namespace_key) => namespace
            .chains
            .as_deref()
            .filter(|chains| !chains.is_empty())
            .map(<[_]>::iter)
            .map(Iterator::collect)
            .ok_or_else(|| NamespaceValidationError::MissingChains {
                namespace: namespace_key.clone(),
            }),
    }
}

fn required_namespace_components(namespaces: &ProposalNamespaces) -> BTreeSet<CaipNamespace> {
    namespaces.keys().map(namespace_component).collect()
}

fn approved_namespace_components(namespaces: &SessionNamespaces) -> BTreeSet<CaipNamespace> {
    namespaces.keys().map(namespace_component).collect()
}

fn namespace_component(key: &NamespaceKey) -> CaipNamespace {
    CaipNamespace::parse(key.namespace()).expect("NamespaceKey validates its namespace component")
}
