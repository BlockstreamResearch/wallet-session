//! Wallet capability planning for session proposals.

use std::collections::BTreeMap;

use serde_json::Value;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, CaipNamespace, NamespaceKey},
    namespaces::{NamespaceValidationError, validate_approved_namespaces},
    session::{
        DappMetadata, JsonRpcRequest, ProposalNamespace, ProposalNamespaces, ScopedProperties,
        SessionEventName, SessionMethod, SessionNamespace, SessionNamespaces, SessionProperties,
        SessionProposeParams,
    },
};

use crate::pairing::SessionProposalApproval;

/// Wallet-supported chains, accounts, methods, and events.
///
/// The planner uses these capabilities to produce the `namespaces` object sent
/// when approving a `wc_sessionPropose`.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#approving-a-session-response>
///
/// > All required namespaces MUST be satisfied by a wallet
///
/// The maintained JavaScript helper follows the same data shape: proposal
/// namespaces plus wallet-supported namespaces produce approved session
/// namespaces.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/namespaces.ts#L99-L207>
///
/// > It takes required & optional namespaces provided in the session proposal
/// > along with the supported chains/methods/events/accounts by the wallet and
/// > returns a structured namespaces object
///
/// # Examples
///
/// ```
/// use wc_core::{WalletCapabilities, WalletChainCapability};
/// use wc_protocol::{
///     caip::{Caip10AccountId, Caip2ChainId, NamespaceKey},
///     session::{DappMetadata, JsonRpcRequest, SessionProposeParams},
/// };
///
/// let proposal = serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionPropose",
///   "params": {
///     "id": 1,
///     "expiryTimestamp": 1780000000,
///     "relays": [{"protocol": "irn"}],
///     "proposer": {
///       "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
///       "metadata": {"name": "Dapp", "description": "Dapp", "url": "https://example.com", "icons": []}
///     },
///     "requiredNamespaces": {},
///     "optionalNamespaces": {
///       "eip155": {
///         "chains": ["eip155:1"],
///         "methods": ["personal_sign"],
///         "events": ["accountsChanged"]
///       }
///     }
///   }
/// }"#)?;
///
/// let chain = Caip2ChainId::parse("eip155:1")?;
/// let capability = WalletChainCapability::new(
///     chain,
///     vec![Caip10AccountId::parse("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")?],
///     vec!["personal_sign".parse()?],
///     vec!["accountsChanged".parse()?],
/// )?;
/// let capabilities = WalletCapabilities::new([capability])?;
///
/// let approval = capabilities.plan_session_approval(
///     &proposal,
///     DappMetadata {
///         name: "Wallet".to_owned(),
///         description: "Wallet".to_owned(),
///         url: "https://example.com/wallet".to_owned(),
///         icons: Vec::new(),
///         verify_url: None,
///         redirect: None,
///     },
///     1_780_000_000,
/// )?;
///
/// assert!(approval.namespaces.contains_key(&NamespaceKey::parse("eip155")?));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WalletCapabilities {
    chains: BTreeMap<Caip2ChainId, WalletChainCapability>,
    session_properties: SessionProperties,
    scoped_properties: ScopedProperties,
}

impl WalletCapabilities {
    /// Builds a capability set keyed by CAIP-2 chain ID.
    ///
    /// Duplicate chain entries are merged so callers can compose capabilities
    /// from multiple wallet account sources without widening permissions by
    /// hand.
    pub fn new(
        chains: impl IntoIterator<Item = WalletChainCapability>,
    ) -> Result<Self, WalletCapabilityError> {
        let mut capabilities = Self::default();
        for chain in chains {
            capabilities.insert(chain)?;
        }
        Ok(capabilities)
    }

    /// Inserts or merges one chain capability.
    pub fn insert(&mut self, chain: WalletChainCapability) -> Result<(), WalletCapabilityError> {
        chain.validate()?;
        let entry = self
            .chains
            .entry(chain.chain_id.clone())
            .or_insert_with(|| WalletChainCapability {
                chain_id: chain.chain_id.clone(),
                accounts: Vec::new(),
                methods: Vec::new(),
                events: Vec::new(),
            });

        for account in chain.accounts {
            insert_unique(&mut entry.accounts, account);
        }
        for method in chain.methods {
            insert_unique(&mut entry.methods, method);
        }
        for event in chain.events {
            insert_unique(&mut entry.events, event);
        }

        Ok(())
    }

    /// Returns capabilities for a CAIP-2 chain.
    #[must_use]
    pub fn chain(&self, chain_id: &Caip2ChainId) -> Option<&WalletChainCapability> {
        self.chains.get(chain_id)
    }

    /// Adds wallet-owned session properties available during proposal approval.
    ///
    /// These are capability declarations the wallet is willing to return in
    /// `wc_sessionSettle`. Requested values from the dapp are not echoed.
    ///
    /// <https://docs.walletconnect.network/wallet-sdk/android/eip5792#wallet-response>
    ///
    /// > The wallet’s response should specify the capabilities it supports
    #[must_use]
    pub fn with_session_properties(mut self, session_properties: SessionProperties) -> Self {
        self.session_properties = session_properties;
        self
    }

    /// Adds wallet-owned scoped properties available during proposal approval.
    ///
    /// Scoped properties are keyed by namespace or CAIP-2 chain and are only
    /// returned for scopes that are also approved in session namespaces.
    ///
    /// <https://github.com/ChainAgnostic/namespaces/blob/main/eip155/caip25.md#session-properties>
    ///
    /// > both parties can put such objects in the appropriately-keyed
    /// > `scopedProperties` partition for chain-specific capabilities
    #[must_use]
    pub fn with_scoped_properties(mut self, scoped_properties: ScopedProperties) -> Self {
        self.scoped_properties = scoped_properties;
        self
    }

    /// Plans approval data for a decrypted `wc_sessionPropose` request.
    ///
    /// Required namespaces are all-or-error. Optional namespaces approve the
    /// supported chain/method/event intersection.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#proposal-namespace>
    ///
    /// > There will be two objects that will be included, `requiredNamespaces`
    /// > and `optionalNamespaces`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/namespaces.ts#L132-L207>
    ///
    /// > verify all required namespaces are supported
    ///
    /// > add optional namespaces
    pub fn plan_session_approval(
        &self,
        proposal: &JsonRpcRequest<SessionProposeParams>,
        wallet_metadata: DappMetadata,
        expiry: u64,
    ) -> Result<SessionProposalApproval, ProposalPlanningError> {
        validate_proposal_namespaces(&proposal.params.required_namespaces)?;
        validate_proposal_namespaces(&proposal.params.optional_namespaces)?;

        let mut namespaces = SessionNamespaces::new();
        self.add_proposal_namespaces(
            &proposal.params.required_namespaces,
            ProposalRequirement::Required,
            &mut namespaces,
        )?;
        self.add_proposal_namespaces(
            &proposal.params.optional_namespaces,
            ProposalRequirement::Optional,
            &mut namespaces,
        )?;

        if namespaces.is_empty() {
            return Err(ProposalPlanningError::NoSupportedNamespaces);
        }

        validate_approved_namespaces(&proposal.params.required_namespaces, &namespaces)
            .map_err(|source| ProposalPlanningError::ApprovalNamespaces { source })?;

        let session_properties = plan_session_properties(
            proposal.params.session_properties.as_ref(),
            &self.session_properties,
        )?;
        let scoped_properties = plan_scoped_properties(
            proposal.params.scoped_properties.as_ref(),
            &self.scoped_properties,
            &namespaces,
        )?;

        let mut approval = SessionProposalApproval::new(namespaces, wallet_metadata, expiry);
        approval.session_properties = session_properties;
        approval.scoped_properties = scoped_properties;
        Ok(approval)
    }

    /// Validates a `wc_sessionUpdate` namespace replacement against wallet capabilities.
    ///
    /// Session updates replace the active namespace set. A wallet should only
    /// acknowledge a replacement whose chains, accounts, methods, and events
    /// are all currently supported by the wallet.
    pub fn validate_session_update_namespaces(
        &self,
        namespaces: &SessionNamespaces,
    ) -> Result<(), SessionUpdateApprovalError> {
        validate_session_namespace_shape(namespaces)?;

        for (key, namespace) in namespaces {
            let chains = session_namespace_chains(key, namespace)?;
            for chain_id in chains {
                let capability = self.chains.get(&chain_id).ok_or_else(|| {
                    SessionUpdateApprovalError::MissingChain {
                        chain_id: chain_id.clone(),
                    }
                })?;

                let accounts = namespace
                    .accounts
                    .iter()
                    .filter(|account| account.chain_id() == chain_id)
                    .collect::<Vec<_>>();
                if accounts.is_empty() {
                    return Err(SessionUpdateApprovalError::Namespaces {
                        source: NamespaceValidationError::MissingAccountForChain {
                            chain_id: chain_id.clone(),
                        },
                    });
                }
                for account in accounts {
                    if !capability.accounts.contains(account) {
                        return Err(SessionUpdateApprovalError::UnsupportedAccount {
                            chain_id: chain_id.clone(),
                            account: account.clone(),
                        });
                    }
                }

                for method in &namespace.methods {
                    if !capability.methods.contains(method) {
                        return Err(SessionUpdateApprovalError::UnsupportedMethod {
                            chain_id: chain_id.clone(),
                            method: method.clone(),
                        });
                    }
                }

                for event in &namespace.events {
                    if !capability.events.contains(event) {
                        return Err(SessionUpdateApprovalError::UnsupportedEvent {
                            chain_id: chain_id.clone(),
                            event: event.clone(),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    fn add_proposal_namespaces(
        &self,
        proposal_namespaces: &ProposalNamespaces,
        requirement: ProposalRequirement,
        approved: &mut SessionNamespaces,
    ) -> Result<(), ProposalPlanningError> {
        for (key, namespace) in proposal_namespaces {
            for chain_id in proposal_chains(key, namespace)? {
                match requirement {
                    ProposalRequirement::Required => {
                        match self.satisfied_chain(&chain_id, namespace) {
                            Ok(capability) => {
                                add_required_chain(key, &chain_id, namespace, capability, approved);
                            }
                            Err(unsupported) => {
                                return Err(unsupported.into_required_error(chain_id));
                            }
                        }
                    }
                    ProposalRequirement::Optional => {
                        self.add_optional_chain(key, &chain_id, namespace, approved);
                    }
                }
            }
        }

        Ok(())
    }

    /// Checks all permissions for one required proposal chain.
    ///
    /// Required proposal namespaces are not intersected. Missing chain,
    /// account, method, or event support rejects the whole plan.
    fn satisfied_chain<'a>(
        &'a self,
        chain_id: &Caip2ChainId,
        namespace: &ProposalNamespace,
    ) -> Result<&'a WalletChainCapability, UnsupportedChain> {
        let capability = self.chains.get(chain_id).ok_or(UnsupportedChain::Chain)?;

        if capability.accounts.is_empty() {
            return Err(UnsupportedChain::Accounts);
        }

        for method in &namespace.methods {
            if !capability.methods.contains(method) {
                return Err(UnsupportedChain::Method(method.clone()));
            }
        }

        for event in &namespace.events {
            if !capability.events.contains(event) {
                return Err(UnsupportedChain::Event(event.clone()));
            }
        }

        Ok(capability)
    }

    /// Adds the supported subset for one optional proposal chain.
    ///
    /// Optional methods and events are intersected with wallet capabilities,
    /// matching the maintained helper's `methodsToAdd` and `eventsToAdd`
    /// construction.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/namespaces.ts#L171-L199>
    ///
    /// > const methodsToAdd = supportedNamespaces[optionalNamespace].methods.filter((method) =>
    /// > const eventsToAdd = supportedNamespaces[optionalNamespace].events.filter((event) =>
    fn add_optional_chain(
        &self,
        proposal_key: &NamespaceKey,
        chain_id: &Caip2ChainId,
        namespace: &ProposalNamespace,
        approved: &mut SessionNamespaces,
    ) {
        let Some(capability) = self.chains.get(chain_id) else {
            return;
        };
        if capability.accounts.is_empty() {
            return;
        }

        let supported_methods = namespace
            .methods
            .iter()
            .filter(|method| capability.methods.contains(method))
            .cloned()
            .collect::<Vec<_>>();
        if !namespace.methods.is_empty() && supported_methods.is_empty() {
            return;
        }

        let supported_events = namespace
            .events
            .iter()
            .filter(|event| capability.events.contains(event))
            .cloned()
            .collect::<Vec<_>>();
        if supported_methods.is_empty() && supported_events.is_empty() {
            return;
        }

        add_optional_approval(
            proposal_key,
            chain_id,
            capability,
            &supported_methods,
            &supported_events,
            approved,
        );
    }
}

/// Wallet capability for one CAIP-2 chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletChainCapability {
    chain_id: Caip2ChainId,
    accounts: Vec<Caip10AccountId>,
    methods: Vec<SessionMethod>,
    events: Vec<SessionEventName>,
}

impl WalletChainCapability {
    /// Builds a chain capability and verifies all accounts use the same chain.
    ///
    /// <https://github.com/ChainAgnostic/CAIPs/blob/ebacdb90283ded501350bd0011db4362734f9c4b/CAIPs/caip-10.md#syntax>
    ///
    /// > account_id:        chain_id + ":" + account_address
    pub fn new(
        chain_id: Caip2ChainId,
        accounts: Vec<Caip10AccountId>,
        methods: Vec<SessionMethod>,
        events: Vec<SessionEventName>,
    ) -> Result<Self, WalletCapabilityError> {
        let capability = Self {
            chain_id,
            accounts: dedupe(accounts),
            methods: dedupe(methods),
            events: dedupe(events),
        };
        capability.validate()?;
        Ok(capability)
    }

    /// CAIP-2 chain covered by this capability.
    #[must_use]
    pub const fn chain_id(&self) -> &Caip2ChainId {
        &self.chain_id
    }

    /// CAIP-10 accounts available for approval on this chain.
    #[must_use]
    pub fn accounts(&self) -> &[Caip10AccountId] {
        &self.accounts
    }

    /// JSON-RPC methods this wallet can expose on this chain.
    #[must_use]
    pub fn methods(&self) -> &[SessionMethod] {
        &self.methods
    }

    /// Session events this wallet can expose on this chain.
    #[must_use]
    pub fn events(&self) -> &[SessionEventName] {
        &self.events
    }

    fn validate(&self) -> Result<(), WalletCapabilityError> {
        if self.accounts.is_empty() {
            return Err(WalletCapabilityError::EmptyAccounts {
                chain_id: self.chain_id.clone(),
            });
        }

        for account in &self.accounts {
            if account.chain_id() != self.chain_id {
                return Err(WalletCapabilityError::AccountChainMismatch {
                    chain_id: self.chain_id.clone(),
                    account: account.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Capability construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalletCapabilityError {
    /// A chain capability without accounts cannot approve that chain.
    #[error("wallet capability for chain {chain_id} has no accounts")]
    EmptyAccounts {
        /// Chain with no CAIP-10 accounts.
        chain_id: Caip2ChainId,
    },

    /// A CAIP-10 account belongs to a different chain than the capability key.
    #[error("account {account} does not match wallet capability chain {chain_id}")]
    AccountChainMismatch {
        /// Capability chain.
        chain_id: Caip2ChainId,
        /// Account stored under the wrong chain.
        account: Caip10AccountId,
    },
}

/// Session proposal planning error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProposalPlanningError {
    /// Proposal namespace shape failed protocol validation.
    #[error("session proposal namespace is invalid")]
    ProposalNamespaces {
        /// Source namespace validation error.
        #[source]
        source: NamespaceValidationError,
    },

    /// Planned approved namespaces failed the required-namespace check.
    #[error("planned approved namespaces are invalid")]
    ApprovalNamespaces {
        /// Source namespace validation error.
        #[source]
        source: NamespaceValidationError,
    },

    /// Wallet has no capability for a required CAIP-2 chain.
    #[error("wallet has no capability for required chain {chain_id}")]
    MissingRequiredChain {
        /// Required chain.
        chain_id: Caip2ChainId,
    },

    /// Wallet has no account for a required CAIP-2 chain.
    #[error("wallet has no account for required chain {chain_id}")]
    MissingRequiredAccount {
        /// Required chain.
        chain_id: Caip2ChainId,
    },

    /// Wallet does not support a required method on a required chain.
    #[error("wallet is missing required method {method} for chain {chain_id}")]
    MissingRequiredMethod {
        /// Required chain.
        chain_id: Caip2ChainId,
        /// Required method.
        method: SessionMethod,
    },

    /// Wallet does not support a required event on a required chain.
    #[error("wallet is missing required event {event} for chain {chain_id}")]
    MissingRequiredEvent {
        /// Required chain.
        chain_id: Caip2ChainId,
        /// Required event.
        event: SessionEventName,
    },

    /// No required or optional proposal namespace can be approved.
    #[error("session proposal has no namespaces supported by this wallet")]
    NoSupportedNamespaces,

    /// Dapp requested a required session property the wallet cannot provide.
    #[error("wallet does not support requested session property {property}")]
    UnsupportedSessionProperty {
        /// Unsupported property key.
        property: String,
    },

    /// Dapp requested a required scoped property the wallet cannot provide.
    #[error("wallet does not support requested scoped property {property} for {scope}")]
    UnsupportedScopedProperty {
        /// Top-level scoped property key.
        scope: String,
        /// Unsupported property key within that scope.
        property: String,
    },

    /// Scoped property reduction requires object-shaped request and support values.
    #[error("scoped property value for {scope} must be an object")]
    UnsupportedScopedPropertyShape {
        /// Top-level scoped property key.
        scope: String,
    },
}

/// Session update approval validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionUpdateApprovalError {
    /// Requested replacement namespaces failed protocol shape validation.
    #[error("session update namespaces are invalid")]
    Namespaces {
        /// Source namespace validation error.
        #[source]
        source: NamespaceValidationError,
    },

    /// Wallet has no capability for a requested CAIP-2 chain.
    #[error("wallet has no capability for session update chain {chain_id}")]
    MissingChain {
        /// Requested chain.
        chain_id: Caip2ChainId,
    },

    /// Requested account is not wallet-owned for the chain.
    #[error("wallet does not support session update account {account} for chain {chain_id}")]
    UnsupportedAccount {
        /// Requested chain.
        chain_id: Caip2ChainId,
        /// Unsupported account.
        account: Caip10AccountId,
    },

    /// Requested method is not supported by the wallet for the chain.
    #[error("wallet does not support session update method {method} for chain {chain_id}")]
    UnsupportedMethod {
        /// Requested chain.
        chain_id: Caip2ChainId,
        /// Unsupported method.
        method: SessionMethod,
    },

    /// Requested event is not supported by the wallet for the chain.
    #[error("wallet does not support session update event {event} for chain {chain_id}")]
    UnsupportedEvent {
        /// Requested chain.
        chain_id: Caip2ChainId,
        /// Unsupported event.
        event: SessionEventName,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProposalRequirement {
    Required,
    Optional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnsupportedChain {
    Chain,
    Accounts,
    Method(SessionMethod),
    Event(SessionEventName),
}

impl UnsupportedChain {
    fn into_required_error(self, chain_id: Caip2ChainId) -> ProposalPlanningError {
        match self {
            Self::Chain => ProposalPlanningError::MissingRequiredChain { chain_id },
            Self::Accounts => ProposalPlanningError::MissingRequiredAccount { chain_id },
            Self::Method(method) => {
                ProposalPlanningError::MissingRequiredMethod { chain_id, method }
            }
            Self::Event(event) => ProposalPlanningError::MissingRequiredEvent { chain_id, event },
        }
    }
}

fn validate_proposal_namespaces(
    namespaces: &ProposalNamespaces,
) -> Result<(), ProposalPlanningError> {
    // Reuse the protocol validator for proposal namespace shape while ignoring
    // the expected "not approved yet" errors caused by the empty approved map.
    validate_approved_namespaces(namespaces, &SessionNamespaces::new()).or_else(|error| match error
    {
        NamespaceValidationError::MissingRequiredNamespace { .. }
        | NamespaceValidationError::MissingAccountForChain { .. } => Ok(()),
        source => Err(ProposalPlanningError::ProposalNamespaces { source }),
    })
}

fn validate_session_namespace_shape(
    namespaces: &SessionNamespaces,
) -> Result<(), SessionUpdateApprovalError> {
    validate_approved_namespaces(&ProposalNamespaces::new(), namespaces)
        .map_err(|source| SessionUpdateApprovalError::Namespaces { source })
}

fn session_namespace_chains(
    key: &NamespaceKey,
    namespace: &SessionNamespace,
) -> Result<Vec<Caip2ChainId>, SessionUpdateApprovalError> {
    let mut chains = Vec::new();
    if let Some(chain_id) = key.chain_id() {
        insert_unique(&mut chains, chain_id.clone());
    }

    for chain_id in namespace.chains.iter().flatten() {
        if chain_id.namespace() != key.namespace() {
            return Err(SessionUpdateApprovalError::Namespaces {
                source: NamespaceValidationError::ChainNamespaceMismatch {
                    namespace: namespace_component(key),
                    chain_id: chain_id.clone(),
                },
            });
        }
        insert_unique(&mut chains, chain_id.clone());
    }

    for account in &namespace.accounts {
        insert_unique(&mut chains, account.chain_id());
    }

    Ok(chains)
}

/// Adds a required chain after `satisfied_chain` has checked all permissions.
fn add_required_chain(
    proposal_key: &NamespaceKey,
    chain_id: &Caip2ChainId,
    namespace: &ProposalNamespace,
    capability: &WalletChainCapability,
    approved: &mut SessionNamespaces,
) {
    let approved_key = approval_key(proposal_key, chain_id);
    let entry = approved.entry(approved_key).or_insert(SessionNamespace {
        chains: Some(Vec::new()),
        accounts: Vec::new(),
        methods: Vec::new(),
        events: Vec::new(),
    });

    insert_unique(entry.chains.get_or_insert_with(Vec::new), chain_id.clone());
    for account in &capability.accounts {
        insert_unique(&mut entry.accounts, account.clone());
    }
    for method in &namespace.methods {
        insert_unique(&mut entry.methods, method.clone());
    }
    for event in &namespace.events {
        insert_unique(&mut entry.events, event.clone());
    }
}

/// Adds already-intersected optional permissions for one chain.
fn add_optional_approval(
    proposal_key: &NamespaceKey,
    chain_id: &Caip2ChainId,
    capability: &WalletChainCapability,
    methods: &[SessionMethod],
    events: &[SessionEventName],
    approved: &mut SessionNamespaces,
) {
    let approved_key = approval_key(proposal_key, chain_id);
    let entry = approved.entry(approved_key).or_insert(SessionNamespace {
        chains: Some(Vec::new()),
        accounts: Vec::new(),
        methods: Vec::new(),
        events: Vec::new(),
    });

    insert_unique(entry.chains.get_or_insert_with(Vec::new), chain_id.clone());
    for account in &capability.accounts {
        insert_unique(&mut entry.accounts, account.clone());
    }
    for method in methods {
        insert_unique(&mut entry.methods, method.clone());
    }
    for event in events {
        insert_unique(&mut entry.events, event.clone());
    }
}

fn proposal_chains(
    key: &NamespaceKey,
    namespace: &ProposalNamespace,
) -> Result<Vec<Caip2ChainId>, ProposalPlanningError> {
    if let Some(chain_id) = key.chain_id() {
        return Ok(vec![chain_id.clone()]);
    }

    namespace
        .chains
        .clone()
        .filter(|chains| !chains.is_empty())
        .ok_or_else(|| ProposalPlanningError::ProposalNamespaces {
            source: NamespaceValidationError::MissingChains {
                namespace: namespace_component(key),
            },
        })
}

fn approval_key(proposal_key: &NamespaceKey, chain_id: &Caip2ChainId) -> NamespaceKey {
    if proposal_key.chain_id().is_some() {
        NamespaceKey::ChainId(chain_id.clone())
    } else {
        NamespaceKey::Namespace(namespace_component(proposal_key))
    }
}

fn namespace_component(key: &NamespaceKey) -> CaipNamespace {
    CaipNamespace::parse(key.namespace()).expect("NamespaceKey validates its namespace component")
}

fn plan_session_properties(
    requested: Option<&SessionProperties>,
    supported: &SessionProperties,
) -> Result<Option<SessionProperties>, ProposalPlanningError> {
    let Some(requested) = requested else {
        return Ok(None);
    };

    let mut approved = SessionProperties::new();
    for (property, requested_value) in requested {
        if let Some(supported_value) = supported.get(property) {
            approved.insert(property.clone(), supported_value.clone());
        } else if !is_optional_property(requested_value) {
            return Err(ProposalPlanningError::UnsupportedSessionProperty {
                property: property.clone(),
            });
        }
    }

    Ok(non_empty(approved))
}

fn plan_scoped_properties(
    requested: Option<&ScopedProperties>,
    supported: &ScopedProperties,
    approved_namespaces: &SessionNamespaces,
) -> Result<Option<ScopedProperties>, ProposalPlanningError> {
    let Some(requested) = requested else {
        return Ok(None);
    };

    let mut approved = ScopedProperties::new();
    for (scope, requested_value) in requested {
        let scope_is_approved = is_property_scope_approved(scope, approved_namespaces);
        let Some(supported_value) = supported.get(scope).filter(|_| scope_is_approved) else {
            reject_required_scoped_properties(scope, requested_value)?;
            continue;
        };

        let planned = plan_scoped_property_value(scope, requested_value, supported_value)?;
        if !planned.is_null() {
            approved.insert(scope.clone(), planned);
        }
    }

    Ok(non_empty(approved))
}

fn plan_scoped_property_value(
    scope: &str,
    requested: &Value,
    supported: &Value,
) -> Result<Value, ProposalPlanningError> {
    let requested = RequestedScopedPropertyValue::new(scope, requested)?;
    let supported = SupportedScopedPropertyValue::new(scope, supported)?;

    let mut approved = serde_json::Map::new();
    for (property, requested_value) in requested.properties() {
        if let Some(supported_value) = supported.properties().get(property) {
            approved.insert(property.clone(), supported_value.clone());
        } else if !is_optional_property(requested_value) {
            return Err(ProposalPlanningError::UnsupportedScopedProperty {
                scope: scope.to_owned(),
                property: property.clone(),
            });
        }
    }

    if approved.is_empty() {
        Ok(ApprovedScopedPropertyValue::empty().into_value())
    } else {
        Ok(ApprovedScopedPropertyValue::new(approved).into_value())
    }
}

#[derive(Debug, Clone, Copy)]
struct RequestedScopedPropertyValue<'a> {
    properties: &'a serde_json::Map<String, Value>,
}

impl<'a> RequestedScopedPropertyValue<'a> {
    fn new(scope: &str, value: &'a Value) -> Result<Self, ProposalPlanningError> {
        match value {
            Value::Object(properties) => Ok(Self { properties }),
            _ => Err(ProposalPlanningError::UnsupportedScopedPropertyShape {
                scope: scope.to_owned(),
            }),
        }
    }

    const fn properties(self) -> &'a serde_json::Map<String, Value> {
        self.properties
    }
}

#[derive(Debug, Clone, Copy)]
struct SupportedScopedPropertyValue<'a> {
    properties: &'a serde_json::Map<String, Value>,
}

impl<'a> SupportedScopedPropertyValue<'a> {
    fn new(scope: &str, value: &'a Value) -> Result<Self, ProposalPlanningError> {
        match value {
            Value::Object(properties) => Ok(Self { properties }),
            _ => Err(ProposalPlanningError::UnsupportedScopedPropertyShape {
                scope: scope.to_owned(),
            }),
        }
    }

    const fn properties(self) -> &'a serde_json::Map<String, Value> {
        self.properties
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovedScopedPropertyValue(Value);

impl ApprovedScopedPropertyValue {
    const fn new(properties: serde_json::Map<String, Value>) -> Self {
        Self(Value::Object(properties))
    }

    const fn empty() -> Self {
        Self(Value::Null)
    }

    fn into_value(self) -> Value {
        self.0
    }
}

fn reject_required_scoped_properties(
    scope: &str,
    requested: &Value,
) -> Result<(), ProposalPlanningError> {
    if let Value::Object(properties) = requested {
        if let Some((property, _)) = properties
            .iter()
            .find(|(_property, value)| !is_optional_property(value))
        {
            return Err(ProposalPlanningError::UnsupportedScopedProperty {
                scope: scope.to_owned(),
                property: property.clone(),
            });
        }
        return Ok(());
    }

    if is_optional_property(requested) {
        Ok(())
    } else {
        Err(ProposalPlanningError::UnsupportedScopedProperty {
            scope: scope.to_owned(),
            property: scope.to_owned(),
        })
    }
}

fn is_property_scope_approved(scope: &str, approved_namespaces: &SessionNamespaces) -> bool {
    let Ok(scope_key) = NamespaceKey::parse(scope) else {
        return false;
    };

    if approved_namespaces.contains_key(&scope_key) {
        return true;
    }

    if let Some(chain_id) = scope_key.chain_id() {
        return approved_namespaces.iter().any(|(key, namespace)| {
            key.namespace() == chain_id.namespace()
                && namespace
                    .chains
                    .as_ref()
                    .is_some_and(|chains| chains.contains(chain_id))
        });
    }

    approved_namespaces
        .keys()
        .any(|key| key.namespace() == scope_key.namespace())
}

fn is_optional_property(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("optional"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn non_empty<T>(map: BTreeMap<String, T>) -> Option<BTreeMap<String, T>> {
    if map.is_empty() { None } else { Some(map) }
}

fn dedupe<T>(items: Vec<T>) -> Vec<T>
where
    T: Eq,
{
    let mut deduped = Vec::new();
    for item in items {
        insert_unique(&mut deduped, item);
    }
    deduped
}

fn insert_unique<T>(items: &mut Vec<T>, value: T)
where
    T: Eq,
{
    if !items.contains(&value) {
        items.push(value);
    }
}
