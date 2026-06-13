//! Session namespace update review primitives.

use std::collections::{BTreeMap, BTreeSet};

use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, NamespaceKey},
    relay::RelayTopic,
    session::{
        SessionEventName, SessionMethod, SessionNamespace, SessionNamespaces, SessionUpdateParams,
    },
};

/// Permission-level diff between current and requested session namespaces.
///
/// `wc_sessionUpdate` replaces namespaces, which can add accounts, chains,
/// methods, or events to an active session. Callers can use this diff before
/// approving the update.
///
/// <https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session>
///
/// > include new accounts or chains or methods in an existing session
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L638-L650>
///
/// > method: "wc_sessionUpdate",
/// > params: { namespaces },
///
/// # Examples
///
/// ```
/// use wc_core::diff_session_namespaces;
/// use wc_protocol::{
///     caip::NamespaceKey,
///     session::{SessionNamespace, SessionNamespaces},
/// };
///
/// let key = NamespaceKey::parse("eip155")?;
/// let current = SessionNamespaces::from([(
///     key.clone(),
///     SessionNamespace {
///         chains: Some(vec!["eip155:1".parse()?]),
///         accounts: vec!["eip155:1:0x1111111111111111111111111111111111111111".parse()?],
///         methods: vec!["personal_sign".parse()?],
///         events: vec!["accountsChanged".parse()?],
///     },
/// )]);
/// let requested = SessionNamespaces::from([(
///     key.clone(),
///     SessionNamespace {
///         chains: Some(vec!["eip155:1".parse()?]),
///         accounts: vec![
///             "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
///             "eip155:1:0x2222222222222222222222222222222222222222".parse()?,
///         ],
///         methods: vec!["personal_sign".parse()?],
///         events: vec!["accountsChanged".parse()?],
///     },
/// )]);
///
/// let diff = diff_session_namespaces(&current, &requested);
/// assert!(diff.has_additions());
/// assert_eq!(diff.added().namespaces()[&key].accounts().len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionNamespacesDiff {
    added: SessionNamespacePermissionSet,
    removed: SessionNamespacePermissionSet,
}

impl SessionNamespacesDiff {
    /// Builds a diff from active namespaces to requested replacement namespaces.
    #[must_use]
    pub fn between(current: &SessionNamespaces, requested: &SessionNamespaces) -> Self {
        diff_session_namespaces(current, requested)
    }

    /// Permissions present in requested namespaces but not current namespaces.
    #[must_use]
    pub const fn added(&self) -> &SessionNamespacePermissionSet {
        &self.added
    }

    /// Permissions present in current namespaces but not requested namespaces.
    #[must_use]
    pub const fn removed(&self) -> &SessionNamespacePermissionSet {
        &self.removed
    }

    /// No permission fields changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    /// Requested namespaces add at least one chain, account, method, or event.
    #[must_use]
    pub fn has_additions(&self) -> bool {
        !self.added.is_empty()
    }

    /// Requested namespaces remove at least one chain, account, method, or event.
    #[must_use]
    pub fn has_removals(&self) -> bool {
        !self.removed.is_empty()
    }
}

/// Wallet-facing review data for a pending `wc_sessionUpdate`.
///
/// `wc_sessionUpdate` replaces the active namespace set. This review keeps the
/// current namespaces, requested replacement, and computed diff together so a
/// wallet UI can show exactly what approval would change before acknowledging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionUpdateReview {
    topic: RelayTopic,
    request_id: u64,
    current_namespaces: SessionNamespaces,
    requested_namespaces: SessionNamespaces,
    diff: SessionNamespacesDiff,
}

impl SessionUpdateReview {
    /// Builds review data from active and requested namespaces.
    #[must_use]
    pub fn new(
        topic: RelayTopic,
        request_id: u64,
        current_namespaces: SessionNamespaces,
        requested_namespaces: SessionNamespaces,
    ) -> Self {
        let diff = diff_session_namespaces(&current_namespaces, &requested_namespaces);
        Self {
            topic,
            request_id,
            current_namespaces,
            requested_namespaces,
            diff,
        }
    }

    /// Active session topic receiving the update.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request id from `wc_sessionUpdate`.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Namespaces currently stored on the active session.
    #[must_use]
    pub const fn current_namespaces(&self) -> &SessionNamespaces {
        &self.current_namespaces
    }

    /// Replacement namespaces requested by the peer.
    #[must_use]
    pub const fn requested_namespaces(&self) -> &SessionNamespaces {
        &self.requested_namespaces
    }

    /// Permission-level diff from current to requested namespaces.
    #[must_use]
    pub const fn diff(&self) -> &SessionNamespacesDiff {
        &self.diff
    }

    /// Typed params that would be acknowledged if this update is approved.
    #[must_use]
    pub fn requested_params(&self) -> SessionUpdateParams {
        SessionUpdateParams {
            namespaces: self.requested_namespaces.clone(),
        }
    }
}

/// Namespace-keyed set of changed permissions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionNamespacePermissionSet {
    namespaces: BTreeMap<NamespaceKey, SessionNamespacePermissions>,
}

impl SessionNamespacePermissionSet {
    /// Changed permissions by namespace key.
    #[must_use]
    pub const fn namespaces(&self) -> &BTreeMap<NamespaceKey, SessionNamespacePermissions> {
        &self.namespaces
    }

    /// No namespace key has changed permissions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespaces.is_empty()
    }
}

/// Changed chains, accounts, methods, and events for one namespace key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionNamespacePermissions {
    chains: Vec<Caip2ChainId>,
    accounts: Vec<Caip10AccountId>,
    methods: Vec<SessionMethod>,
    events: Vec<SessionEventName>,
}

impl SessionNamespacePermissions {
    /// Changed CAIP-2 chains.
    #[must_use]
    pub fn chains(&self) -> &[Caip2ChainId] {
        &self.chains
    }

    /// Changed CAIP-10 accounts.
    #[must_use]
    pub fn accounts(&self) -> &[Caip10AccountId] {
        &self.accounts
    }

    /// Changed JSON-RPC methods.
    #[must_use]
    pub fn methods(&self) -> &[SessionMethod] {
        &self.methods
    }

    /// Changed session events.
    #[must_use]
    pub fn events(&self) -> &[SessionEventName] {
        &self.events
    }

    fn is_empty(&self) -> bool {
        self.chains.is_empty()
            && self.accounts.is_empty()
            && self.methods.is_empty()
            && self.events.is_empty()
    }
}

/// Computes added and removed permissions for a `wc_sessionUpdate`.
///
/// The diff treats each namespace list as a set. Duplicates in the wire payload
/// do not grant a second permission and should not produce review noise.
#[must_use]
pub fn diff_session_namespaces(
    current: &SessionNamespaces,
    requested: &SessionNamespaces,
) -> SessionNamespacesDiff {
    let keys = current
        .keys()
        .chain(requested.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut added = BTreeMap::new();
    let mut removed = BTreeMap::new();

    for key in keys {
        let current_permissions = current
            .get(&key)
            .map_or_else(SessionNamespacePermissions::default, |namespace| {
                namespace_permissions(&key, namespace)
            });
        let requested_permissions = requested
            .get(&key)
            .map_or_else(SessionNamespacePermissions::default, |namespace| {
                namespace_permissions(&key, namespace)
            });

        let added_permissions = permission_difference(&requested_permissions, &current_permissions);
        if !added_permissions.is_empty() {
            added.insert(key.clone(), added_permissions);
        }

        let removed_permissions =
            permission_difference(&current_permissions, &requested_permissions);
        if !removed_permissions.is_empty() {
            removed.insert(key, removed_permissions);
        }
    }

    SessionNamespacesDiff {
        added: SessionNamespacePermissionSet { namespaces: added },
        removed: SessionNamespacePermissionSet {
            namespaces: removed,
        },
    }
}

fn namespace_permissions(
    key: &NamespaceKey,
    namespace: &SessionNamespace,
) -> SessionNamespacePermissions {
    let mut chains = namespace
        .chains
        .iter()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    if let Some(chain_id) = key.chain_id() {
        chains.insert(chain_id.clone());
    }

    SessionNamespacePermissions {
        chains: chains.into_iter().collect(),
        accounts: namespace
            .accounts
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        methods: namespace
            .methods
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        events: namespace
            .events
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

fn permission_difference(
    left: &SessionNamespacePermissions,
    right: &SessionNamespacePermissions,
) -> SessionNamespacePermissions {
    SessionNamespacePermissions {
        chains: difference(&left.chains, &right.chains),
        accounts: difference(&left.accounts, &right.accounts),
        methods: difference(&left.methods, &right.methods),
        events: difference(&left.events, &right.events),
    }
}

fn difference<T>(left: &[T], right: &[T]) -> Vec<T>
where
    T: Clone + Ord,
{
    let right = right.iter().collect::<BTreeSet<_>>();
    left.iter()
        .filter(|value| !right.contains(value))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use wc_protocol::{
        caip::NamespaceKey,
        session::{SessionNamespace, SessionNamespaces},
    };

    use super::diff_session_namespaces;

    #[test]
    fn unchanged_namespaces_have_empty_diff() -> Result<(), Box<dyn std::error::Error>> {
        let namespaces = SessionNamespaces::from([(
            NamespaceKey::parse("eip155")?,
            namespace(
                &["eip155:1"],
                &["eip155:1:0x1111111111111111111111111111111111111111"],
                &["personal_sign"],
                &["accountsChanged"],
            )?,
        )]);

        let diff = diff_session_namespaces(&namespaces, &namespaces);

        assert!(diff.is_empty());
        assert!(!diff.has_additions());
        assert!(!diff.has_removals());

        Ok(())
    }

    #[test]
    fn detects_added_and_removed_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let key = NamespaceKey::parse("eip155")?;
        let current = SessionNamespaces::from([(
            key.clone(),
            namespace(
                &["eip155:1"],
                &["eip155:1:0x1111111111111111111111111111111111111111"],
                &["personal_sign", "eth_signTypedData"],
                &["accountsChanged"],
            )?,
        )]);
        let requested = SessionNamespaces::from([(
            key.clone(),
            namespace(
                &["eip155:1", "eip155:137"],
                &[
                    "eip155:1:0x2222222222222222222222222222222222222222",
                    "eip155:137:0x3333333333333333333333333333333333333333",
                ],
                &["personal_sign", "eth_sendTransaction"],
                &["chainChanged"],
            )?,
        )]);

        let diff = diff_session_namespaces(&current, &requested);
        let added = &diff.added().namespaces()[&key];
        let removed = &diff.removed().namespaces()[&key];

        assert_eq!(added.chains().len(), 1);
        assert_eq!(added.accounts().len(), 2);
        assert_eq!(added.methods().len(), 1);
        assert_eq!(added.events().len(), 1);
        assert_eq!(removed.chains().len(), 0);
        assert_eq!(removed.accounts().len(), 1);
        assert_eq!(removed.methods().len(), 1);
        assert_eq!(removed.events().len(), 1);

        Ok(())
    }

    #[test]
    fn treats_duplicate_values_as_one_permission() -> Result<(), Box<dyn std::error::Error>> {
        let key = NamespaceKey::parse("eip155")?;
        let current = SessionNamespaces::new();
        let requested = SessionNamespaces::from([(
            key.clone(),
            namespace(
                &["eip155:1", "eip155:1"],
                &[
                    "eip155:1:0x1111111111111111111111111111111111111111",
                    "eip155:1:0x1111111111111111111111111111111111111111",
                ],
                &["personal_sign", "personal_sign"],
                &["accountsChanged", "accountsChanged"],
            )?,
        )]);

        let diff = diff_session_namespaces(&current, &requested);
        let added = &diff.added().namespaces()[&key];

        assert_eq!(added.chains().len(), 1);
        assert_eq!(added.accounts().len(), 1);
        assert_eq!(added.methods().len(), 1);
        assert_eq!(added.events().len(), 1);

        Ok(())
    }

    #[test]
    fn chain_specific_key_counts_as_chain_permission() -> Result<(), Box<dyn std::error::Error>> {
        let key = NamespaceKey::parse("eip155:1")?;
        let current = SessionNamespaces::new();
        let requested = SessionNamespaces::from([(
            key.clone(),
            namespace(
                &[],
                &["eip155:1:0x1111111111111111111111111111111111111111"],
                &["personal_sign"],
                &[],
            )?,
        )]);

        let diff = diff_session_namespaces(&current, &requested);

        assert_eq!(
            diff.added().namespaces()[&key].chains()[0].as_str(),
            "eip155:1"
        );

        Ok(())
    }

    fn namespace(
        chains: &[&str],
        accounts: &[&str],
        methods: &[&str],
        events: &[&str],
    ) -> Result<SessionNamespace, Box<dyn std::error::Error>> {
        Ok(SessionNamespace {
            chains: if chains.is_empty() {
                None
            } else {
                Some(
                    chains
                        .iter()
                        .map(|chain| chain.parse())
                        .collect::<Result<_, _>>()?,
                )
            },
            accounts: accounts
                .iter()
                .map(|account| account.parse())
                .collect::<Result<_, _>>()?,
            methods: methods
                .iter()
                .map(|method| method.parse())
                .collect::<Result<_, _>>()?,
            events: events
                .iter()
                .map(|event| event.parse())
                .collect::<Result<_, _>>()?,
        })
    }
}
