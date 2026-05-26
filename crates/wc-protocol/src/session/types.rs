//! Shared Sign API session DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::DappMetadata;

/// Approved namespace map keyed by namespace or CAIP-2 chain ID.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L17-L19>
///
/// > type Namespace = BaseNamespace;
/// > type Namespaces = Record<string, Namespace>;
pub type SessionNamespaces = BTreeMap<String, SessionNamespace>;

/// Approved chains, accounts, methods, and events for one namespace.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L10-L15>
///
/// > interface BaseNamespace {
/// > chains?: string[];
/// > accounts: string[];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionNamespace {
    /// Approved CAIP-2 chains under this namespace key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    /// Approved CAIP-10 accounts.
    pub accounts: Vec<String>,
    /// Approved JSON-RPC methods.
    pub methods: Vec<String>,
    /// Approved session events.
    pub events: Vec<String>,
}

/// Participant public key and metadata.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L41-L48>
///
/// > self: {
/// > publicKey: string;
/// > metadata: SignClientTypes.Metadata;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionParticipant {
    /// Participant public key.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Participant metadata suitable for the peer's UI.
    pub metadata: DappMetadata,
}

/// Optional string session properties.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L21-L22>
///
/// > type SessionProperties = ProposalTypes.SessionProperties;
pub type SessionProperties = BTreeMap<String, String>;

/// Optional namespace-scoped properties.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L21-L22>
///
/// > type ScopedProperties = ProposalTypes.ScopedProperties;
pub type ScopedProperties = BTreeMap<String, Value>;

/// Session configuration fields used by current Sign clients.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L24-L26>
///
/// > interface SessionConfig {
/// > disableDeepLink?: boolean;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Disables deep-link behavior when the peer supports that option.
    #[serde(
        rename = "disableDeepLink",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_deep_link: Option<bool>,
}
