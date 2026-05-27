//! Shared Sign API session DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::{Cacao, DappMetadata, ProposalNamespaces, RelayProtocolOptions};
use crate::{
    caip::{Caip2ChainId, Caip10AccountId, NamespaceKey},
    relay::RelayTopic,
};

/// Stored Sign API session.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L28-L52>
///
/// > interface Struct {
/// > topic: string;
/// > pairingTopic: string;
/// > relay: RelayerTypes.ProtocolOptions;
///
/// Authenticated sessions created by the maintained Sign Client include
/// `authentication` on the wallet side.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375>
///
/// > authentication: auths,
/// > requiredNamespaces: {},
/// > optionalNamespaces: {},
/// > relay: { protocol: "irn" },
/// > pairingTopic: pendingRequest.pairingTopic,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::Session;
///
/// let json = r#"{
///   "topic": "1111111111111111111111111111111111111111111111111111111111111111",
///   "pairingTopic": "2222222222222222222222222222222222222222222222222222222222222222",
///   "relay": {"protocol": "irn"},
///   "expiry": 1780470684,
///   "acknowledged": true,
///   "controller": "wallet-public-key",
///   "namespaces": {
///     "eip155": {
///       "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
///       "chains": ["eip155:1"],
///       "events": ["chainChanged", "accountsChanged"],
///       "methods": ["personal_sign"]
///     }
///   },
///   "requiredNamespaces": {},
///   "optionalNamespaces": {},
///   "self": {
///     "publicKey": "wallet-public-key",
///     "metadata": {"name": "Wallet", "description": "Wallet", "url": "https://example.com/wallet", "icons": []}
///   },
///   "peer": {
///     "publicKey": "dapp-public-key",
///     "metadata": {"name": "Dapp", "description": "Dapp", "url": "https://example.com/dapp", "icons": []}
///   },
///   "transportType": "relay"
/// }"#;
///
/// let session = serde_json::from_str::<Session>(json)?;
/// assert_eq!(session.namespaces["eip155"].methods, ["personal_sign"]);
/// assert!(!session.is_expired_at(1_700_000_000));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Topic used to route encrypted session messages.
    pub topic: RelayTopic,
    /// Pairing topic that introduced the peers.
    #[serde(rename = "pairingTopic")]
    pub pairing_topic: RelayTopic,
    /// Relay protocol options used for session traffic.
    pub relay: RelayProtocolOptions,
    /// Session expiry as unix seconds.
    pub expiry: u64,
    /// Whether the local SDK has acknowledged the session.
    pub acknowledged: bool,
    /// Public key that controls this local session view.
    pub controller: String,
    /// Approved namespaces available to session requests and events.
    pub namespaces: SessionNamespaces,
    /// Required namespaces copied from the proposal.
    #[serde(rename = "requiredNamespaces", default)]
    pub required_namespaces: ProposalNamespaces,
    /// Optional namespaces copied from the proposal.
    #[serde(rename = "optionalNamespaces", default)]
    pub optional_namespaces: ProposalNamespaces,
    /// String session properties copied from approval or proposal state.
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<SessionProperties>,
    /// Namespace-scoped properties copied from approval or proposal state.
    #[serde(
        rename = "scopedProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub scoped_properties: Option<ScopedProperties>,
    /// Session configuration copied from approval state.
    #[serde(
        rename = "sessionConfig",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_config: Option<SessionConfig>,
    /// Local participant stored under the SDK `self` field.
    #[serde(rename = "self")]
    pub self_participant: SessionParticipant,
    /// Remote session participant.
    pub peer: SessionParticipant,
    /// CACAO payloads stored by wallet-side authenticated sessions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Cacao>>,
    /// `WalletPay` result payloads preserved as JSON until modeled.
    #[serde(
        rename = "walletPayResult",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_pay_result: Option<Vec<Value>>,
    /// Transport selected for this session.
    #[serde(
        rename = "transportType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub transport_type: Option<SessionTransportType>,
}

impl Session {
    /// Compares the session expiry to a caller-provided unix timestamp.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry <= now_unix_seconds
    }
}

/// Session transport type stored by current Sign clients.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/relayer.ts#L29-L33>
///
/// > export type TransportType = "relay" | "link_mode";
/// >
/// > export interface SubscribeOptions {
/// > relay?: ProtocolOptions;
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SessionTransportType {
    /// Relay transport.
    Relay,
    /// Link Mode transport.
    LinkMode,
    /// Unknown transport name kept lossless for forward compatibility.
    Other(String),
}

impl SessionTransportType {
    /// Wire name used in SDK session storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Relay => "relay",
            Self::LinkMode => "link_mode",
            Self::Other(value) => value,
        }
    }

    /// Converts a stored transport string into a typed value.
    #[must_use]
    pub fn from_wire(value: impl Into<String>) -> Self {
        let value = value.into();
        match value.as_str() {
            "relay" => Self::Relay,
            "link_mode" => Self::LinkMode,
            _ => Self::Other(value),
        }
    }
}

impl Serialize for SessionTransportType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SessionTransportType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_wire)
    }
}

/// Approved namespace map keyed by namespace or CAIP-2 chain ID.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/session.ts#L17-L19>
///
/// > type Namespace = BaseNamespace;
/// > type Namespaces = Record<string, Namespace>;
pub type SessionNamespaces = BTreeMap<NamespaceKey, SessionNamespace>;

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
    pub chains: Option<Vec<Caip2ChainId>>,
    /// Approved CAIP-10 accounts.
    pub accounts: Vec<Caip10AccountId>,
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
