//! Session settlement DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    RelayProtocolOptions, ScopedProperties, SessionConfig, SessionNamespaces, SessionParticipant,
    SessionProperties,
};

/// Decrypted `wc_sessionSettle` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionsettle>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > Used to settle a session over topic B.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L44-L56>
///
/// > wc_sessionSettle: {
/// > relay: RelayerTypes.ProtocolOptions;
/// > namespaces: SessionTypes.Namespaces;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L482-L491>
///
/// > const sessionSettle = {
/// > relay: { protocol: relayProtocol ?? "irn" },
/// > namespaces,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionSettleParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionSettle",
///   "params": {
///     "relay": {"protocol": "irn"},
///     "namespaces": {
///       "eip155": {
///         "chains": ["eip155:1"],
///         "accounts": ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
///         "methods": ["personal_sign"],
///         "events": ["accountsChanged"]
///       }
///     },
///     "controller": {
///       "publicKey": "316472c516263b72d3b79e1e4a8260e4c2dfbf908c25698fee126c0888ea445f",
///       "metadata": {
///         "name": "Wallet",
///         "description": "Wallet app",
///         "url": "https://example.com/wallet",
///         "icons": []
///       }
///     },
///     "expiry": 1780418257
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionSettleParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionSettle);
/// assert_eq!(request.params.namespaces["eip155"].methods, ["personal_sign"]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSettleParams {
    /// Relay protocol options for the settled session topic.
    pub relay: RelayProtocolOptions,
    /// Approved namespaces with accounts.
    pub namespaces: SessionNamespaces,
    /// Wallet-controlled public key and metadata.
    pub controller: SessionParticipant,
    /// Session expiry timestamp in unix seconds.
    pub expiry: u64,
    /// Optional string session properties.
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<SessionProperties>,
    /// Optional namespace-scoped properties.
    #[serde(
        rename = "scopedProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub scoped_properties: Option<ScopedProperties>,
    /// Optional session configuration currently used by the JavaScript client.
    #[serde(
        rename = "sessionConfig",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_config: Option<SessionConfig>,
    /// Optional Sign API special namespaces from the written RPC method spec.
    #[serde(
        rename = "specialNamespaces",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub special_namespaces: Option<SpecialNamespaces>,
    /// Experimental proposal subrequest responses from the JavaScript client.
    #[serde(
        rename = "proposalRequestsResponses",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub proposal_requests_responses: Option<Value>,
}

impl SessionSettleParams {
    /// Compares the session expiry to a caller-provided unix timestamp.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry <= now_unix_seconds
    }
}

/// Optional special namespace map from the Sign RPC method spec.
pub type SpecialNamespaces = BTreeMap<String, SpecialNamespace>;

/// Special namespace entry without accounts.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > "specialNamespaces": { // optional
/// > "<namespace_name>": {
/// > "methods": [string],
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecialNamespace {
    /// Approved JSON-RPC methods.
    pub methods: Vec<String>,
    /// Approved session events.
    pub events: Vec<String>,
}
