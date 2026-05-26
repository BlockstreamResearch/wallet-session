//! Sign API session proposal DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::relay::{JSON_RPC_VERSION, RelayTopic};

/// `wc_sessionPropose` JSON-RPC method name.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L14-L23>
///
/// > export type WcMethod =
/// > | "wc_sessionPropose"
pub const WC_SESSION_PROPOSE_METHOD: &str = "wc_sessionPropose";

/// JSON-RPC request envelope for Sign API methods.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/engine.ts#L52-L58>
///
/// > interface EventCallback<T extends JsonRpcRequest | JsonRpcResponse> {
/// > payload: T;
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{
///     JsonRpcRequest, SessionProposeParams, WC_SESSION_PROPOSE_METHOD,
/// };
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionPropose",
///   "params": {
///     "id": 1,
///     "pairingTopic": "3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb",
///     "expiryTimestamp": 1700000300,
///     "relays": [{"protocol": "irn"}],
///     "proposer": {
///       "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
///       "metadata": {
///         "name": "React App",
///         "description": "React App for WalletConnect",
///         "url": "https://example.com",
///         "icons": ["https://example.com/icon.png"]
///       }
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
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(json)?;
/// assert_eq!(request.method, WC_SESSION_PROPOSE_METHOD);
/// assert_eq!(request.params.effective_id(request.id), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    /// Request identifier used by the Sign API response.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Sign API method name.
    pub method: String,
    /// Method-specific request payload.
    pub params: T,
}

impl<T> JsonRpcRequest<T> {
    /// Builds a Sign API JSON-RPC request envelope.
    #[must_use]
    pub fn new(id: u64, method: impl Into<String>, params: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            method: method.into(),
            params,
        }
    }

    /// Returns true for `wc_sessionPropose`.
    #[must_use]
    pub fn is_session_propose(&self) -> bool {
        self.method == WC_SESSION_PROPOSE_METHOD
    }
}

/// Decrypted `wc_sessionPropose` params.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L21-L45>
///
/// > export interface Struct {
/// > id: number;
/// > expiryTimestamp: number;
/// > relays: RelayerTypes.ProtocolOptions[];
/// > proposer: {
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2116-L2125>
///
/// > const proposal: ProposalTypes.Struct = {
/// > id,
/// > pairingTopic: topic,
/// > expiryTimestamp,
/// > ...params,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProposeParams {
    /// Proposal ID as duplicated inside params by deployed clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Pairing topic as duplicated inside params by deployed clients.
    #[serde(
        rename = "pairingTopic",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pairing_topic: Option<RelayTopic>,
    /// Deprecated proposal expiry field still present in older event examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// Proposal expiry timestamp in unix seconds.
    #[serde(
        rename = "expiryTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry_timestamp: Option<u64>,
    /// Relay protocols the dapp can use for the proposed session.
    pub relays: Vec<RelayProtocolOptions>,
    /// Dapp public key and metadata.
    pub proposer: Proposer,
    /// Proposal namespaces the wallet must satisfy.
    #[serde(rename = "requiredNamespaces", default)]
    pub required_namespaces: ProposalNamespaces,
    /// Proposal namespaces the wallet may satisfy.
    #[serde(rename = "optionalNamespaces", default)]
    pub optional_namespaces: ProposalNamespaces,
    /// Optional string session properties requested by the dapp.
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<BTreeMap<String, String>>,
    /// Optional namespace-scoped properties requested by the dapp.
    #[serde(
        rename = "scopedProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub scoped_properties: Option<BTreeMap<String, Value>>,
    /// Verify attestation attached by the transport, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// Verify encrypted ID attached by the transport, when present.
    #[serde(
        rename = "encryptedId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_id: Option<String>,
    /// Experimental proposal subrequests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ProposalRequests>,
}

impl SessionProposeParams {
    /// Returns the params ID when present, otherwise the JSON-RPC envelope ID.
    #[must_use]
    pub fn effective_id(&self, request_id: u64) -> u64 {
        self.id.unwrap_or(request_id)
    }

    /// Returns `expiryTimestamp`, falling back to the deprecated `expiry`.
    #[must_use]
    pub const fn effective_expiry_timestamp(&self) -> Option<u64> {
        match self.expiry_timestamp {
            Some(expiry_timestamp) => Some(expiry_timestamp),
            None => self.expiry,
        }
    }

    /// Compares the proposal expiry to a caller-provided unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.effective_expiry_timestamp()
            .is_some_and(|expiry| expiry <= now_unix_seconds)
    }
}

/// Proposal namespace map keyed by namespace or CAIP-2 chain ID.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#proposal-namespace>
///
/// > There will be two objects that will be included, `requiredNamespaces` and
/// > `optionalNamespaces`.
pub type ProposalNamespaces = BTreeMap<String, ProposalNamespace>;

/// Methods, events, and optional chains requested for one proposal namespace.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L8-L17>
///
/// > interface BaseRequiredNamespace {
/// > chains?: string[];
/// > methods: string[];
/// > events: string[];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalNamespace {
    /// CAIP-2 chains requested under this namespace key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<String>>,
    /// JSON-RPC methods requested under this namespace key.
    pub methods: Vec<String>,
    /// Session events requested under this namespace key.
    pub events: Vec<String>,
}

/// Relay protocol option used by the proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/relayer.ts#L10-L14>
///
/// > export interface ProtocolOptions {
/// > protocol: string;
/// > data?: string;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayProtocolOptions {
    /// Relay protocol identifier, usually `irn`.
    pub protocol: String,
    /// Protocol-specific relay data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Dapp key and metadata sent in a session proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L29-L32>
///
/// > proposer: {
/// > publicKey: string;
/// > metadata: SignClientTypes.Metadata;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposer {
    /// Dapp public key used later for session key agreement.
    #[serde(rename = "publicKey")]
    pub public_key: String,
    /// Dapp metadata suitable for wallet UI.
    pub metadata: DappMetadata,
}

/// Dapp metadata displayed when the wallet asks the user to approve a proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/core.ts#L29-L40>
///
/// > interface Metadata {
/// > name: string;
/// > description: string;
/// > url: string;
/// > icons: string[];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappMetadata {
    /// Dapp display name.
    pub name: String,
    /// Dapp description.
    pub description: String,
    /// Dapp origin URL.
    pub url: String,
    /// Dapp icon URLs.
    pub icons: Vec<String>,
    /// Verify URL advertised by the dapp.
    #[serde(rename = "verifyUrl", default, skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
    /// Redirect targets advertised by the dapp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<DappRedirect>,
}

/// Optional native or universal redirect targets.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/core.ts#L35-L39>
///
/// > redirect?: {
/// > native?: string;
/// > universal?: string;
/// > linkMode?: boolean;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappRedirect {
    /// Native app redirect URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    /// Universal link redirect URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal: Option<String>,
    /// Link-mode support flag.
    #[serde(rename = "linkMode", default, skip_serializing_if = "Option::is_none")]
    pub link_mode: Option<bool>,
}

/// Experimental proposal subrequests carried by current TypeScript clients.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L41-L44>
///
/// > requests?: {
/// > authentication?: AuthTypes.AuthenticateParams[];
/// > walletPay?: EngineTypes.WalletPayParams;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRequests {
    /// Authentication subrequests are preserved as JSON until modeled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Value>>,
    /// `WalletPay` subrequest is preserved as JSON until modeled.
    #[serde(rename = "walletPay", default, skip_serializing_if = "Option::is_none")]
    pub wallet_pay: Option<Value>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SESSION_PROPOSE_JSON: &str = r#"{
      "id": 1675734656244887,
      "jsonrpc": "2.0",
      "method": "wc_sessionPropose",
      "params": {
        "id": 1675734656244887,
        "pairingTopic": "3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb",
        "expiryTimestamp": 1675734962,
        "requiredNamespaces": {
          "eip155": {
            "methods": [
              "eth_sendTransaction",
              "eth_signTransaction",
              "eth_sign",
              "personal_sign",
              "eth_signTypedData"
            ],
            "chains": ["eip155:5"],
            "events": ["chainChanged", "accountsChanged"]
          }
        },
        "optionalNamespaces": {
          "eip155:42161": {
            "methods": ["personal_sign"],
            "events": ["accountsChanged", "chainChanged"]
          }
        },
        "relays": [{"protocol": "irn"}],
        "proposer": {
          "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
          "metadata": {
            "description": "React App for WalletConnect",
            "url": "http://localhost:3000",
            "icons": ["https://avatars.githubusercontent.com/u/37784886"],
            "name": "React App",
            "redirect": {
              "native": "example://wc",
              "universal": "https://example.com/wc",
              "linkMode": true
            }
          }
        }
      }
    }"#;

    #[test]
    fn session_proposal_deserializes_spec_event_shape() {
        let request =
            serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(SESSION_PROPOSE_JSON)
                .expect("session proposal parses");

        assert!(request.is_session_propose());
        assert_eq!(
            request.params.effective_id(request.id),
            1_675_734_656_244_887
        );
        assert_eq!(
            request.params.effective_expiry_timestamp(),
            Some(1_675_734_962)
        );
        assert_eq!(
            request
                .params
                .pairing_topic
                .as_ref()
                .map(ToString::to_string),
            Some("3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb".to_owned())
        );
        assert_eq!(request.params.relays[0].protocol, "irn");
        assert_eq!(request.params.proposer.metadata.name, "React App");
        assert_eq!(
            request.params.required_namespaces["eip155"]
                .chains
                .as_deref(),
            Some(["eip155:5".to_owned()].as_slice())
        );
        assert_eq!(
            request.params.optional_namespaces["eip155:42161"]
                .chains
                .as_ref(),
            None
        );
        assert!(request.params.is_expired_at(1_700_000_000));
    }

    #[test]
    fn session_proposal_deserializes_wire_shape_without_param_id_or_pairing_topic() {
        let value = json!({
            "id": 42,
            "jsonrpc": "2.0",
            "method": "wc_sessionPropose",
            "params": {
                "expiryTimestamp": 99,
                "relays": [{"protocol": "irn", "data": "relay-data"}],
                "proposer": {
                    "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                    "metadata": {
                        "name": "Example",
                        "description": "Example dapp",
                        "url": "https://example.com",
                        "icons": []
                    }
                },
                "requiredNamespaces": {},
                "optionalNamespaces": {}
            }
        });

        let request =
            serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value).expect("parses");

        assert_eq!(request.params.effective_id(request.id), 42);
        assert_eq!(request.params.pairing_topic, None);
        assert_eq!(request.params.relays[0].data.as_deref(), Some("relay-data"));
    }

    #[test]
    fn session_proposal_uses_deprecated_expiry_fallback() {
        let value = json!({
            "id": 7,
            "jsonrpc": "2.0",
            "method": "wc_sessionPropose",
            "params": {
                "expiry": 88,
                "relays": [{"protocol": "irn"}],
                "proposer": {
                    "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                    "metadata": {
                        "name": "Example",
                        "description": "Example dapp",
                        "url": "https://example.com",
                        "icons": []
                    }
                },
                "requiredNamespaces": {}
            }
        });

        let request =
            serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value).expect("parses");

        assert_eq!(request.params.effective_expiry_timestamp(), Some(88));
        assert!(request.params.optional_namespaces.is_empty());
    }

    #[test]
    fn session_proposal_serializes_current_type_names() {
        let request = JsonRpcRequest::new(
            1,
            WC_SESSION_PROPOSE_METHOD,
            SessionProposeParams {
                id: Some(1),
                pairing_topic: Some(RelayTopic::from_bytes([0x11; 32])),
                expiry: None,
                expiry_timestamp: Some(2),
                relays: vec![RelayProtocolOptions {
                    protocol: "irn".to_owned(),
                    data: None,
                }],
                proposer: Proposer {
                    public_key: "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207"
                        .to_owned(),
                    metadata: DappMetadata {
                        name: "Example".to_owned(),
                        description: "Example dapp".to_owned(),
                        url: "https://example.com".to_owned(),
                        icons: vec![],
                        verify_url: Some("https://verify.example.com".to_owned()),
                        redirect: None,
                    },
                },
                required_namespaces: ProposalNamespaces::new(),
                optional_namespaces: ProposalNamespaces::new(),
                session_properties: Some(BTreeMap::from([(
                    "caip154-mandatory".to_owned(),
                    "true".to_owned(),
                )])),
                scoped_properties: Some(BTreeMap::from([(
                    "eip155:1".to_owned(),
                    json!({"walletService": ["https://example.com"]}),
                )])),
                attestation: Some("attestation-jwt".to_owned()),
                encrypted_id: Some("encrypted-id".to_owned()),
                requests: Some(ProposalRequests {
                    authentication: Some(vec![json!({"chains": ["eip155:1"]})]),
                    wallet_pay: Some(json!({"version": "1"})),
                }),
            },
        );

        let value = serde_json::to_value(request).expect("serializes");

        assert_eq!(value["params"]["expiryTimestamp"], 2);
        assert_eq!(
            value["params"]["pairingTopic"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(
            value["params"]["proposer"]["publicKey"].as_str(),
            Some("a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207")
        );
        assert_eq!(
            value["params"]["proposer"]["metadata"]["verifyUrl"].as_str(),
            Some("https://verify.example.com")
        );
        assert_eq!(
            value["params"]["encryptedId"].as_str(),
            Some("encrypted-id")
        );
        assert!(value["params"].get("expiry").is_none());
    }
}
