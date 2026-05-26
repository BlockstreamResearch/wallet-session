//! Sign API JSON-RPC envelopes.

use serde::{Deserialize, Serialize};

use super::SignMethod;
use crate::relay::JSON_RPC_VERSION;

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
///     JsonRpcRequest, SessionProposeParams, SignMethod,
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
/// assert_eq!(request.method, SignMethod::SessionPropose);
/// assert_eq!(request.params.effective_id(request.id), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    /// Request identifier used by the Sign API response.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Sign API method.
    pub method: SignMethod,
    /// Method-specific request payload.
    pub params: T,
}

impl<T> JsonRpcRequest<T> {
    /// Builds a Sign API JSON-RPC request envelope.
    #[must_use]
    pub fn new(id: u64, method: SignMethod, params: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            method,
            params,
        }
    }

    /// Returns true for `wc_sessionPropose`.
    #[must_use]
    pub fn is_session_propose(&self) -> bool {
        self.method == SignMethod::SessionPropose
    }
}
