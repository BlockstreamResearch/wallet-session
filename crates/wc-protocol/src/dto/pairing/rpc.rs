//! Pairing API JSON-RPC envelopes.

use serde::{Deserialize, Serialize};

use super::PairingMethod;
use crate::relay::JSON_RPC_VERSION;

/// JSON-RPC request envelope for Pairing API methods.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L112-L117>
///
/// > sendRequest<M extends PairingJsonRpcTypes.WcMethod>(
/// > topic: string,
/// > method: M,
/// > params: PairingJsonRpcTypes.RequestParams[M],
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L262-L268>
///
/// > const payload = formatJsonRpcRequest(method, params);
/// > const message = await this.core.crypto.encode(topic, payload);
///
/// # Examples
///
/// ```
/// use wc_protocol::dto::pairing::{
///     PairingJsonRpcRequest, PairingMethod, PairingPingParams,
/// };
///
/// let json = r#"{
///   "id": 1779866795062281,
///   "jsonrpc": "2.0",
///   "method": "wc_pairingPing",
///   "params": {}
/// }"#;
///
/// let request = serde_json::from_str::<PairingJsonRpcRequest<PairingPingParams>>(json)?;
/// assert_eq!(request.method, PairingMethod::Ping);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingJsonRpcRequest<T> {
    /// Request identifier used by the Pairing API response.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Pairing API method.
    pub method: PairingMethod,
    /// Method-specific request payload.
    pub params: T,
}

impl<T> PairingJsonRpcRequest<T> {
    /// Builds a Pairing API JSON-RPC request envelope.
    #[must_use]
    pub fn new(id: u64, method: PairingMethod, params: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            method,
            params,
        }
    }

    /// Classifies an already-deserialized Pairing request as `wc_pairingPing`.
    #[must_use]
    pub fn is_pairing_ping(&self) -> bool {
        self.method == PairingMethod::Ping
    }

    /// Classifies an already-deserialized Pairing request as `wc_pairingDelete`.
    #[must_use]
    pub fn is_pairing_delete(&self) -> bool {
        self.method == PairingMethod::Delete
    }
}

/// JSON-RPC success response envelope for Pairing API methods.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L45-L49>
///
/// > interface Results {
/// > wc_pairingDelete: true;
/// > wc_pairingPing: true;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L379-L385>
///
/// > await this.sendResult<"wc_pairingPing">(id, topic, true);
/// > this.events.emit(PAIRING_EVENTS.ping, { id, topic });
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingJsonRpcResponse<T> {
    /// Request identifier from the answered Pairing API request.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Method-specific success payload.
    pub result: T,
}

impl<T> PairingJsonRpcResponse<T> {
    /// Builds a Pairing API JSON-RPC success response envelope.
    #[must_use]
    pub fn new(id: u64, result: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            result,
        }
    }
}
