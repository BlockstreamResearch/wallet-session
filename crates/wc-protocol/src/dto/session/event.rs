//! Session event DTOs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::SessionEventName;
use crate::caip::Caip2ChainId;

/// Decrypted `wc_sessionEvent` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionevent>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionevent>
///
/// > // wc_sessionEvent params
/// > {
/// > "event": {
/// > "name": string,
/// > "data": any
/// > },
/// > "chainId": string
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L74-L80>
///
/// > wc_sessionEvent: {
/// > event: {
/// > name: string;
/// > data: unknown;
/// > };
/// > chainId: string;
/// > };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L881-L896>
///
/// > await this.sendRequest({
/// > topic,
/// > method: "wc_sessionEvent",
/// > params: { event, chainId },
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionEventParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionEvent",
///   "params": {
///     "event": {
///       "name": "accountsChanged",
///       "data": [
///         "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
///       ]
///     },
///     "chainId": "eip155:1"
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionEventParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionEvent);
/// assert_eq!(request.params.event.name.as_str(), "accountsChanged");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEventParams {
    /// Routed session event.
    pub event: SessionEvent,
    /// Target chain in CAIP-2 format.
    #[serde(rename = "chainId")]
    pub chain_id: Caip2ChainId,
}

/// Chain-specific event payload inside `wc_sessionEvent`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2520-L2539>
///
/// > const memoryKey = `${topic}_session_event_${params.event.name}`;
/// > ...
/// > this.isValidEmit({ topic, ...params });
/// > this.client.events.emit("session_event", { id, topic, params });
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvent {
    /// Namespace-approved event name.
    pub name: SessionEventName,
    /// Event data preserved as JSON because the Sign API leaves the value
    /// chain-specific.
    pub data: Value,
}
