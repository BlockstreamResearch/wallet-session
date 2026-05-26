//! Session ping DTOs.

use serde::{Deserialize, Serialize};

/// Decrypted `wc_sessionPing` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionping>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionping>
///
/// > // wc_sessionPing params
/// > {
/// > // empty
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L57-L65>
///
/// > wc_sessionPing: Record<string, unknown>;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L862-L870>
///
/// > this.sendRequest({
/// > topic,
/// > method: "wc_sessionPing",
/// > params: {},
///
/// The peer acknowledges a valid ping with JSON-RPC result `true`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2401-L2411>
///
/// > await this.sendResult<"wc_sessionPing">({
/// > id,
/// > topic,
/// > result: true,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionPingParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionPing",
///   "params": {}
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionPingParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionPing);
/// assert_eq!(request.params, SessionPingParams::default());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPingParams {}
