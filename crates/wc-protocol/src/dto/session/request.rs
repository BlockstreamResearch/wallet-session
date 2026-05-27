//! Session request DTOs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::rpc::{JsonRpcError, JsonRpcErrorResponse, JsonRpcResponse};
use crate::caip::Caip2ChainId;

/// Decrypted `wc_sessionRequest` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
///
/// > Sends a CAIP-27 request to the peer client.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L66-L73>
///
/// > wc_sessionRequest: { request: { method: string; params: any;
/// > expiryTimestamp?: number; }; chainId: string; };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L749-L755>
///
/// > request: {
/// > ...request,
/// > expiryTimestamp: calcExpiry(expiry),
/// > },
/// > chainId,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequestParams {
    /// Requested chain in CAIP-2 format.
    #[serde(rename = "chainId")]
    pub chain_id: Caip2ChainId,
    /// Dapp JSON-RPC request routed through the session.
    pub request: SessionRequest,
}

impl SessionRequestParams {
    /// Uses the nested request expiry because `wc_sessionRequest` has no
    /// separate params-level expiry after decryption.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.request.is_expired_at(now_unix_seconds)
    }
}

/// Chain-specific JSON-RPC request inside `wc_sessionRequest`.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
///
/// > The event includes a `topic` and a `request` object, which will differ
/// > based on the requested action.
///
/// The Sign RPC spec documents the optional request expiry as `expiry`, while
/// the maintained TypeScript Sign Client sends `expiryTimestamp` after applying
/// `calcExpiry`. Decoding accepts both field names; encoding uses
/// `expiryTimestamp`.
///
/// # Examples
///
/// ```
/// use wc_protocol::session::SessionRequestParams;
///
/// let json = r#"{
///   "chainId": "eip155:1",
///   "request": {
///     "method": "personal_sign",
///     "params": [
///       "0x68656c6c6f",
///       "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
///     ],
///     "expiryTimestamp": 1700000300
///   }
/// }"#;
///
/// let params = serde_json::from_str::<SessionRequestParams>(json)?;
/// assert_eq!(params.chain_id.as_str(), "eip155:1");
/// assert_eq!(params.request.method, "personal_sign");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequest {
    /// Chain-specific JSON-RPC method.
    pub method: String,
    /// Chain-specific JSON-RPC params preserved as JSON.
    pub params: Value,
    /// Request expiry timestamp in unix seconds.
    #[serde(
        rename = "expiryTimestamp",
        alias = "expiry",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry_timestamp: Option<u64>,
}

impl SessionRequest {
    /// Treats absent expiry as not expired, matching the Sign RPC indefinite
    /// request rule.
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > If this parameter is not specified, the request is considered
    /// > indefinite.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp
            .is_some_and(|expiry| expiry <= now_unix_seconds)
    }
}

/// Chain-specific result payload for a `wc_sessionRequest` response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
///
/// > // Success result
/// > any
///
/// The maintained Sign Client passes this value unchanged into
/// `formatJsonRpcResult`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1789-L1792>
///
/// > const payload = formatJsonRpcResult(id, result);
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use wc_protocol::session::{
///     SessionRequestResult, session_request_success_response,
/// };
///
/// let response = session_request_success_response(1, json!("0xsignature"));
/// let value = serde_json::to_value(response)?;
/// assert_eq!(value["jsonrpc"], "2.0");
/// assert_eq!(value["result"], "0xsignature");
///
/// let result = SessionRequestResult::new(json!({"transactionHash": "0xabc"}));
/// assert_eq!(result.as_value()["transactionHash"], "0xabc");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionRequestResult(Value);

impl SessionRequestResult {
    /// Wraps the chain-specific JSON-RPC result without normalizing it.
    #[must_use]
    pub const fn new(value: Value) -> Self {
        Self(value)
    }

    /// Borrows the preserved JSON result.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// Unwraps the preserved JSON result.
    #[must_use]
    pub fn into_value(self) -> Value {
        self.0
    }
}

impl From<Value> for SessionRequestResult {
    fn from(value: Value) -> Self {
        Self::new(value)
    }
}

/// JSON-RPC success response for `wc_sessionRequest`.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
///
/// > // Success result
/// > any
pub type SessionRequestResponse = JsonRpcResponse<SessionRequestResult>;

/// JSON-RPC error response for `wc_sessionRequest`.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
///
/// > The client should immediately reject the request and respond an error if
/// > the target session permissions doesn't include the requested method or
/// > chain ID.
pub type SessionRequestErrorResponse = JsonRpcErrorResponse;

/// Builds a `wc_sessionRequest` success response.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L28-L34>
///
/// > export function formatJsonRpcResult<T = any>(id: number, result: T):
/// > JsonRpcResult<T> {
/// > result,
#[must_use]
pub fn session_request_success_response(
    id: u64,
    result: impl Into<Value>,
) -> SessionRequestResponse {
    JsonRpcResponse::new(id, SessionRequestResult::new(result.into()))
}

/// Builds a `wc_sessionRequest` error response.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L36-L45>
///
/// > export function formatJsonRpcError(
/// > error: formatErrorMessage(error, data),
#[must_use]
pub fn session_request_error_response(id: u64, error: JsonRpcError) -> SessionRequestErrorResponse {
    JsonRpcErrorResponse::new(id, error)
}
