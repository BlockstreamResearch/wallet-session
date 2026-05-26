//! Session request DTOs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub chain_id: String,
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
/// assert_eq!(params.chain_id, "eip155:1");
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
