//! Session extension DTOs.

use serde::{Deserialize, Serialize};

/// Decrypted `wc_sessionExtend` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionextend>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionextend>
///
/// > Used to extend the lifetime of a session.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L57-L60>
///
/// > wc_sessionExtend: Record<string, unknown>;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L678-L683>
///
/// > await this.setExpiry(topic, calcExpiry(SESSION_EXPIRY));
/// > this.sendRequest({
/// > method: "wc_sessionExtend",
/// > params: {},
///
/// TODO: The written spec includes `expiry`, while current Sign Client traffic sends an empty object and updates expiry from local session state.
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionExtendParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionExtend",
///   "params": {}
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionExtendParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionExtend);
/// assert_eq!(request.params.expiry, None);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionExtendParams {
    /// Optional absolute expiry timestamp from the written Sign RPC spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
}

impl SessionExtendParams {
    /// Treats absent expiry as not expired because current SDK traffic does not
    /// carry the new expiry in request params.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        match self.expiry {
            Some(expiry) => expiry <= now_unix_seconds,
            None => false,
        }
    }
}
