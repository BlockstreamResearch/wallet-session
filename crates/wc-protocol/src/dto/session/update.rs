//! Session update DTOs.

use serde::{Deserialize, Serialize};

use super::SessionNamespaces;

/// Decrypted `wc_sessionUpdate` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionupdate>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionupdate>
///
/// > Used to update the namespaces of a session.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L57-L59>
///
/// > wc_sessionUpdate: {
/// > namespaces: SessionTypes.Namespaces;
/// > };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L638-L642>
///
/// > await this.sendRequest({
/// > topic,
/// > method: "wc_sessionUpdate",
/// > params: { namespaces },
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionUpdateParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionUpdate",
///   "params": {
///     "namespaces": {
///       "eip155": {
///         "chains": ["eip155:1"],
///         "accounts": ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
///         "methods": ["personal_sign"],
///         "events": ["accountsChanged"]
///       }
///     }
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionUpdateParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionUpdate);
/// assert_eq!(request.params.namespaces["eip155"].accounts.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionUpdateParams {
    /// Replacement namespaces for the session.
    pub namespaces: SessionNamespaces,
}
