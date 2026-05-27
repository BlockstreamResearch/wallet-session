//! Pairing ping DTOs.

use serde::{Deserialize, Serialize};

/// Decrypted `wc_pairingPing` params.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L37-L43>
///
/// > wc_pairingPing: Record<string, unknown>;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L204-L211>
///
/// > const id = await this.sendRequest(topic, "wc_pairingPing", {});
///
/// # Examples
///
/// ```
/// use wc_protocol::dto::pairing::{
///     PairingJsonRpcRequest, PairingMethod, PairingPingParams,
/// };
///
/// let request = PairingJsonRpcRequest::new(
///     1,
///     PairingMethod::Ping,
///     PairingPingParams::default(),
/// );
///
/// let value = serde_json::to_value(request)?;
/// assert_eq!(value["method"], "wc_pairingPing");
/// assert_eq!(value["params"], serde_json::json!({}));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPingParams {}
