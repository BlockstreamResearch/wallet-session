//! Pairing deletion DTOs.

use serde::{Deserialize, Serialize};

/// Decrypted `wc_pairingDelete` params.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L37-L41>
///
/// > wc_pairingDelete: {
/// > code: number;
/// > message: string;
/// > };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L235-L241>
///
/// > await this.sendRequest(topic, "wc_pairingDelete", getSdkError("USER_DISCONNECTED"));
/// > await this.deletePairing(topic);
///
/// # Examples
///
/// ```
/// use wc_protocol::dto::pairing::PairingDeleteParams;
///
/// let params = PairingDeleteParams::user_disconnected();
/// let value = serde_json::to_value(params)?;
/// assert_eq!(value["code"], PairingDeleteParams::USER_DISCONNECTED_CODE);
/// assert_eq!(value["message"], PairingDeleteParams::USER_DISCONNECTED_MESSAGE);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingDeleteParams {
    /// Reason code.
    pub code: i64,
    /// Human-readable reason message.
    pub message: String,
}

impl PairingDeleteParams {
    /// SDK-defined reason code sent by the maintained Pairing controller for
    /// pairing disconnects.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/errors.ts#L86-L90>
    ///
    /// > USER_DISCONNECTED: {
    /// > message: "User disconnected.",
    /// > code: 6000,
    /// > },
    pub const USER_DISCONNECTED_CODE: i64 = 6000;

    /// SDK-defined reason message sent by the maintained Pairing controller for
    /// pairing disconnects.
    pub const USER_DISCONNECTED_MESSAGE: &str = "User disconnected.";

    /// Builds the SDK-defined user-disconnect reason.
    #[must_use]
    pub fn user_disconnected() -> Self {
        Self {
            code: Self::USER_DISCONNECTED_CODE,
            message: Self::USER_DISCONNECTED_MESSAGE.to_owned(),
        }
    }
}
