//! Session deletion DTOs.

use serde::{Deserialize, Serialize};

/// Decrypted `wc_sessionDelete` params.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessiondelete>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessiondelete>
///
/// > // wc_sessionDelete params
/// > {
/// > "code": Int64,
/// > "message": string
/// > }
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L61-L64>
///
/// > wc_sessionDelete: {
/// > code: number;
/// > message: string;
/// > };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L898-L910>
///
/// > method: "wc_sessionDelete",
/// > params: getSdkError("USER_DISCONNECTED"),
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcRequest, SessionDeleteParams, SignMethod};
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionDelete",
///   "params": {
///     "message": "User disconnected.",
///     "code": 6000
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionDeleteParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionDelete);
/// assert_eq!(request.params.code, SessionDeleteParams::USER_DISCONNECTED_CODE);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDeleteParams {
    /// Reason code.
    pub code: i64,
    /// Human-readable reason message.
    pub message: String,
}

impl SessionDeleteParams {
    /// SDK-defined reason code sent by the maintained Sign Client for session
    /// disconnects.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/errors.ts#L86-L90>
    ///
    /// > USER_DISCONNECTED: {
    /// > message: "User disconnected.",
    /// > code: 6000,
    /// > },
    pub const USER_DISCONNECTED_CODE: i64 = 6000;

    /// SDK-defined reason message sent by the maintained Sign Client for
    /// session disconnects.
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
