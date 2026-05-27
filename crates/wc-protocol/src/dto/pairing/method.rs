//! Pairing API method names.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Pairing API JSON-RPC method.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L27-L33>
///
/// > type WcMethod = "wc_pairingDelete" | "wc_pairingPing";
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PairingMethod {
    /// Pairing deletion request.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L235-L241>
    ///
    /// > await this.sendRequest(topic, "wc_pairingDelete", getSdkError("USER_DISCONNECTED"));
    #[serde(rename = "wc_pairingDelete")]
    Delete,
    /// Pairing liveness ping.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L204-L211>
    ///
    /// > const id = await this.sendRequest(topic, "wc_pairingPing", {});
    #[serde(rename = "wc_pairingPing")]
    Ping,
}

impl PairingMethod {
    /// Wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "wc_pairingDelete",
            Self::Ping => "wc_pairingPing",
        }
    }

    /// Parses a method name without allocating.
    #[must_use]
    pub const fn from_wire(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"wc_pairingDelete" => Some(Self::Delete),
            b"wc_pairingPing" => Some(Self::Ping),
            _ => None,
        }
    }
}

impl fmt::Display for PairingMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn pairing_method_serializes_and_deserializes_wire_names() {
        assert_eq!(PairingMethod::Delete.as_str(), "wc_pairingDelete");
        assert_eq!(
            PairingMethod::from_wire("wc_pairingPing"),
            Some(PairingMethod::Ping)
        );
        assert_eq!(PairingMethod::from_wire("wc_unknown"), None);
        assert_eq!(
            serde_json::to_value(PairingMethod::Ping).expect("serializes"),
            json!("wc_pairingPing")
        );
        assert_eq!(
            serde_json::from_value::<PairingMethod>(json!("wc_pairingDelete"))
                .expect("deserializes"),
            PairingMethod::Delete
        );
    }
}
