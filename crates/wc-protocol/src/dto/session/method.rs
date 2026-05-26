//! Sign API method names.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Sign API JSON-RPC method.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods>
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#rpc-methods>
///
/// > This doc should be used as a _source-of-truth_ and reflect the latest
/// > decisions and changes applied to the WalletConnect collection of
/// > client-to-client JSON-RPC methods for all platforms SDKs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignMethod {
    /// Session proposal sent on a pairing topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionpropose>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
    ///
    /// > Used to propose a session through topic A. Requires a success response
    /// > with associated data.
    #[serde(rename = "wc_sessionPropose")]
    SessionPropose,
    /// Session settlement sent after proposal approval.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionsettle>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
    ///
    /// > Used to settle a session over topic B.
    #[serde(rename = "wc_sessionSettle")]
    SessionSettle,
    /// Session namespace update.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionupdate>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionupdate>
    ///
    /// > Used to update the namespaces of a session.
    #[serde(rename = "wc_sessionUpdate")]
    SessionUpdate,
    /// Session expiry extension.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionextend>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionextend>
    ///
    /// > Used to extend the lifetime of a session.
    #[serde(rename = "wc_sessionExtend")]
    SessionExtend,
    /// Session deletion with reason code and message.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessiondelete>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessiondelete>
    ///
    /// > Used to inform the peer to close and delete a session.
    #[serde(rename = "wc_sessionDelete")]
    SessionDelete,
    /// Session liveness ping.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionping>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionping>
    ///
    /// > Used to evaluate if peer is currently online. Timeout at 30 seconds
    #[serde(rename = "wc_sessionPing")]
    SessionPing,
    /// Dapp JSON-RPC request routed through an approved session.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
    ///
    /// > Sends a CAIP-27 request to the peer client.
    #[serde(rename = "wc_sessionRequest")]
    SessionRequest,
    /// Session event routed to the peer.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_event>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_event>
    ///
    /// > This event can be triggered by either the wallet or dapp by calling the
    /// > `emit` method.
    #[serde(rename = "wc_sessionEvent")]
    SessionEvent,
    /// Session authentication request.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionauthenticate>
    ///
    /// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionauthenticate>
    ///
    /// > Used to request authentication signature to a peer through topic P.
    /// > Response is expected on topic R with shared symKey.
    #[serde(rename = "wc_sessionAuthenticate")]
    SessionAuthenticate,
}

impl SignMethod {
    /// Wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionPropose => "wc_sessionPropose",
            Self::SessionSettle => "wc_sessionSettle",
            Self::SessionUpdate => "wc_sessionUpdate",
            Self::SessionExtend => "wc_sessionExtend",
            Self::SessionDelete => "wc_sessionDelete",
            Self::SessionPing => "wc_sessionPing",
            Self::SessionRequest => "wc_sessionRequest",
            Self::SessionEvent => "wc_sessionEvent",
            Self::SessionAuthenticate => "wc_sessionAuthenticate",
        }
    }

    /// Parses a method name without allocating.
    #[must_use]
    pub const fn from_wire(value: &str) -> Option<Self> {
        match value.as_bytes() {
            b"wc_sessionPropose" => Some(Self::SessionPropose),
            b"wc_sessionSettle" => Some(Self::SessionSettle),
            b"wc_sessionUpdate" => Some(Self::SessionUpdate),
            b"wc_sessionExtend" => Some(Self::SessionExtend),
            b"wc_sessionDelete" => Some(Self::SessionDelete),
            b"wc_sessionPing" => Some(Self::SessionPing),
            b"wc_sessionRequest" => Some(Self::SessionRequest),
            b"wc_sessionEvent" => Some(Self::SessionEvent),
            b"wc_sessionAuthenticate" => Some(Self::SessionAuthenticate),
            _ => None,
        }
    }
}

impl fmt::Display for SignMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn sign_method_serializes_and_deserializes_wire_names() {
        assert_eq!(SignMethod::SessionPropose.as_str(), "wc_sessionPropose");
        assert_eq!(
            SignMethod::from_wire("wc_sessionAuthenticate"),
            Some(SignMethod::SessionAuthenticate)
        );
        assert_eq!(SignMethod::from_wire("wc_unknown"), None);
        assert_eq!(
            serde_json::to_value(SignMethod::SessionRequest).expect("serializes"),
            json!("wc_sessionRequest")
        );
        assert_eq!(
            serde_json::from_value::<SignMethod>(json!("wc_sessionEvent")).expect("deserializes"),
            SignMethod::SessionEvent
        );
    }
}
