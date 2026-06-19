use std::fmt;

use wc_protocol::session::{SessionEventName, SessionMethod};

use crate::BitcoinRequestError;

/// Bitcoin JSON-RPC methods defined by `WalletConnect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinMethod {
    /// Signs and broadcasts a single-recipient transfer.
    SendTransfer,
    /// Returns wallet-owned addresses needed by a dapp to monitor UTXOs.
    GetAccountAddresses,
    /// Signs a Partially Signed Bitcoin Transaction.
    SignPsbt,
    /// Signs an arbitrary message with a connected Bitcoin address.
    SignMessage,
}

impl BitcoinMethod {
    /// Wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendTransfer => "sendTransfer",
            Self::GetAccountAddresses => "getAccountAddresses",
            Self::SignPsbt => "signPsbt",
            Self::SignMessage => "signMessage",
        }
    }

    /// Parses a `WalletConnect` Bitcoin method name.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "sendTransfer" => Some(Self::SendTransfer),
            "getAccountAddresses" => Some(Self::GetAccountAddresses),
            "signPsbt" => Some(Self::SignPsbt),
            "signMessage" => Some(Self::SignMessage),
            _ => None,
        }
    }

    /// Returns this method as a generic session method.
    #[must_use]
    pub fn session_method(self) -> SessionMethod {
        SessionMethod::parse(self.as_str()).expect("Bitcoin method constants are non-empty")
    }
}

impl fmt::Display for BitcoinMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl TryFrom<&SessionMethod> for BitcoinMethod {
    type Error = BitcoinRequestError;

    fn try_from(method: &SessionMethod) -> Result<Self, Self::Error> {
        Self::from_wire(method.as_str()).ok_or_else(|| BitcoinRequestError::UnsupportedMethod {
            method: method.as_str().to_owned(),
        })
    }
}

/// Bitcoin session events defined by `WalletConnect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BitcoinEvent {
    /// Connected account address set changed.
    AddressesChanged,
}

impl BitcoinEvent {
    /// Wire event name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddressesChanged => "bip122_addressesChanged",
        }
    }

    /// Returns this event as a generic session event name.
    #[must_use]
    pub fn session_event_name(self) -> SessionEventName {
        SessionEventName::parse(self.as_str()).expect("Bitcoin event constants are non-empty")
    }
}

impl fmt::Display for BitcoinEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
