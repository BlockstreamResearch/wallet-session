//! Chain-scoped session method and event names.

use std::{borrow::Borrow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Chain or namespace method name inside session permissions and requests.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/namespaces.md#proposal-namespace>
///
/// > The namespace proposal outlines the chains, methods and events the dapp is
/// > seeking permission for.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L66-L72>
///
/// > wc_sessionRequest: {
/// > request: {
/// > method: string;
///
/// The maintained JavaScript SDK accepts any non-blank string here.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L332-L335>
///
/// > if (!isValidString(request.method, false)) return false;
///
/// # Examples
///
/// ```
/// use wc_protocol::session::SessionMethod;
///
/// let method = SessionMethod::parse("personal_sign")?;
/// assert_eq!(method.as_str(), "personal_sign");
///
/// let custom = SessionMethod::parse("custom/method")?;
/// assert_eq!(custom.to_string(), "custom/method");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionMethod(String);

impl SessionMethod {
    /// Parses a wire method name.
    ///
    /// The JavaScript validator uses `trim().length` but keeps the original
    /// string in the request or namespace.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L36-L40>
    ///
    /// > return typeof input === "string" && Boolean(input.trim().length);
    pub fn parse(value: impl Into<String>) -> Result<Self, SessionMethodError> {
        let value = parse_non_blank(value.into()).ok_or(SessionMethodError::Empty)?;
        Ok(Self(value))
    }

    /// Borrows the preserved wire method name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the preserved wire method name.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Borrow<str> for SessionMethod {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for SessionMethod {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SessionMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SessionMethod {
    type Err = SessionMethodError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for SessionMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SessionMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Session event name inside session permissions and emitted events.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionevent>
///
/// > "event": {
/// > "name": string,
/// > "data": any
///
/// The maintained JavaScript SDK accepts any non-blank string here.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L346-L349>
///
/// > if (isUndefined(event)) return false;
/// > if (!isValidString(event.name, false)) return false;
///
/// # Examples
///
/// ```
/// use wc_protocol::session::SessionEventName;
///
/// let event = SessionEventName::parse("accountsChanged")?;
/// assert_eq!(event.as_str(), "accountsChanged");
///
/// let custom = SessionEventName::parse("custom/event")?;
/// assert_eq!(custom.to_string(), "custom/event");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionEventName(String);

impl SessionEventName {
    /// Parses a wire event name.
    ///
    /// Namespace validation uses the same non-blank string rule before checking
    /// whether the event exists in the approved namespace.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L370-L377>
    ///
    /// > if (!isValidString(eventName, false)) return false;
    /// > const events = getNamespacesEventsForChainId(namespaces, chainId);
    pub fn parse(value: impl Into<String>) -> Result<Self, SessionEventNameError> {
        let value = parse_non_blank(value.into()).ok_or(SessionEventNameError::Empty)?;
        Ok(Self(value))
    }

    /// Borrows the preserved wire event name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the preserved wire event name.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Borrow<str> for SessionEventName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for SessionEventName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SessionEventName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SessionEventName {
    type Err = SessionEventNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for SessionEventName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SessionEventName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Session method parse failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionMethodError {
    /// Empty or whitespace-only method names fail the same non-blank check as
    /// the JavaScript SDK.
    #[error("session method must contain non-whitespace characters")]
    Empty,
}

/// Session event name parse failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionEventNameError {
    /// Empty or whitespace-only event names fail the same non-blank check as
    /// the JavaScript SDK.
    #[error("session event name must contain non-whitespace characters")]
    Empty,
}

/// Applies the upstream `isValidString(value, false)` shape without trimming.
///
/// The preserved string is important because SDK namespace checks compare the
/// exact wire value with `.includes(...)`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/validators.ts#L360-L367>
///
/// > const methods = getNamespacesMethodsForChainId(namespaces, chainId);
/// > return methods.includes(method);
fn parse_non_blank(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn session_method_preserves_non_blank_wire_value() {
        let method = SessionMethod::parse(" custom/method ").expect("method parses");

        assert_eq!(method.as_str(), " custom/method ");
        assert_eq!(method.to_string(), " custom/method ");
        assert_eq!(
            serde_json::to_value(&method).expect("serializes"),
            json!(" custom/method ")
        );
        assert_eq!(
            serde_json::from_value::<SessionMethod>(json!("personal_sign"))
                .expect("deserializes")
                .as_str(),
            "personal_sign"
        );
    }

    #[test]
    fn session_event_name_preserves_non_blank_wire_value() {
        let event = SessionEventName::parse(" custom/event ").expect("event parses");

        assert_eq!(event.as_str(), " custom/event ");
        assert_eq!(event.to_string(), " custom/event ");
        assert_eq!(
            serde_json::to_value(&event).expect("serializes"),
            json!(" custom/event ")
        );
        assert_eq!(
            serde_json::from_value::<SessionEventName>(json!("accountsChanged"))
                .expect("deserializes")
                .as_str(),
            "accountsChanged"
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_only_names() {
        assert_eq!(
            SessionMethod::parse("").expect_err("empty method fails"),
            SessionMethodError::Empty
        );
        assert_eq!(
            SessionMethod::parse(" \t\n").expect_err("blank method fails"),
            SessionMethodError::Empty
        );
        assert_eq!(
            SessionEventName::parse("").expect_err("empty event fails"),
            SessionEventNameError::Empty
        );
        assert_eq!(
            SessionEventName::parse(" \t\n").expect_err("blank event fails"),
            SessionEventNameError::Empty
        );
    }
}
