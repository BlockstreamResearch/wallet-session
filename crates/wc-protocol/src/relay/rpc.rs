//! Relay JSON-RPC envelopes and IRN method DTOs.
//!
//! The relay uses JSON-RPC 2.0 with `irn_*` methods for topic subscription,
//! publishing, message delivery, mailbox fetch, and unsubscribe operations.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use super::RelayTopic;

/// JSON-RPC version required by relay envelopes.
pub const JSON_RPC_VERSION: &str = "2.0";

const RPC_ID_ENTROPY_BASE: u64 = 1_000_000;

/// A relay JSON-RPC message ID.
///
/// The relay RPC spec describes message IDs as a timestamp plus random
/// entropy. The live probe uses numeric IDs to match deployed JS clients.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#definitions>
///
/// > id - 19 digit unique identifier. We suggest a 13 digit epoch timestamp plus 6 digit entropy
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/jsonrpc/utils/src/format.ts#L29-L33>
///
/// > const date = BigInt(Date.now()) * BigInt(1000000);
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::RelayRpcId;
///
/// let id = RelayRpcId::from_millis_entropy(1_700_000_000_000, 42)?;
/// assert_eq!(id.as_u64(), 1_700_000_000_000_000_042);
/// # Ok::<(), wc_protocol::relay::RelayRpcIdError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayRpcId(u64);

impl RelayRpcId {
    /// Wraps a numeric relay ID that was already generated or decoded.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Builds an ID from epoch milliseconds and a six-digit entropy value.
    pub fn from_millis_entropy(epoch_millis: u64, entropy: u32) -> Result<Self, RelayRpcIdError> {
        if entropy >= u32::try_from(RPC_ID_ENTROPY_BASE).expect("constant fits in u32") {
            return Err(RelayRpcIdError::EntropyOutOfRange { entropy });
        }

        let value = epoch_millis
            .checked_mul(RPC_ID_ENTROPY_BASE)
            .and_then(|value| value.checked_add(u64::from(entropy)))
            .ok_or(RelayRpcIdError::Overflow)?;

        Ok(Self(value))
    }

    /// Numeric form serialized into the JSON-RPC `id` field.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Checks whether a raw JSON value contains this ID.
    ///
    /// The relay usually returns numeric IDs, but accepting digit strings makes
    /// response matching tolerant while extraction is still early.
    #[must_use]
    pub fn matches_json_value(self, value: Option<&Value>) -> bool {
        match value {
            Some(Value::String(id)) => id.parse::<u64>().ok() == Some(self.0),
            Some(Value::Number(id)) => id.as_u64() == Some(self.0),
            _ => false,
        }
    }
}

impl Serialize for RelayRpcId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for RelayRpcId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = RelayRpcId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a numeric JSON-RPC id or decimal string id")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(RelayRpcId::new(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                value.parse::<u64>().map(RelayRpcId::new).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Relay JSON-RPC ID construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayRpcIdError {
    /// The relay ID layout reserves six decimal digits for entropy.
    #[error("relay rpc id entropy must be less than 1_000_000, got {entropy}")]
    EntropyOutOfRange {
        /// Entropy value passed to `from_millis_entropy`.
        entropy: u32,
    },

    /// `epoch_millis * 1_000_000 + entropy` exceeded `u64`.
    #[error("relay rpc id overflow")]
    Overflow,
}

/// Request params bound to one relay JSON-RPC method.
pub trait RelayRequest {
    /// `irn_*` method emitted in the JSON-RPC request envelope.
    const METHOD: &'static str;
}

/// Relay JSON-RPC request envelope.
///
/// # Examples
///
/// ```
/// use wc_protocol::relay::{IrnSubscribe, RelayJsonRpcRequest, RelayRpcId, RelayTopic};
///
/// let topic = RelayTopic::from_hex("11".repeat(32))?;
/// let request = RelayJsonRpcRequest::new(RelayRpcId::new(1), IrnSubscribe::new(topic));
/// let json = serde_json::to_value(&request)?;
///
/// assert_eq!(json["jsonrpc"], "2.0");
/// assert_eq!(json["method"], "irn_subscribe");
/// assert_eq!(
///     json["params"]["topic"],
///     "1111111111111111111111111111111111111111111111111111111111111111",
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayJsonRpcRequest<T> {
    /// Correlates requests with relay responses and subscription acks.
    pub id: RelayRpcId,
    /// Relay envelopes use JSON-RPC 2.0.
    pub jsonrpc: String,
    /// `irn_*` method selected by the params type.
    pub method: String,
    /// Method-specific relay payload.
    pub params: T,
}

impl<T> RelayJsonRpcRequest<T>
where
    T: RelayRequest,
{
    /// Creates a request envelope for a typed relay method.
    #[must_use]
    pub fn new(id: RelayRpcId, params: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            method: T::METHOD.to_owned(),
            params,
        }
    }
}

impl<T> RelayJsonRpcRequest<T> {
    /// Request ID used for response matching.
    #[must_use]
    pub const fn id(&self) -> RelayRpcId {
        self.id
    }

    /// Relay method stored in the envelope.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }
}

/// Relay JSON-RPC success response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayJsonRpcSuccess<T> {
    /// ID copied from the request being acknowledged.
    pub id: RelayRpcId,
    /// Relay envelopes use JSON-RPC 2.0.
    pub jsonrpc: String,
    /// Method-specific success value.
    pub result: T,
}

impl<T> RelayJsonRpcSuccess<T> {
    /// Builds the success response used when acknowledging relay pushes.
    #[must_use]
    pub fn new(id: RelayRpcId, result: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            result,
        }
    }
}

/// Relay JSON-RPC error response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayJsonRpcErrorResponse {
    /// ID copied from the failed request.
    pub id: RelayRpcId,
    /// Relay envelopes use JSON-RPC 2.0.
    pub jsonrpc: String,
    /// Relay-supplied JSON-RPC error payload.
    pub error: RelayJsonRpcErrorData,
}

/// Relay JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayJsonRpcErrorData {
    /// JSON-RPC error code returned by the relay.
    pub code: i64,
    /// Relay-provided diagnostic text.
    pub message: String,
    /// Relay-provided structured diagnostic data when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Relay JSON-RPC response envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelayJsonRpcResponse<T> {
    /// Response containing a `result` member.
    Success(RelayJsonRpcSuccess<T>),
    /// Response containing an `error` member.
    Error(RelayJsonRpcErrorResponse),
}

impl<T> RelayJsonRpcResponse<T> {
    /// Splits the untagged wire response into success or relay error data.
    pub fn into_result(self) -> Result<T, RelayJsonRpcErrorData> {
        match self {
            Self::Success(success) => Ok(success.result),
            Self::Error(error) => Err(error.error),
        }
    }
}

/// `irn_subscribe` params.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
///
/// > Used when a client subscribes a given topic.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/jsonrpc.ts#L17>
///
/// > subscribe: "irn_subscribe",
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnSubscribe {
    /// Relay routing key to register on the current connection.
    pub topic: RelayTopic,
}

impl IrnSubscribe {
    /// Builds params for `irn_subscribe`.
    #[must_use]
    pub const fn new(topic: RelayTopic) -> Self {
        Self { topic }
    }
}

impl RelayRequest for IrnSubscribe {
    const METHOD: &'static str = "irn_subscribe";
}

/// `irn_publish` params.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#publish>
///
/// > Used when a client publishes a message to a server.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/jsonrpc.ts#L15>
///
/// > publish: "irn_publish",
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/types.ts#L29-L35>
///
/// > topic: string;
/// > message: string;
/// > ttl: number;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnPublish {
    /// Relay routing key that receives the message.
    pub topic: RelayTopic,
    /// Payload string forwarded by the relay without protocol interpretation.
    pub message: String,
    /// Server retention window in seconds.
    pub ttl: u64,
    /// `WalletConnect` message classifier used above the relay layer.
    pub tag: u64,
}

impl IrnPublish {
    /// Builds params for `irn_publish`.
    #[must_use]
    pub fn new(topic: RelayTopic, message: impl Into<String>, ttl: u64, tag: u64) -> Self {
        Self {
            topic,
            message: message.into(),
            ttl,
            tag,
        }
    }
}

impl RelayRequest for IrnPublish {
    const METHOD: &'static str = "irn_publish";
}

/// `irn_subscription` params sent by the relay to a subscriber.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscription>
///
/// > Used when a server sends a subscription message to a client.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/jsonrpc.ts#L19>
///
/// > subscription: "irn_subscription",
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnSubscription {
    /// Subscription ID needed later by `irn_unsubscribe`.
    pub id: String,
    /// Message and delivery metadata.
    pub data: IrnSubscriptionData,
}

impl RelayRequest for IrnSubscription {
    const METHOD: &'static str = "irn_subscription";
}

/// Message data delivered through `irn_subscription`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnSubscriptionData {
    /// Relay routing key that received the push.
    pub topic: RelayTopic,
    /// Payload string originally supplied to `irn_publish`.
    pub message: String,
    /// Relay server publish timestamp in milliseconds.
    #[serde(rename = "publishedAt")]
    pub published_at: u64,
    /// Message classifier; the live relay may omit it on delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u64>,
}

/// `irn_fetchMessages` params.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
///
/// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
///
/// The maintained JavaScript client restores subscriptions with the batch
/// variant. This type models the single-topic server method from the spec.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/jsonrpc.ts#L22>
///
/// > batchFetchMessages: "irn_batchFetchMessages",
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnFetchMessages {
    /// Relay routing key whose pending mailbox is requested.
    pub topic: RelayTopic,
}

impl IrnFetchMessages {
    /// Builds params for `irn_fetchMessages`.
    #[must_use]
    pub const fn new(topic: RelayTopic) -> Self {
        Self { topic }
    }
}

impl RelayRequest for IrnFetchMessages {
    const METHOD: &'static str = "irn_fetchMessages";
}

/// `irn_fetchMessages` result.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
///
/// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnFetchMessagesResponse {
    /// Relay pagination flag for the topic mailbox.
    #[serde(rename = "hasMore")]
    pub has_more: bool,
    /// Messages retained by the relay for this topic.
    pub messages: Vec<IrnSubscriptionData>,
}

/// `irn_unsubscribe` params.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
///
/// > Used when a client unsubscribes a given topic.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/relay/relay-api/src/jsonrpc.ts#L20>
///
/// > unsubscribe: "irn_unsubscribe",
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrnUnsubscribe {
    /// Relay routing key registered by the subscription.
    pub topic: RelayTopic,
    /// Subscription ID returned by `irn_subscribe`.
    pub id: String,
}

impl IrnUnsubscribe {
    /// Builds params for `irn_unsubscribe`.
    #[must_use]
    pub fn new(topic: RelayTopic, id: impl Into<String>) -> Self {
        Self {
            topic,
            id: id.into(),
        }
    }
}

impl RelayRequest for IrnUnsubscribe {
    const METHOD: &'static str = "irn_unsubscribe";
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn request_serializes_with_method_name() {
        let topic = RelayTopic::from_bytes([0x11; 32]);
        let request = RelayJsonRpcRequest::new(RelayRpcId::new(1), IrnSubscribe::new(topic));

        assert_eq!(
            serde_json::to_value(request).expect("request serializes"),
            json!({
                "id": 1,
                "jsonrpc": "2.0",
                "method": "irn_subscribe",
                "params": {
                    "topic": "1111111111111111111111111111111111111111111111111111111111111111",
                },
            })
        );
    }

    #[test]
    fn rpc_id_deserializes_from_number_or_string() {
        assert_eq!(
            serde_json::from_value::<RelayRpcId>(json!(42)).expect("numeric id parses"),
            RelayRpcId::new(42)
        );
        assert_eq!(
            serde_json::from_value::<RelayRpcId>(json!("42")).expect("string id parses"),
            RelayRpcId::new(42)
        );
    }

    #[test]
    fn subscription_deserializes_live_relay_shape() {
        let value = json!({
            "id": 455_626_923_045_889_u64,
            "jsonrpc": "2.0",
            "method": "irn_subscription",
            "params": {
                "id": "99b9a5f9792ca2594dbeb51163162acb08d42956684ee38455573daa07e579b5",
                "data": {
                    "topic": "185355c71cc41c2891b71fdb80d6f13730f78cd8b47bf90e26eae52b55904f4b",
                    "message": "hello",
                    "publishedAt": 1_779_792_668_077_u64,
                },
            },
        });

        let request = serde_json::from_value::<RelayJsonRpcRequest<IrnSubscription>>(value)
            .expect("subscription parses");

        assert_eq!(request.method(), "irn_subscription");
        assert_eq!(request.params.data.message, "hello");
        assert_eq!(request.params.data.tag, None);
    }
}
