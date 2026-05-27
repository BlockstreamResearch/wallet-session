//! Single-connection relay client.

use std::{
    collections::VecDeque,
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use wc_protocol::relay::{
    IrnBatchFetchMessages, IrnBatchFetchMessagesResponse, IrnBatchSubscribe, IrnBatchUnsubscribe,
    IrnFetchMessages, IrnFetchMessagesResponse, IrnPublish, IrnSubscribe, IrnSubscription,
    IrnUnsubscribe, RelayJsonRpcErrorData, RelayJsonRpcRequest, RelayJsonRpcResponse, RelayRequest,
    RelayRpcId, RelayRpcIdError, RelayTopic,
};

use crate::{NativeRelayTransport, TransportError};

static RPC_ENTROPY_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Behavioral relay client over a native WebSocket transport.
///
/// This layer owns relay JSON-RPC IDs, request/response matching, and
/// `irn_subscription` push acknowledgement. Encryption, message DTO parsing,
/// pairing state, and session state remain outside this crate.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#definitions>
///
/// > id - 19 digit unique identifier. We suggest a 13 digit epoch timestamp plus 6 digit entropy
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscription>
///
/// > Used when a server sends a subscription message to a client.
pub struct RelayClient {
    transport: NativeRelayTransport,
    status: u16,
    queued_messages: VecDeque<IrnSubscription>,
}

impl RelayClient {
    /// Opens a relay WebSocket connection and wraps it in a relay client.
    pub async fn connect(url: &str) -> Result<Self, RelayClientError> {
        let connection = NativeRelayTransport::connect(url).await?;
        Ok(Self {
            status: connection.status(),
            transport: connection.into_transport(),
            queued_messages: VecDeque::new(),
        })
    }

    /// HTTP status returned during the WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Subscribes the connection to one relay topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn subscribe(&mut self, topic: RelayTopic) -> Result<String, RelayClientError> {
        self.request(IrnSubscribe::new(topic)).await
    }

    /// Subscribes the connection to multiple relay topics.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#batch-subscribe>
    ///
    /// > Used when a client subscribes multiple topics.
    pub async fn batch_subscribe(
        &mut self,
        topics: Vec<RelayTopic>,
    ) -> Result<Vec<String>, RelayClientError> {
        self.request(IrnBatchSubscribe::new(topics)).await
    }

    /// Publishes an encrypted `WalletConnect` message string to the relay.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#publish>
    ///
    /// > Used when a client publishes a message to a server.
    pub async fn publish(&mut self, params: IrnPublish) -> Result<bool, RelayClientError> {
        self.request(params).await
    }

    /// Fetches retained messages for one relay topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
    pub async fn fetch_messages(
        &mut self,
        topic: RelayTopic,
    ) -> Result<IrnFetchMessagesResponse, RelayClientError> {
        self.request(IrnFetchMessages::new(topic)).await
    }

    /// Fetches retained messages for multiple relay topics.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#batch-fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching multiple topics before subscribing.
    pub async fn batch_fetch_messages(
        &mut self,
        topics: Vec<RelayTopic>,
    ) -> Result<IrnBatchFetchMessagesResponse, RelayClientError> {
        self.request(IrnBatchFetchMessages::new(topics)).await
    }

    /// Unsubscribes the connection from one relay topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
    ///
    /// > Used when a client unsubscribes a given topic.
    pub async fn unsubscribe(
        &mut self,
        topic: RelayTopic,
        subscription_id: impl Into<String>,
    ) -> Result<bool, RelayClientError> {
        self.request(IrnUnsubscribe::new(topic, subscription_id))
            .await
    }

    /// Unsubscribes the connection from multiple relay topics.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#batch-unsubscribe>
    ///
    /// > Used when a client unsubscribes multiple topics.
    pub async fn batch_unsubscribe(
        &mut self,
        subscriptions: Vec<IrnUnsubscribe>,
    ) -> Result<bool, RelayClientError> {
        self.request(IrnBatchUnsubscribe::new(subscriptions)).await
    }

    /// Reads the next acknowledged relay push message.
    ///
    /// Messages received while another request was waiting for its response are
    /// returned before reading additional WebSocket frames.
    pub async fn next_message(&mut self) -> Result<Option<IrnSubscription>, RelayClientError> {
        if let Some(message) = self.queued_messages.pop_front() {
            return Ok(Some(message));
        }

        let Some(value) = self.transport.next_json().await? else {
            return Ok(None);
        };

        if is_subscription(&value) {
            return self.ack_subscription(value).await.map(Some);
        }

        Err(RelayClientError::UnexpectedMessage { value })
    }

    async fn request<T, R>(&mut self, params: T) -> Result<R, RelayClientError>
    where
        T: RelayRequest + Send + Serialize + Sync,
        R: DeserializeOwned + Send,
    {
        let id = next_rpc_id()?;
        let request = RelayJsonRpcRequest::new(id, params);
        self.transport.send_request(&request).await?;
        self.read_response(id).await
    }

    async fn read_response<R>(&mut self, expected_id: RelayRpcId) -> Result<R, RelayClientError>
    where
        R: DeserializeOwned + Send,
    {
        loop {
            let Some(value) = self.transport.next_json().await? else {
                return Err(RelayClientError::StreamEnded);
            };

            if is_subscription(&value) {
                let message = self.ack_subscription(value).await?;
                self.queued_messages.push_back(message);
                continue;
            }

            if !expected_id.matches_json_value(value.get("id")) {
                return Err(RelayClientError::UnexpectedMessage { value });
            }

            let response = serde_json::from_value::<RelayJsonRpcResponse<R>>(value)
                .map_err(|source| RelayClientError::Json { source })?;

            return response.into_result().map_err(Into::into);
        }
    }

    async fn ack_subscription(
        &mut self,
        value: Value,
    ) -> Result<IrnSubscription, RelayClientError> {
        let request = serde_json::from_value::<RelayJsonRpcRequest<IrnSubscription>>(value)
            .map_err(|source| RelayClientError::Json { source })?;
        self.transport.ack_subscription(&request).await?;
        Ok(request.params)
    }
}

/// Relay client failure.
#[derive(Debug, thiserror::Error)]
pub enum RelayClientError {
    /// Native WebSocket transport failed.
    #[error("relay transport failed")]
    Transport {
        /// Source transport error.
        #[from]
        source: TransportError,
    },

    /// Incoming or outgoing JSON did not match the expected relay shape.
    #[error("relay json failed")]
    Json {
        /// Source serde JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// The relay returned a JSON-RPC error response.
    #[error("relay error response: code={code} message={message}")]
    Relay {
        /// Relay JSON-RPC error code.
        code: i64,
        /// Relay JSON-RPC error message.
        message: String,
        /// Relay JSON-RPC error data when provided.
        data: Option<String>,
    },

    /// System clock is before the unix epoch while generating a relay RPC ID.
    #[error("relay rpc id clock failed")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Relay RPC ID construction failed.
    #[error("relay rpc id construction failed")]
    RpcId {
        /// Source relay RPC ID error.
        #[source]
        source: RelayRpcIdError,
    },

    /// The WebSocket stream ended while a relay response was expected.
    #[error("relay stream ended while waiting for response")]
    StreamEnded,

    /// A JSON message was not the expected response or subscription push.
    #[error("unexpected relay message")]
    UnexpectedMessage {
        /// JSON message that was not usable in the current client state.
        value: Value,
    },
}

impl From<RelayJsonRpcErrorData> for RelayClientError {
    fn from(error: RelayJsonRpcErrorData) -> Self {
        Self::Relay {
            code: error.code,
            message: error.message,
            data: error.data,
        }
    }
}

fn next_rpc_id() -> Result<RelayRpcId, RelayClientError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| RelayClientError::Clock { source })?;
    let millis = u64::try_from(now.as_millis()).map_err(|_| RelayClientError::RpcId {
        source: RelayRpcIdError::Overflow,
    })?;
    let counter = RPC_ENTROPY_COUNTER.fetch_add(1, Ordering::Relaxed) % 1_000_000;
    let entropy = (now.subsec_micros() + counter) % 1_000_000;

    RelayRpcId::from_millis_entropy(millis, entropy)
        .map_err(|source| RelayClientError::RpcId { source })
}

fn is_subscription(value: &Value) -> bool {
    value.get("method").and_then(Value::as_str) == Some(<IrnSubscription as RelayRequest>::METHOD)
}
