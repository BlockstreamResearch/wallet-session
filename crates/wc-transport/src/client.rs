//! Single-connection relay client.

use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH},
};

use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::time::{Instant, sleep, timeout_at};
use wc_protocol::relay::{
    IrnBatchFetchMessages, IrnBatchFetchMessagesResponse, IrnBatchSubscribe, IrnBatchUnsubscribe,
    IrnFetchMessages, IrnFetchMessagesResponse, IrnPublish, IrnSubscribe, IrnSubscription,
    IrnUnsubscribe, RelayJsonRpcErrorData, RelayJsonRpcRequest, RelayJsonRpcResponse, RelayRequest,
    RelayRpcId, RelayRpcIdError, RelayTopic,
};

use crate::{
    DEFAULT_MAX_INCOMING_FRAME_BYTES, NativeRelayTransport, NativeRelayTransportConfig,
    TransportError,
};

static RPC_ENTROPY_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Default maximum time a relay request can wait for its matching response.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of acknowledged relay pushes buffered while requests finish.
pub const DEFAULT_MAX_QUEUED_MESSAGES: usize = 1024;

/// Default number of relay pushes processed while one response is pending.
pub const DEFAULT_MAX_PUSHES_WHILE_WAITING: usize = 1024;

/// Default number of WebSocket open attempts for `RelayClient::connect_with_retry`.
pub const DEFAULT_CONNECT_RETRY_ATTEMPTS: NonZeroUsize = NonZeroUsize::new(3).expect("non-zero");

/// Default delay before the first retrying connection attempt.
pub const DEFAULT_CONNECT_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);

/// Default upper bound for retry connection delays.
pub const DEFAULT_CONNECT_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);

/// Bounded exponential retry policy for opening a relay WebSocket.
///
/// This policy only covers connection establishment. Restoring subscriptions
/// after an established connection is lost is a separate runtime decision
/// because resubscribe behavior must respect the active pairing/session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayReconnectConfig {
    /// Total connection attempts, including the first immediate attempt.
    pub max_attempts: NonZeroUsize,
    /// Delay after the first failed attempt.
    pub initial_delay: Duration,
    /// Maximum retry delay after exponential growth.
    pub max_delay: Duration,
}

impl RelayReconnectConfig {
    /// Builds a reconnect policy from explicit attempt and delay bounds.
    #[must_use]
    pub const fn new(
        max_attempts: NonZeroUsize,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        Self {
            max_attempts,
            initial_delay,
            max_delay,
        }
    }

    /// Delay to wait after a failed one-based attempt number.
    ///
    /// Returns `None` when no later attempt is allowed by `max_attempts`.
    #[must_use]
    pub fn delay_after_failure(&self, failed_attempt: NonZeroUsize) -> Option<Duration> {
        if failed_attempt >= self.max_attempts {
            return None;
        }

        let mut delay = self.initial_delay.min(self.max_delay);
        for _ in 1..failed_attempt.get() {
            delay = delay.saturating_mul(2).min(self.max_delay);
        }

        Some(delay)
    }
}

impl Default for RelayReconnectConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_CONNECT_RETRY_ATTEMPTS,
            initial_delay: DEFAULT_CONNECT_RETRY_INITIAL_DELAY,
            max_delay: DEFAULT_CONNECT_RETRY_MAX_DELAY,
        }
    }
}

/// Runtime limits for the single-connection relay client.
///
/// These limits keep relay delivery separate from protocol trust. The client
/// may acknowledge a well-formed `irn_subscription` frame, but the message is
/// only routed when its topic belongs to this connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClientConfig {
    /// Maximum time spent waiting for a response with the matching JSON-RPC ID.
    pub request_timeout: Duration,
    /// Maximum number of relay push messages buffered behind pending requests.
    pub max_queued_messages: usize,
    /// Maximum number of relay push messages handled while one response is pending.
    pub max_pushes_while_waiting: usize,
    /// Maximum WebSocket text or binary frame size accepted from the relay.
    pub max_incoming_frame_bytes: usize,
}

impl Default for RelayClientConfig {
    fn default() -> Self {
        Self {
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            max_queued_messages: DEFAULT_MAX_QUEUED_MESSAGES,
            max_pushes_while_waiting: DEFAULT_MAX_PUSHES_WHILE_WAITING,
            max_incoming_frame_bytes: DEFAULT_MAX_INCOMING_FRAME_BYTES,
        }
    }
}

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
    config: RelayClientConfig,
    subscriptions: HashMap<RelayTopic, String>,
    queued_messages: VecDeque<IrnSubscription>,
}

impl RelayClient {
    /// Opens a relay WebSocket connection and wraps it in a relay client.
    pub async fn connect(url: &str) -> Result<Self, RelayClientError> {
        Self::connect_with_config(url, RelayClientConfig::default()).await
    }

    /// Opens a relay WebSocket connection with explicit runtime limits.
    pub async fn connect_with_config(
        url: &str,
        config: RelayClientConfig,
    ) -> Result<Self, RelayClientError> {
        Self::connect_once(url, config).await.map_err(Into::into)
    }

    /// Opens a relay WebSocket connection using bounded retry/backoff.
    ///
    /// The first attempt is immediate. Later attempts sleep according to
    /// `RelayReconnectConfig::delay_after_failure`.
    pub async fn connect_with_retry(
        url: &str,
        config: RelayClientConfig,
        reconnect: RelayReconnectConfig,
    ) -> Result<Self, RelayClientError> {
        for attempt in 1..=reconnect.max_attempts.get() {
            match Self::connect_once(url, config.clone()).await {
                Ok(client) => return Ok(client),
                Err(source) => {
                    let failed_attempt = NonZeroUsize::new(attempt).expect("range starts at one");
                    let Some(delay) = reconnect.delay_after_failure(failed_attempt) else {
                        return Err(RelayClientError::ConnectRetryExhausted {
                            attempts: reconnect.max_attempts,
                            source,
                        });
                    };
                    sleep(delay).await;
                }
            }
        }

        unreachable!("non-zero max_attempts always enters the loop")
    }

    async fn connect_once(url: &str, config: RelayClientConfig) -> Result<Self, TransportError> {
        let connection = NativeRelayTransport::connect_with_config(
            url,
            NativeRelayTransportConfig {
                max_incoming_frame_bytes: config.max_incoming_frame_bytes,
            },
        )
        .await?;
        Ok(Self {
            status: connection.status(),
            transport: connection.into_transport(),
            config,
            subscriptions: HashMap::new(),
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
        let was_subscribed = self.subscriptions.contains_key(&topic);
        let subscription_id: String = match self
            .request_with_push_topics(
                IrnSubscribe::new(topic.clone()),
                std::slice::from_ref(&topic),
            )
            .await
        {
            Ok(subscription_id) => subscription_id,
            Err(error) => {
                if !was_subscribed {
                    self.remove_queued_topic_messages(&topic);
                }
                return Err(error);
            }
        };
        self.subscriptions.insert(topic, subscription_id.clone());
        Ok(subscription_id)
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
        let new_topics = topics
            .iter()
            .filter(|topic| !self.subscriptions.contains_key(*topic))
            .cloned()
            .collect::<Vec<_>>();
        let subscription_ids: Vec<String> = match self
            .request_with_push_topics(IrnBatchSubscribe::new(topics.clone()), &topics)
            .await
        {
            Ok(subscription_ids) => subscription_ids,
            Err(error) => {
                for topic in &new_topics {
                    self.remove_queued_topic_messages(topic);
                }
                return Err(error);
            }
        };

        if subscription_ids.len() != topics.len() {
            for topic in &new_topics {
                self.remove_queued_topic_messages(topic);
            }
            return Err(RelayClientError::BatchSubscribeLength {
                expected: topics.len(),
                actual: subscription_ids.len(),
            });
        }

        for (topic, subscription_id) in topics.into_iter().zip(subscription_ids.iter()) {
            self.subscriptions.insert(topic, subscription_id.clone());
        }

        Ok(subscription_ids)
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
        topic: &RelayTopic,
    ) -> Result<IrnFetchMessagesResponse, RelayClientError> {
        self.request(IrnFetchMessages::new(topic.clone())).await
    }

    /// Fetches retained messages for multiple relay topics.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#batch-fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching multiple topics before subscribing.
    pub async fn batch_fetch_messages(
        &mut self,
        topics: &[RelayTopic],
    ) -> Result<IrnBatchFetchMessagesResponse, RelayClientError> {
        self.request(IrnBatchFetchMessages::new(topics.to_vec()))
            .await
    }

    /// Unsubscribes the connection from one relay topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
    ///
    /// > Used when a client unsubscribes a given topic.
    pub async fn unsubscribe(
        &mut self,
        topic: &RelayTopic,
        subscription_id: &str,
    ) -> Result<bool, RelayClientError> {
        let acknowledged = self
            .request(IrnUnsubscribe::new(topic.clone(), subscription_id))
            .await?;

        if acknowledged {
            self.remove_subscription(topic);
        }

        Ok(acknowledged)
    }

    /// Unsubscribes the connection from multiple relay topics.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#batch-unsubscribe>
    ///
    /// > Used when a client unsubscribes multiple topics.
    pub async fn batch_unsubscribe(
        &mut self,
        subscriptions: &[IrnUnsubscribe],
    ) -> Result<bool, RelayClientError> {
        let unsubscribed_topics = subscriptions
            .iter()
            .map(|subscription| subscription.topic.clone())
            .collect::<Vec<_>>();
        let acknowledged = self
            .request(IrnBatchUnsubscribe::new(subscriptions.to_vec()))
            .await?;

        if acknowledged {
            for topic in &unsubscribed_topics {
                self.remove_subscription(topic);
            }
        }

        Ok(acknowledged)
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
            let message = self.ack_subscription(value).await?;
            self.ensure_expected_subscription_topic(&message, &[])?;
            return Ok(Some(message));
        }

        Err(RelayClientError::UnexpectedMessage { value })
    }

    /// Reads the next acknowledged relay push for one active topic.
    ///
    /// Pushes for other active topics are acknowledged and kept in the local
    /// queue for later routing.
    pub async fn next_message_for_topic(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<Option<IrnSubscription>, RelayClientError> {
        if let Some(index) = self
            .queued_messages
            .iter()
            .position(|message| &message.data.topic == topic)
        {
            return Ok(self.queued_messages.remove(index));
        }

        loop {
            let Some(value) = self.transport.next_json().await? else {
                return Ok(None);
            };

            if is_subscription(&value) {
                let message = self.ack_subscription(value).await?;
                self.ensure_expected_subscription_topic(&message, &[])?;
                if &message.data.topic == topic {
                    return Ok(Some(message));
                }

                self.queue_message(message)?;
                continue;
            }

            return Err(RelayClientError::UnexpectedMessage { value });
        }
    }

    async fn request<T, R>(&mut self, params: T) -> Result<R, RelayClientError>
    where
        T: RelayRequest + Send + Serialize + Sync,
        R: DeserializeOwned + Send,
    {
        self.request_with_push_topics(params, &[]).await
    }

    /// Sends one request while allowing pushes for topics being subscribed.
    ///
    /// The pending topic list is scoped to this response wait. If the request
    /// fails, `subscribe` and `batch_subscribe` prune any queued messages for
    /// topics that were not already registered.
    async fn request_with_push_topics<T, R>(
        &mut self,
        params: T,
        pending_subscription_topics: &[RelayTopic],
    ) -> Result<R, RelayClientError>
    where
        T: RelayRequest + Send + Serialize + Sync,
        R: DeserializeOwned + Send,
    {
        let id = next_rpc_id()?;
        let request = RelayJsonRpcRequest::new(id, params);
        self.transport.send_request(&request).await?;
        self.read_response(id, pending_subscription_topics).await
    }

    /// Reads until the expected JSON-RPC response arrives or the deadline expires.
    ///
    /// Relay pushes can be interleaved with responses, so the loop acknowledges
    /// and queues authorized `irn_subscription` messages without resetting the
    /// original request deadline.
    async fn read_response<R>(
        &mut self,
        expected_id: RelayRpcId,
        pending_subscription_topics: &[RelayTopic],
    ) -> Result<R, RelayClientError>
    where
        R: DeserializeOwned + Send,
    {
        let deadline = Instant::now() + self.config.request_timeout;
        let mut pushes_while_waiting = 0_usize;

        loop {
            let Some(value) = timeout_at(deadline, self.transport.next_json())
                .await
                .map_err(|_| RelayClientError::RequestTimedOut {
                    timeout: self.config.request_timeout,
                })??
            else {
                return Err(RelayClientError::StreamEnded);
            };

            if is_subscription(&value) {
                if pushes_while_waiting >= self.config.max_pushes_while_waiting {
                    return Err(RelayClientError::PushLimitExceeded {
                        limit: self.config.max_pushes_while_waiting,
                    });
                }

                pushes_while_waiting += 1;
                let message = self.ack_subscription(value).await?;
                self.ensure_expected_subscription_topic(&message, pending_subscription_topics)?;
                self.queue_message(message)?;
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

    /// Acknowledges receipt of one relay subscription frame.
    ///
    /// The ack is only a relay-delivery receipt. Topic routing and higher-level
    /// protocol validation happen after the ack.
    async fn ack_subscription(
        &mut self,
        value: Value,
    ) -> Result<IrnSubscription, RelayClientError> {
        let request = serde_json::from_value::<RelayJsonRpcRequest<IrnSubscription>>(value)
            .map_err(|source| RelayClientError::Json { source })?;
        self.transport.ack_subscription(&request).await?;
        Ok(request.params)
    }

    /// Checks that an acknowledged relay push belongs to this connection.
    fn ensure_expected_subscription_topic(
        &self,
        message: &IrnSubscription,
        pending_subscription_topics: &[RelayTopic],
    ) -> Result<(), RelayClientError> {
        let topic = &message.data.topic;

        if self.subscriptions.contains_key(topic)
            || pending_subscription_topics
                .iter()
                .any(|pending_topic| pending_topic == topic)
        {
            return Ok(());
        }

        Err(RelayClientError::UnexpectedSubscriptionTopic {
            topic: topic.clone(),
        })
    }

    /// Buffers a push that arrived while a request was waiting for its response.
    fn queue_message(&mut self, message: IrnSubscription) -> Result<(), RelayClientError> {
        if self.queued_messages.len() >= self.config.max_queued_messages {
            return Err(RelayClientError::QueueFull {
                limit: self.config.max_queued_messages,
            });
        }

        self.queued_messages.push_back(message);
        Ok(())
    }

    /// Removes active routing and already-buffered pushes for one topic.
    fn remove_subscription(&mut self, topic: &RelayTopic) {
        self.subscriptions.remove(topic);
        self.remove_queued_topic_messages(topic);
    }

    /// Drops buffered pushes for topics that are not active anymore.
    fn remove_queued_topic_messages(&mut self, topic: &RelayTopic) {
        self.queued_messages
            .retain(|message| &message.data.topic != topic);
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

    /// The relay did not send the matching JSON-RPC response before the deadline.
    #[error("relay request timed out after {timeout:?}")]
    RequestTimedOut {
        /// Configured request timeout.
        timeout: Duration,
    },

    /// The relay WebSocket could not be opened after all configured attempts.
    #[error("relay connect retry exhausted after {attempts} attempts")]
    ConnectRetryExhausted {
        /// Number of connection attempts made.
        attempts: NonZeroUsize,
        /// Last connection error.
        #[source]
        source: TransportError,
    },

    /// Too many relay pushes arrived while one JSON-RPC response was pending.
    #[error("relay push limit exceeded while waiting for response")]
    PushLimitExceeded {
        /// Configured push limit for one pending response.
        limit: usize,
    },

    /// A relay push could not be buffered without exceeding the queue limit.
    #[error("relay message queue is full")]
    QueueFull {
        /// Configured maximum queued relay messages.
        limit: usize,
    },

    /// Batch subscribe returned a different number of subscription IDs than topics.
    #[error("relay batch subscribe response length mismatch: expected {expected}, got {actual}")]
    BatchSubscribeLength {
        /// Number of topics sent in `irn_batchSubscribe`.
        expected: usize,
        /// Number of subscription IDs returned by the relay.
        actual: usize,
    },

    /// Relay delivered a subscription message for a topic not owned by this connection.
    #[error("unexpected relay subscription topic")]
    UnexpectedSubscriptionTopic {
        /// Unexpected topic. The display form omits it to avoid accidental routing-key logs.
        topic: RelayTopic,
    },

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
