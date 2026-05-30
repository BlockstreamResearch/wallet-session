use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::time::timeout;
use wc_protocol::relay::{
    IrnBatchFetchMessagesResponse, IrnBatchPublish, IrnFetchMessagesResponse, IrnPublish,
    IrnSubscription, IrnUnsubscribe, RelayJsonRpcResponse, RelayRequest, RelayRpcId, RelayTopic,
};
use wc_transport::{NativeRelayTransport, RelayClient, RelayClientError};

use crate::util::rpc_id;

const READ_TIMEOUT: Duration = Duration::from_secs(20);

pub struct RelaySocket {
    role: &'static str,
    client: RelayClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressedDelivery {
    /// No relay push arrived for the checked topics during the wait window.
    NoDelivery,
    /// A stale relay push arrived after local routing had been removed.
    ///
    /// The relay client acknowledges relay delivery before routing, then rejects
    /// inactive topics. The live harness records this as a dropped stale push
    /// instead of treating the client-side rejection as a probe crash.
    InactiveTopicDropped { topic: RelayTopic },
}

impl RelaySocket {
    pub async fn connect(role: &'static str, url: &str) -> Result<Self> {
        let client = RelayClient::connect(url)
            .await
            .with_context(|| format!("{role} failed to connect to relay"))?;
        println!("{role} connected status={}", client.status());
        Ok(Self { role, client })
    }

    pub async fn subscribe(&mut self, topic: RelayTopic) -> Result<String> {
        println!("{} -> irn_subscribe", self.role);
        let subscription_id = self
            .client
            .subscribe(topic)
            .await
            .with_context(|| format!("{} failed to subscribe relay topic", self.role))?;
        println!("{} <- irn_subscribe result", self.role);
        Ok(subscription_id)
    }

    pub async fn batch_subscribe(&mut self, topics: Vec<RelayTopic>) -> Result<Vec<String>> {
        println!(
            "{} -> irn_batchSubscribe topics={}",
            self.role,
            topics.len()
        );
        let subscription_ids = self
            .client
            .batch_subscribe(topics)
            .await
            .with_context(|| format!("{} failed to batch subscribe relay topics", self.role))?;
        println!("{} <- irn_batchSubscribe result", self.role);
        Ok(subscription_ids)
    }

    pub async fn publish(&mut self, params: IrnPublish) -> Result<bool> {
        println!("{} -> irn_publish", self.role);
        let ack = self
            .client
            .publish(params)
            .await
            .with_context(|| format!("{} failed to publish relay message", self.role))?;
        println!("{} <- irn_publish result={ack}", self.role);
        Ok(ack)
    }

    pub async fn fetch_messages(&mut self, topic: &RelayTopic) -> Result<IrnFetchMessagesResponse> {
        println!("{} -> irn_fetchMessages", self.role);
        let response = self
            .client
            .fetch_messages(topic)
            .await
            .with_context(|| format!("{} failed to fetch relay messages", self.role))?;
        println!("{} <- irn_fetchMessages result", self.role);
        Ok(response)
    }

    pub async fn batch_fetch_messages(
        &mut self,
        topics: &[RelayTopic],
    ) -> Result<IrnBatchFetchMessagesResponse> {
        println!(
            "{} -> irn_batchFetchMessages topics={}",
            self.role,
            topics.len()
        );
        let response = self
            .client
            .batch_fetch_messages(topics)
            .await
            .with_context(|| format!("{} failed to batch fetch relay messages", self.role))?;
        println!("{} <- irn_batchFetchMessages result", self.role);
        Ok(response)
    }

    pub async fn unsubscribe(&mut self, topic: &RelayTopic, subscription_id: &str) -> Result<bool> {
        println!("{} -> irn_unsubscribe", self.role);
        let ack = self
            .client
            .unsubscribe(topic, subscription_id)
            .await
            .with_context(|| format!("{} failed to unsubscribe relay topic", self.role))?;
        println!("{} <- irn_unsubscribe result={ack}", self.role);
        Ok(ack)
    }

    pub async fn batch_unsubscribe(&mut self, subscriptions: &[IrnUnsubscribe]) -> Result<bool> {
        println!(
            "{} -> irn_batchUnsubscribe subscriptions={}",
            self.role,
            subscriptions.len()
        );
        let ack = self
            .client
            .batch_unsubscribe(subscriptions)
            .await
            .with_context(|| format!("{} failed to batch unsubscribe relay topics", self.role))?;
        println!("{} <- irn_batchUnsubscribe result={ack}", self.role);
        Ok(ack)
    }

    pub async fn read_subscription(
        &mut self,
        expected_topic: &RelayTopic,
        expected_message: &str,
    ) -> Result<()> {
        loop {
            let Some(subscription) = self
                .read_any_subscription_for_topic(expected_topic, READ_TIMEOUT)
                .await?
            else {
                bail!("{} timed out waiting for relay subscription", self.role);
            };
            let data = &subscription.data;

            println!(
                "{} <- irn_subscription topic_match={} message_match={} tag_present={} tag={} published_at={}",
                self.role,
                data.topic == *expected_topic,
                data.message == expected_message,
                data.tag.is_some(),
                data.tag.unwrap_or_default(),
                data.published_at
            );

            if data.topic == *expected_topic && data.message == expected_message {
                return Ok(());
            }
        }
    }

    pub async fn read_any_subscription_for_topic(
        &mut self,
        expected_topic: &RelayTopic,
        wait: Duration,
    ) -> Result<Option<IrnSubscription>> {
        loop {
            let Some(subscription) = self.next_subscription(wait).await? else {
                return Ok(None);
            };

            if subscription.data.topic == *expected_topic {
                return Ok(Some(subscription));
            }

            println!(
                "{} <- ignored irn_subscription topic={}",
                self.role, subscription.data.topic
            );
        }
    }

    pub async fn read_suppressed_subscription_for_topics(
        &mut self,
        suppressed_topics: &[RelayTopic],
        wait: Duration,
    ) -> Result<SuppressedDelivery> {
        let deadline = Instant::now() + wait;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(SuppressedDelivery::NoDelivery);
            }

            let Ok(message) = timeout(remaining, self.client.next_message()).await else {
                return Ok(SuppressedDelivery::NoDelivery);
            };

            match message {
                Ok(Some(subscription)) => {
                    if suppressed_topics.contains(&subscription.data.topic) {
                        bail!(
                            "{} routed suppressed relay subscription topic={}",
                            self.role,
                            subscription.data.topic
                        );
                    }

                    println!(
                        "{} <- ignored irn_subscription topic={}",
                        self.role, subscription.data.topic
                    );
                }
                Ok(None) => return Ok(SuppressedDelivery::NoDelivery),
                Err(RelayClientError::UnexpectedSubscriptionTopic { topic }) => {
                    println!(
                        "{} <- dropped inactive irn_subscription topic={}",
                        self.role, topic
                    );

                    if suppressed_topics.contains(&topic) {
                        return Ok(SuppressedDelivery::InactiveTopicDropped { topic });
                    }
                }
                Err(source) => {
                    return Err(source).with_context(|| {
                        format!("{} failed to read relay subscription", self.role)
                    });
                }
            }
        }
    }

    pub async fn next_subscription(&mut self, wait: Duration) -> Result<Option<IrnSubscription>> {
        let Ok(message) = timeout(wait, self.client.next_message()).await else {
            return Ok(None);
        };

        message.with_context(|| format!("{} failed to read relay subscription", self.role))
    }
}

pub struct RawRelaySocket {
    role: &'static str,
    stream: NativeRelayTransport,
}

impl RawRelaySocket {
    pub async fn connect(role: &'static str, url: &str) -> Result<Self> {
        let connection = NativeRelayTransport::connect(url)
            .await
            .with_context(|| format!("{role} failed to connect to relay"))?;
        println!("{role} connected status={}", connection.status());
        Ok(Self {
            role,
            stream: connection.into_transport(),
        })
    }

    pub async fn call_raw(&mut self, method: &str, params: Value) -> Result<RelayRpcId> {
        let id = rpc_id()?;
        let request = json!({
            "id": id.as_u64(),
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send_json(&request).await?;
        println!("{} -> {method} id={}", self.role, id.as_u64());
        Ok(id)
    }

    pub async fn probe_batch_publish_shapes(
        &mut self,
        messages: Vec<IrnPublish>,
    ) -> Result<Option<Value>> {
        let typed_params = serde_json::to_value(IrnBatchPublish::new(messages.clone()))
            .context("failed to serialize batch publish params")?;
        let messages = serde_json::to_value(messages).context("failed to serialize messages")?;
        let without_prompt = match &messages {
            Value::Array(messages) => Value::Array(
                messages
                    .iter()
                    .cloned()
                    .map(|mut message| {
                        if let Value::Object(fields) = &mut message {
                            fields.remove("prompt");
                        }
                        message
                    })
                    .collect(),
            ),
            other => other.clone(),
        };
        let variants = [
            ("typed-object", typed_params),
            (
                "object-without-prompt",
                json!({ "messages": without_prompt }),
            ),
            ("array", messages),
        ];

        for (name, params) in variants {
            let id = self
                .call_raw(<IrnBatchPublish as RelayRequest>::METHOD, params)
                .await?;
            match self.read_response::<Value>(id).await {
                Ok(value) => {
                    println!("{} batch_publish_shape={name}", self.role);
                    return Ok(Some(value));
                }
                Err(error) => {
                    println!("{} batch_publish_shape={name} error={error}", self.role);
                }
            }
        }

        Ok(None)
    }

    pub async fn read_response<T>(&mut self, expected_id: RelayRpcId) -> Result<T>
    where
        T: DeserializeOwned,
    {
        loop {
            let value = self.read_json().await?;
            if value.get("error").is_some() {
                bail!("{} relay error response: {value}", self.role);
            }
            if expected_id.matches_json_value(value.get("id")) {
                let response = serde_json::from_value::<RelayJsonRpcResponse<T>>(value)
                    .context("failed to parse relay response")?;

                println!("{} <- response id={}", self.role, expected_id.as_u64());

                return match response.into_result() {
                    Ok(result) => Ok(result),
                    Err(error) => bail!(
                        "{} response error for id {}: code={} message={}",
                        self.role,
                        expected_id.as_u64(),
                        error.code,
                        error.message
                    ),
                };
            }

            println!("{} <- ignored json={value}", self.role);
        }
    }

    pub async fn send_json(&mut self, value: &Value) -> Result<()> {
        self.stream
            .send_json(value)
            .await
            .with_context(|| format!("{} failed to send json", self.role))
    }

    pub async fn read_json(&mut self) -> Result<Value> {
        let Ok(message) = timeout(READ_TIMEOUT, self.stream.next_json()).await else {
            bail!("{} timed out waiting for relay message", self.role);
        };

        message
            .with_context(|| format!("{} failed to read relay websocket message", self.role))?
            .ok_or_else(|| anyhow!("{} relay stream ended", self.role))
    }
}
