//! THIS IS PLAYGROUND ONLY TO TEST THE API AND UNDERSTAND HOW IT WORKS
//!
//! Development harnesses for live `WalletConnect` protocol exploration.
//!
//! The first harness probes the Relay Server JSON-RPC contract before those
//! request/response shapes are promoted into stable library types.

use std::{
    env,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, Utf8Bytes},
};
use wc_protocol::{
    pairing::PairingUri,
    relay::{
        DEFAULT_RELAY_URL, IrnBatchFetchMessages, IrnBatchFetchMessagesResponse, IrnBatchPublish,
        IrnBatchSubscribe, IrnBatchUnsubscribe, IrnFetchMessages, IrnFetchMessagesResponse,
        IrnPublish, IrnSubscribe, IrnSubscription, IrnUnsubscribe, RelayAuthToken,
        RelayConnectionUrl, RelayJsonRpcRequest, RelayJsonRpcResponse, RelayJsonRpcSuccess,
        RelayRequest, RelayRpcId, RelayTopic, relay_auth_audience,
    },
};

const READ_TIMEOUT: Duration = Duration::from_secs(20);
const NO_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("relay-probe") {
        run_async(relay_probe(parse_probe_mode()?))
    } else {
        eprintln!("usage: cargo run -p xtask -- relay-probe");
        eprintln!("       cargo run -p xtask -- relay-probe --matrix");
        eprintln!("       cargo run -p xtask -- relay-probe --pairing-uri '<wc uri>'");
        eprintln!("env: REOWN_PROJECT_ID=<project id>");
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeMode {
    Basic,
    Matrix,
    PairingUri(String),
}

fn parse_probe_mode() -> Result<ProbeMode> {
    let mut mode = env::var("WC_RELAY_PROBE_MODE").unwrap_or_else(|_| "basic".to_owned());

    for argument in env::args().skip(2) {
        match argument.as_str() {
            "--matrix" => "matrix".clone_into(&mut mode),
            "--basic" => "basic".clone_into(&mut mode),
            "--pairing-uri" => {
                let uri = env::args()
                    .skip_while(|argument| argument != "--pairing-uri")
                    .nth(1)
                    .or_else(|| env::var("WC_PAIRING_URI").ok())
                    .context("pass a URI after --pairing-uri or set WC_PAIRING_URI")?;
                return Ok(ProbeMode::PairingUri(uri));
            }
            "--help" | "-h" => {
                eprintln!(
                    "usage: cargo run -p xtask -- relay-probe [--basic|--matrix|--pairing-uri '<wc uri>']"
                );
                eprintln!("env: WC_RELAY_PROBE_MODE=basic|matrix");
                eprintln!("env: WC_PAIRING_URI=<wc uri>");
                return Ok(ProbeMode::Basic);
            }
            other => bail!("unknown relay-probe argument: {other}"),
        }
    }

    match mode.as_str() {
        "basic" => Ok(ProbeMode::Basic),
        "matrix" => Ok(ProbeMode::Matrix),
        other => bail!("unknown WC_RELAY_PROBE_MODE: {other}"),
    }
}

fn run_async(task: impl Future<Output = Result<()>>) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?
        .block_on(task)
}

async fn relay_probe(mode: ProbeMode) -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = RelayProbeConfig::from_env()?;

    match mode {
        ProbeMode::Basic => run_basic_probe(&config).await,
        ProbeMode::Matrix => run_probe_matrix(&config).await,
        ProbeMode::PairingUri(uri) => run_pairing_uri_probe(&config, &uri).await,
    }
}

struct RelayProbeConfig {
    project_id: String,
    relay_url: String,
    relay_audience: String,
    user_agent: String,
    publisher_auth_seed: [u8; 32],
    subscriber_auth_seed: [u8; 32],
}

impl RelayProbeConfig {
    fn from_env() -> Result<Self> {
        let project_id = env::var("REOWN_PROJECT_ID")
            .or_else(|_| env::var("WALLETCONNECT_PROJECT_ID"))
            .context("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID")?;
        let relay_url =
            env::var("REOWN_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_owned());
        let relay_audience = relay_auth_audience(&relay_url).to_owned();
        let user_agent = env::var("REOWN_RELAY_UA")
            .unwrap_or_else(|_| "wc-2/rust-poc-0.1.0/macos/native".to_owned());
        let mut publisher_auth_seed = [0_u8; 32];
        getrandom::fill(&mut publisher_auth_seed)
            .context("failed to generate publisher relay auth seed")?;
        let mut subscriber_auth_seed = [0_u8; 32];
        getrandom::fill(&mut subscriber_auth_seed)
            .context("failed to generate subscriber relay auth seed")?;

        Ok(Self {
            project_id,
            relay_url,
            relay_audience,
            user_agent,
            publisher_auth_seed,
            subscriber_auth_seed,
        })
    }

    fn connection_url(&self, role: &'static str) -> Result<RelayConnectionUrl> {
        let seed = match role {
            "publisher" => &self.publisher_auth_seed,
            _ => &self.subscriber_auth_seed,
        };
        let auth = client_auth_jwt(&self.relay_audience, seed)?;
        Ok(RelayConnectionUrl::new(
            &self.relay_url,
            &self.project_id,
            auth.as_str(),
            &self.user_agent,
        ))
    }

    async fn connect(&self, role: &'static str) -> Result<RelaySocket> {
        let url = self.connection_url(role)?;
        RelaySocket::connect(role, url.as_str()).await
    }
}

async fn run_basic_probe(config: &RelayProbeConfig) -> Result<()> {
    let topic = match env::var("WC_RELAY_PROBE_TOPIC") {
        Ok(topic) => RelayTopic::from_hex(topic)?,
        Err(_) => generated_topic()?,
    };
    let probe_id = rpc_id()?;
    let message = env::var("WC_RELAY_PROBE_MESSAGE")
        .unwrap_or_else(|_| format!("walletconnect-rs relay probe {}", probe_id.as_u64()));

    println!(
        "relay-probe project_id={} relay_url={} topic={topic}",
        redact(&config.project_id),
        config.relay_url
    );

    run_push_delivery(config, "basic", topic, vec![message]).await?;

    Ok(())
}

async fn run_pairing_uri_probe(config: &RelayProbeConfig, uri: &str) -> Result<()> {
    let pairing = PairingUri::parse(uri).context("failed to parse pairing URI")?;
    let now = unix_timestamp();
    let methods = pairing
        .methods()
        .map_or_else(|| "<none>".to_owned(), |methods| methods.join(","));

    println!(
        "pairing-uri project_id={} relay_url={} topic={} version={} relay_protocol={} sym_key={} methods={} expiry={:?} expired_now={}",
        redact(&config.project_id),
        config.relay_url,
        pairing.topic(),
        pairing.version(),
        pairing.relay().protocol(),
        redact(pairing.sym_key().as_str()),
        methods,
        pairing.expiry_timestamp(),
        pairing.is_expired_at(now)
    );

    let mut subscriber = config.connect("subscriber").await?;

    let fetch_id = subscriber
        .call(IrnFetchMessages::new(pairing.topic().clone()))
        .await?;
    let fetch_response: IrnFetchMessagesResponse = subscriber.read_response(fetch_id).await?;
    println!(
        "pairing-uri fetch_messages count={} has_more={}",
        fetch_response.messages.len(),
        fetch_response.has_more
    );
    for (index, message) in fetch_response.messages.iter().enumerate() {
        println!(
            "pairing-uri fetched index={index} topic={} message_len={} tag_present={} tag={} published_at={}",
            message.topic,
            message.message.len(),
            message.tag.is_some(),
            message.tag.unwrap_or_default(),
            message.published_at
        );
    }

    let subscribe_id = subscriber
        .call(IrnSubscribe::new(pairing.topic().clone()))
        .await?;
    let subscription_id: String = subscriber.read_response(subscribe_id).await?;
    println!("pairing-uri subscription_id={subscription_id}");

    let wait = pairing_uri_wait_timeout();
    match subscriber
        .read_any_subscription_for_topic(pairing.topic(), wait)
        .await?
    {
        Some(subscription) => {
            println!(
                "pairing-uri live_message=true topic={} message_len={} tag_present={} tag={} published_at={}",
                subscription.data.topic,
                subscription.data.message.len(),
                subscription.data.tag.is_some(),
                subscription.data.tag.unwrap_or_default(),
                subscription.data.published_at
            );
        }
        None => println!(
            "pairing-uri live_message=false wait_secs={}",
            wait.as_secs()
        ),
    }

    let unsubscribe_id = subscriber
        .call(IrnUnsubscribe::new(
            pairing.topic().clone(),
            subscription_id,
        ))
        .await?;
    let unsubscribe_result: bool = subscriber.read_response(unsubscribe_id).await?;
    println!("pairing-uri unsubscribe_ack={unsubscribe_result}");

    Ok(())
}

async fn run_probe_matrix(config: &RelayProbeConfig) -> Result<()> {
    println!(
        "relay-probe matrix project_id={} relay_url={}",
        redact(&config.project_id),
        config.relay_url
    );

    let basic_topic = generated_topic()?;
    let basic_message = format!("matrix basic {}", rpc_id()?.as_u64());
    run_push_delivery(config, "matrix-basic", basic_topic, vec![basic_message]).await?;

    let multi_topic = generated_topic()?;
    let multi_probe_id = rpc_id()?.as_u64();
    run_push_delivery(
        config,
        "matrix-multi-message",
        multi_topic,
        vec![
            format!("matrix multi {multi_probe_id} message 1"),
            format!("matrix multi {multi_probe_id} message 2"),
            format!("matrix multi {multi_probe_id} message 3"),
        ],
    )
    .await?;

    let encoded_topic = generated_topic()?;
    run_push_delivery(
        config,
        "matrix-encoded-message",
        encoded_topic,
        vec![format!(
            "json edge id={} quote=\" backslash=\\ slash=/ newline=\n tab=\t braces={{}}",
            rpc_id()?.as_u64()
        )],
    )
    .await?;

    run_unsubscribe_suppresses_delivery(config).await?;
    run_batch_subscribe_delivery(config).await?;
    run_batch_fetch_offline_messages(config).await?;
    run_batch_unsubscribe_suppresses_delivery(config).await?;
    run_batch_publish_probe(config).await?;

    println!("relay-probe matrix ok");

    Ok(())
}

async fn run_push_delivery(
    config: &RelayProbeConfig,
    label: &str,
    topic: RelayTopic,
    messages: Vec<String>,
) -> Result<()> {
    println!("{label} topic={topic} messages={}", messages.len());

    let mut subscriber = config.connect("subscriber").await?;
    let subscribe_id = subscriber.call(IrnSubscribe::new(topic.clone())).await?;
    let subscription_id: String = subscriber.read_response(subscribe_id).await?;
    println!("{label} subscriber subscription_id={subscription_id}");

    let mut publisher = config.connect("publisher").await?;
    for (index, message) in messages.iter().enumerate() {
        let publish_id = publisher
            .call(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
        let _: bool = publisher.read_response(publish_id).await?;
        println!("{label} publisher publish_ack index={index}");

        subscriber.read_subscription(&topic, message).await?;
    }

    let fetch_id = subscriber
        .call(IrnFetchMessages::new(topic.clone()))
        .await?;
    let fetch_response: IrnFetchMessagesResponse = subscriber.read_response(fetch_id).await?;
    println!(
        "{label} subscriber fetch_messages count={} has_more={}",
        fetch_response.messages.len(),
        fetch_response.has_more
    );
    if !fetch_response.messages.is_empty() || fetch_response.has_more {
        bail!("{label} expected empty mailbox after live delivery ack");
    }

    let unsubscribe_id = subscriber
        .call(IrnUnsubscribe::new(topic, subscription_id))
        .await?;
    let _: bool = subscriber.read_response(unsubscribe_id).await?;
    println!("{label} subscriber unsubscribe_ack=true");

    Ok(())
}

async fn run_unsubscribe_suppresses_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-unsubscribe-suppression";
    let topic = generated_topic()?;
    let message = format!("{label} {}", rpc_id()?.as_u64());
    println!("{label} topic={topic}");

    let mut subscriber = config.connect("subscriber").await?;
    let subscribe_id = subscriber.call(IrnSubscribe::new(topic.clone())).await?;
    let subscription_id: String = subscriber.read_response(subscribe_id).await?;
    println!("{label} subscriber subscription_id={subscription_id}");

    let unsubscribe_id = subscriber
        .call(IrnUnsubscribe::new(topic.clone(), subscription_id))
        .await?;
    let _: bool = subscriber.read_response(unsubscribe_id).await?;
    println!("{label} subscriber unsubscribe_ack=true");

    let mut publisher = config.connect("publisher").await?;
    let publish_id = publisher
        .call(IrnPublish::new(topic.clone(), message, 30, 0))
        .await?;
    let _: bool = publisher.read_response(publish_id).await?;
    println!("{label} publisher publish_ack=true");

    if let Some(subscription) = subscriber
        .read_any_subscription_for_topic(&topic, NO_DELIVERY_TIMEOUT)
        .await?
    {
        bail!(
            "{label} received subscription after unsubscribe: {}",
            subscription.data.message
        );
    }

    println!("{label} no_delivery_after_unsubscribe=true");

    Ok(())
}

async fn run_batch_subscribe_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-batch-subscribe-delivery";
    let topics = vec![generated_topic()?, generated_topic()?];
    let probe_id = rpc_id()?.as_u64();
    let messages = [
        format!("{label} {probe_id} message 1"),
        format!("{label} {probe_id} message 2"),
    ];
    println!(
        "{label} topics={} messages={}",
        topics.len(),
        messages.len()
    );

    let mut subscriber = config.connect("subscriber").await?;
    let subscribe_id = subscriber
        .call(IrnBatchSubscribe::new(topics.clone()))
        .await?;
    let subscribe_result: Value = subscriber.read_response(subscribe_id).await?;
    println!("{label} subscriber batch_subscribe_result={subscribe_result}");

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages.iter()).enumerate() {
        let publish_id = publisher
            .call(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
        let _: bool = publisher.read_response(publish_id).await?;
        println!("{label} publisher publish_ack index={index}");
        subscriber.read_subscription(topic, message).await?;
    }

    Ok(())
}

async fn run_batch_fetch_offline_messages(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-batch-fetch-offline";
    let topics = vec![generated_topic()?, generated_topic()?];
    let probe_id = rpc_id()?.as_u64();
    let messages = [
        format!("{label} {probe_id} cached 1"),
        format!("{label} {probe_id} cached 2"),
    ];
    println!(
        "{label} topics={} messages={}",
        topics.len(),
        messages.len()
    );

    let subscription_ids = {
        let mut subscriber = config.connect("subscriber").await?;
        let subscribe_id = subscriber
            .call(IrnBatchSubscribe::new(topics.clone()))
            .await?;
        let subscription_ids: Vec<String> = subscriber.read_response(subscribe_id).await?;
        println!(
            "{label} subscriber initial_batch_subscribe_ids={}",
            subscription_ids.len()
        );
        subscription_ids
    };

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages.iter()).enumerate() {
        let publish_id = publisher
            .call(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
        let _: bool = publisher.read_response(publish_id).await?;
        println!("{label} publisher publish_ack index={index}");
    }

    let mut subscriber = config.connect("subscriber").await?;
    let fetch_id = subscriber
        .call(IrnBatchFetchMessages::new(topics.clone()))
        .await?;
    let fetch_response: IrnBatchFetchMessagesResponse = subscriber.read_response(fetch_id).await?;
    println!(
        "{label} subscriber batch_fetch_messages count={} has_more={}",
        fetch_response.messages.len(),
        fetch_response.has_more
    );

    let offline_cache_observed = topics.iter().zip(messages.iter()).all(|(topic, message)| {
        fetch_response
            .messages
            .iter()
            .any(|data| data.topic == *topic && data.message == *message)
    });
    println!("{label} offline_cache_observed={offline_cache_observed}");

    let unsubscribe_id = subscriber
        .call(IrnBatchUnsubscribe::new(
            topics
                .into_iter()
                .zip(subscription_ids)
                .map(|(topic, id)| IrnUnsubscribe::new(topic, id))
                .collect(),
        ))
        .await?;
    let unsubscribe_result: Value = subscriber.read_response(unsubscribe_id).await?;
    println!("{label} subscriber batch_unsubscribe_result={unsubscribe_result}");

    Ok(())
}

async fn run_batch_unsubscribe_suppresses_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-batch-unsubscribe-suppression";
    let topics = vec![generated_topic()?, generated_topic()?];
    let probe_id = rpc_id()?.as_u64();
    let messages = vec![
        format!("{label} {probe_id} message 1"),
        format!("{label} {probe_id} message 2"),
    ];
    println!(
        "{label} topics={} messages={}",
        topics.len(),
        messages.len()
    );

    let mut subscriber = config.connect("subscriber").await?;
    let mut subscriptions = Vec::with_capacity(topics.len());
    for topic in &topics {
        let subscribe_id = subscriber.call(IrnSubscribe::new(topic.clone())).await?;
        let subscription_id: String = subscriber.read_response(subscribe_id).await?;
        println!("{label} subscriber subscription_id={subscription_id}");
        subscriptions.push(IrnUnsubscribe::new(topic.clone(), subscription_id));
    }

    let unsubscribe_id = subscriber
        .call(IrnBatchUnsubscribe::new(subscriptions))
        .await?;
    let unsubscribe_result: Value = subscriber.read_response(unsubscribe_id).await?;
    println!("{label} subscriber batch_unsubscribe_result={unsubscribe_result}");

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages).enumerate() {
        let publish_id = publisher
            .call(IrnPublish::new(topic.clone(), message, 30, 0))
            .await?;
        let _: bool = publisher.read_response(publish_id).await?;
        println!("{label} publisher publish_ack index={index}");
    }

    if let Some(subscription) = subscriber
        .read_any_subscription_for_topics(&topics, NO_DELIVERY_TIMEOUT)
        .await?
    {
        bail!(
            "{label} received subscription after batch unsubscribe: topic={} message={}",
            subscription.data.topic,
            subscription.data.message
        );
    }

    println!("{label} no_delivery_after_batch_unsubscribe=true");

    Ok(())
}

async fn run_batch_publish_probe(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-batch-publish-probe";
    let probe_id = rpc_id()?.as_u64();
    let messages = (0..2)
        .map(|index| {
            generated_topic().map(|topic| {
                IrnPublish::new(topic, format!("{label} {probe_id} message {index}"), 30, 0)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    println!("{label} messages={}", messages.len());

    let mut publisher = config.connect("publisher").await?;
    match publisher.probe_batch_publish_shapes(messages).await? {
        Some(result) => println!("{label} accepted=true result={result}"),
        None => println!("{label} accepted=false relay_error=-32600"),
    }

    Ok(())
}

struct RelaySocket {
    role: &'static str,
    stream: RelayStream,
}

impl RelaySocket {
    async fn connect(role: &'static str, url: &str) -> Result<Self> {
        let (stream, response) = connect_async(url)
            .await
            .with_context(|| format!("{role} failed to connect to relay"))?;
        println!("{role} connected status={}", response.status());
        Ok(Self { role, stream })
    }

    async fn call<T>(&mut self, params: T) -> Result<RelayRpcId>
    where
        T: RelayRequest + serde::Serialize,
    {
        let id = rpc_id()?;
        let request = RelayJsonRpcRequest::new(id, params);
        let value = serde_json::to_value(&request).context("failed to serialize relay request")?;
        self.send_json(&value).await?;
        println!("{} -> {} id={}", self.role, request.method(), id.as_u64());
        Ok(id)
    }

    async fn call_raw(&mut self, method: &str, params: Value) -> Result<RelayRpcId> {
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

    async fn probe_batch_publish_shapes(
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

    async fn read_response<T>(&mut self, expected_id: RelayRpcId) -> Result<T>
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

    async fn read_subscription(
        &mut self,
        expected_topic: &RelayTopic,
        expected_message: &str,
    ) -> Result<()> {
        loop {
            let value = self.read_json().await?;
            if value.get("method").and_then(Value::as_str)
                != Some(<IrnSubscription as RelayRequest>::METHOD)
            {
                println!("{} <- ignored json={value}", self.role);
                continue;
            }

            let subscription = self.parse_and_ack_subscription(value).await?;
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

    async fn read_any_subscription_for_topic(
        &mut self,
        expected_topic: &RelayTopic,
        wait: Duration,
    ) -> Result<Option<IrnSubscription>> {
        loop {
            let Some(value) = self.next_json(wait).await? else {
                return Ok(None);
            };

            if value.get("method").and_then(Value::as_str)
                != Some(<IrnSubscription as RelayRequest>::METHOD)
            {
                println!("{} <- ignored json={value}", self.role);
                continue;
            }

            let subscription = self.parse_and_ack_subscription(value).await?;
            if subscription.data.topic == *expected_topic {
                return Ok(Some(subscription));
            }
        }
    }

    async fn read_any_subscription_for_topics(
        &mut self,
        expected_topics: &[RelayTopic],
        wait: Duration,
    ) -> Result<Option<IrnSubscription>> {
        loop {
            let Some(value) = self.next_json(wait).await? else {
                return Ok(None);
            };

            if value.get("method").and_then(Value::as_str)
                != Some(<IrnSubscription as RelayRequest>::METHOD)
            {
                println!("{} <- ignored json={value}", self.role);
                continue;
            }

            let subscription = self.parse_and_ack_subscription(value).await?;
            if expected_topics.contains(&subscription.data.topic) {
                return Ok(Some(subscription));
            }
        }
    }

    async fn parse_and_ack_subscription(&mut self, value: Value) -> Result<IrnSubscription> {
        let request = serde_json::from_value::<RelayJsonRpcRequest<IrnSubscription>>(value)
            .context("failed to parse irn_subscription")?;
        let ack = RelayJsonRpcSuccess::new(request.id(), true);
        let ack = serde_json::to_value(ack).context("failed to serialize subscription ack")?;
        self.send_json(&ack).await?;
        println!(
            "{} -> irn_subscription ack id={}",
            self.role,
            request.id().as_u64()
        );

        Ok(request.params)
    }

    async fn send_json(&mut self, value: &Value) -> Result<()> {
        self.stream
            .send(Message::Text(Utf8Bytes::from(value.to_string())))
            .await
            .with_context(|| format!("{} failed to send json", self.role))
    }

    async fn read_json(&mut self) -> Result<Value> {
        self.next_json(READ_TIMEOUT)
            .await?
            .ok_or_else(|| anyhow!("{} timed out waiting for relay message", self.role))
    }

    async fn next_json(&mut self, wait: Duration) -> Result<Option<Value>> {
        loop {
            let Ok(message) = timeout(wait, self.stream.next()).await else {
                return Ok(None);
            };

            let Some(message) = message else {
                bail!("{} relay stream ended", self.role);
            };

            let message =
                message.with_context(|| format!("{} failed to read relay message", self.role))?;

            match message {
                Message::Text(text) => return parse_json(&text, self.role).map(Some),
                Message::Binary(bytes) => {
                    let text = String::from_utf8(bytes.to_vec()).with_context(|| {
                        format!("{} received non-utf8 binary message", self.role)
                    })?;
                    return parse_json(&text, self.role).map(Some);
                }
                Message::Ping(bytes) => self.stream.send(Message::Pong(bytes)).await?,
                Message::Pong(_) | Message::Frame(_) => {}
                Message::Close(frame) => bail!("{} relay closed: {frame:?}", self.role),
            }
        }
    }
}

fn parse_json(text: &str, role: &str) -> Result<Value> {
    serde_json::from_str(text).with_context(|| format!("{role} received invalid json: {text}"))
}

fn client_auth_jwt(audience: &str, seed: &[u8; 32]) -> Result<RelayAuthToken> {
    let sub = random_hex(16)?;
    let iat = unix_timestamp();
    RelayAuthToken::sign_with_seed(seed, &sub, audience, iat, 86_400)
        .context("failed to sign relay auth token")
}

fn rpc_id() -> Result<RelayRpcId> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = u64::try_from(now.as_millis()).context("epoch millis do not fit in u64")?;
    let entropy = now.subsec_micros() % 1_000_000;

    RelayRpcId::from_millis_entropy(millis, entropy).context("failed to build relay rpc id")
}

fn generated_topic() -> Result<RelayTopic> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).context("failed to generate relay topic")?;
    Ok(RelayTopic::from_bytes(bytes))
}

fn random_hex(len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; len];
    getrandom::fill(&mut bytes).context("failed to generate random bytes")?;
    Ok(hex_string(&bytes))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn pairing_uri_wait_timeout() -> Duration {
    env::var("WC_PAIRING_URI_WAIT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(Duration::from_secs(5), Duration::from_secs)
}

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return "<redacted>".to_owned();
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}
