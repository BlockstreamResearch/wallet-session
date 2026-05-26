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
use serde_json::Value;
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, Utf8Bytes},
};
use wc_protocol::relay::{
    DEFAULT_RELAY_URL, IrnFetchMessages, IrnFetchMessagesResponse, IrnPublish, IrnSubscribe,
    IrnSubscription, IrnUnsubscribe, RelayAuthToken, RelayConnectionUrl, RelayJsonRpcRequest,
    RelayJsonRpcResponse, RelayJsonRpcSuccess, RelayRequest, RelayRpcId, RelayTopic,
    relay_auth_audience,
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
        eprintln!("env: REOWN_PROJECT_ID=<project id>");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeMode {
    Basic,
    Matrix,
}

fn parse_probe_mode() -> Result<ProbeMode> {
    let mut mode = env::var("WC_RELAY_PROBE_MODE").unwrap_or_else(|_| "basic".to_owned());

    for argument in env::args().skip(2) {
        match argument.as_str() {
            "--matrix" => "matrix".clone_into(&mut mode),
            "--basic" => "basic".clone_into(&mut mode),
            "--help" | "-h" => {
                eprintln!("usage: cargo run -p xtask -- relay-probe [--basic|--matrix]");
                eprintln!("env: WC_RELAY_PROBE_MODE=basic|matrix");
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
    }
}

struct RelayProbeConfig {
    project_id: String,
    relay_url: String,
    relay_audience: String,
    user_agent: String,
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

        Ok(Self {
            project_id,
            relay_url,
            relay_audience,
            user_agent,
        })
    }

    fn connection_url(&self) -> Result<RelayConnectionUrl> {
        let auth = client_auth_jwt(&self.relay_audience)?;
        Ok(RelayConnectionUrl::new(
            &self.relay_url,
            &self.project_id,
            auth.as_str(),
            &self.user_agent,
        ))
    }

    async fn connect(&self, role: &'static str) -> Result<RelaySocket> {
        let url = self.connection_url()?;
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

    async fn read_response<T>(&mut self, expected_id: RelayRpcId) -> Result<T>
    where
        T: DeserializeOwned,
    {
        loop {
            let value = self.read_json().await?;
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

fn client_auth_jwt(audience: &str) -> Result<RelayAuthToken> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).context("failed to generate relay auth seed")?;
    let sub = random_hex(16)?;
    let iat = unix_timestamp();
    RelayAuthToken::sign_with_seed(&seed, &sub, audience, iat, 86_400)
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

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return "<redacted>".to_owned();
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}
