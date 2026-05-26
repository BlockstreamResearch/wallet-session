//! THIS IS PLAYGROUND ONLY TO TEST THE API AND UNDERSTAND HOW IT WORKS
//!
//! Development harnesses for live `WalletConnect` protocol exploration.
//!
//! The first harness probes the Relay Server JSON-RPC contract before those
//! request/response shapes are promoted into stable library types.
//!
//! References:
//! - Relay project ID URL parameter: <https://docs.walletconnect.network/wallet-sdk/web/cloud/relay>
//! - Relay Server RPC methods: <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc>
//! - Relay Client publish/subscribe shape: <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-api>

use std::{
    env,
    fmt::Write as _,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{net::TcpStream, time::timeout};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Message, Utf8Bytes},
};

type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

const DEFAULT_RELAY_URL: &str = "wss://relay.walletconnect.com/";
const READ_TIMEOUT: Duration = Duration::from_secs(20);

fn main() -> Result<()> {
    if env::args().nth(1).as_deref() == Some("relay-probe") {
        run_async(relay_probe())
    } else {
        eprintln!("usage: cargo run -p xtask -- relay-probe");
        eprintln!("env: REOWN_PROJECT_ID=<project id>");
        Ok(())
    }
}

fn run_async(task: impl Future<Output = Result<()>>) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?
        .block_on(task)
}

async fn relay_probe() -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let project_id = env::var("REOWN_PROJECT_ID")
        .or_else(|_| env::var("WALLETCONNECT_PROJECT_ID"))
        .context("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID")?;
    let relay_url = env::var("REOWN_RELAY_URL").unwrap_or_else(|_| DEFAULT_RELAY_URL.to_owned());
    let relay_audience = relay_audience(&relay_url);
    let user_agent = env::var("REOWN_RELAY_UA")
        .unwrap_or_else(|_| "wc-2/rust-poc-0.1.0/macos/native".to_owned());
    let topic = env::var("WC_RELAY_PROBE_TOPIC").unwrap_or_else(|_| generated_topic());
    let probe_id = rpc_id();
    let message = env::var("WC_RELAY_PROBE_MESSAGE")
        .unwrap_or_else(|_| format!("walletconnect-rs relay probe {probe_id}"));

    println!(
        "relay-probe project_id={} relay_url={} topic={topic}",
        redact(&project_id),
        relay_url
    );

    let subscriber_url = relay_url_with_auth(
        &relay_url,
        &project_id,
        &client_auth_jwt(relay_audience)?,
        &user_agent,
    );
    let mut subscriber = RelaySocket::connect("subscriber", &subscriber_url).await?;
    let subscribe_id = subscriber
        .call("irn_subscribe", json!({ "topic": topic }))
        .await?;
    let subscription_id = subscriber
        .read_response(subscribe_id)
        .await?
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("irn_subscribe response did not contain a subscription id"))?
        .to_owned();
    println!("subscriber subscription_id={subscription_id}");

    let publisher_url = relay_url_with_auth(
        &relay_url,
        &project_id,
        &client_auth_jwt(relay_audience)?,
        &user_agent,
    );
    let mut publisher = RelaySocket::connect("publisher", &publisher_url).await?;
    let publish_id = publisher
        .call(
            "irn_publish",
            json!({
                "topic": topic,
                "message": message,
                "ttl": 30,
                "tag": 0,
            }),
        )
        .await?;
    publisher.read_response(publish_id).await?;
    println!("publisher publish_ack=true");

    subscriber.read_subscription(&topic, &message).await?;

    let fetch_id = subscriber
        .call("irn_fetchMessages", json!({ "topic": topic }))
        .await?;
    let fetch_response = subscriber.read_response(fetch_id).await?;
    let fetched_messages = fetch_response
        .pointer("/result/messages")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let has_more = fetch_response
        .pointer("/result/hasMore")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    println!("subscriber fetch_messages count={fetched_messages} has_more={has_more}");

    let unsubscribe_id = subscriber
        .call(
            "irn_unsubscribe",
            json!({
                "topic": topic,
                "id": subscription_id,
            }),
        )
        .await?;
    subscriber.read_response(unsubscribe_id).await?;
    println!("subscriber unsubscribe_ack=true");

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

    async fn call(&mut self, method: &str, params: Value) -> Result<u64> {
        let id = rpc_id();
        let request = json!({
            "id": id,
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send_json(&request).await?;
        println!("{} -> {method} id={id}", self.role);
        Ok(id)
    }

    async fn read_response(&mut self, expected_id: u64) -> Result<Value> {
        loop {
            let value = self.read_json().await?;
            if json_rpc_id_matches(value.get("id"), expected_id) {
                if let Some(error) = value.get("error") {
                    bail!("{} response error for id {expected_id}: {error}", self.role);
                }
                println!("{} <- response id={expected_id}", self.role);
                return Ok(value);
            }

            println!("{} <- ignored json={value}", self.role);
        }
    }

    async fn read_subscription(
        &mut self,
        expected_topic: &str,
        expected_message: &str,
    ) -> Result<()> {
        loop {
            let value = self.read_json().await?;
            if value.get("method").and_then(Value::as_str) != Some("irn_subscription") {
                println!("{} <- ignored json={value}", self.role);
                continue;
            }

            let topic = value
                .pointer("/params/data/topic")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let message = value
                .pointer("/params/data/message")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let tag = value
                .pointer("/params/data/tag")
                .and_then(Value::as_u64)
                .unwrap_or_default();
            let published_at = value
                .pointer("/params/data/publishedAt")
                .and_then(Value::as_u64)
                .unwrap_or_default();

            if let Some(id) = value.get("id").cloned() {
                self.send_json(&json!({
                    "id": id,
                    "jsonrpc": "2.0",
                    "result": true,
                }))
                .await?;
                println!("{} -> irn_subscription ack id={id}", self.role);
            }

            println!(
                "{} <- irn_subscription topic_match={} message_match={} tag={tag} published_at={published_at}",
                self.role,
                topic == expected_topic,
                message == expected_message
            );

            if topic == expected_topic && message == expected_message {
                return Ok(());
            }
        }
    }

    async fn send_json(&mut self, value: &Value) -> Result<()> {
        self.stream
            .send(Message::Text(Utf8Bytes::from(value.to_string())))
            .await
            .with_context(|| format!("{} failed to send json", self.role))
    }

    async fn read_json(&mut self) -> Result<Value> {
        loop {
            let message = timeout(READ_TIMEOUT, self.stream.next())
                .await
                .with_context(|| format!("{} timed out waiting for relay message", self.role))?
                .ok_or_else(|| anyhow!("{} relay stream ended", self.role))?
                .with_context(|| format!("{} failed to read relay message", self.role))?;

            match message {
                Message::Text(text) => return parse_json(&text, self.role),
                Message::Binary(bytes) => {
                    let text = String::from_utf8(bytes.to_vec()).with_context(|| {
                        format!("{} received non-utf8 binary message", self.role)
                    })?;
                    return parse_json(&text, self.role);
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

fn json_rpc_id_matches(value: Option<&Value>, expected_id: u64) -> bool {
    match value {
        Some(Value::String(id)) => id.parse::<u64>().ok() == Some(expected_id),
        Some(Value::Number(id)) => id.as_u64() == Some(expected_id),
        _ => false,
    }
}

fn client_auth_jwt(aud: &str) -> Result<String> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).context("failed to generate relay auth seed")?;
    let sub = random_hex(16)?;
    let iat = unix_timestamp();
    client_auth_jwt_from_parts(&seed, &sub, aud, iat, 86_400)
}

fn client_auth_jwt_from_parts(
    seed: &[u8; 32],
    sub: &str,
    aud: &str,
    iat: u64,
    ttl: u64,
) -> Result<String> {
    let signing_key = SigningKey::from_bytes(seed);
    let public_key = signing_key.verifying_key().to_bytes();

    let header = JwtHeader {
        alg: "EdDSA",
        typ: "JWT",
    };
    // The relay-auth package currently signs this compact claim set. The public
    // spec also documents an `act = "client_auth"` claim, so keep this harness
    // behavior tied to live relay observations until the core type is designed.
    let payload = RelayAuthClaims {
        iss: did_key_ed25519(&public_key),
        sub,
        aud,
        iat,
        exp: iat + ttl,
    };
    let encoded_header = base64url_json(&header)?;
    let encoded_payload = base64url_json(&payload)?;
    let data = format!("{encoded_header}.{encoded_payload}");
    let signature = signing_key.sign(data.as_bytes());

    Ok(format!(
        "{data}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

#[derive(Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[derive(Serialize)]
struct RelayAuthClaims<'a> {
    iss: String,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

fn base64url_json(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("failed to encode jwt json")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn did_key_ed25519(public_key: &[u8; 32]) -> String {
    let mut multicodec = Vec::with_capacity(34);
    multicodec.extend_from_slice(&[0xed, 0x01]);
    multicodec.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(multicodec).into_string())
}

fn relay_url_with_auth(relay_url: &str, project_id: &str, auth: &str, user_agent: &str) -> String {
    let separator = if relay_url.contains('?') { '&' } else { '?' };
    format!(
        "{relay_url}{separator}auth={}&projectId={}&ua={}",
        query_escape(auth),
        query_escape(project_id),
        query_escape(user_agent)
    )
}

fn relay_audience(relay_url: &str) -> &str {
    relay_url
        .split('?')
        .next()
        .unwrap_or(relay_url)
        .trim_end_matches('/')
}

fn query_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                escaped.push(char::from(byte));
            }
            _ => write!(escaped, "%{byte:02X}").expect("writing to String cannot fail"),
        }
    }
    escaped
}

fn rpc_id() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = u64::try_from(now.as_millis()).unwrap_or(u64::MAX / 1_000_000);
    let entropy = u64::from(now.subsec_micros() % 1_000_000);
    millis.saturating_mul(1_000_000).saturating_add(entropy)
}

fn generated_topic() -> String {
    let mut bytes = [0_u8; 32];
    if getrandom::fill(&mut bytes).is_ok() {
        return hex_string(&bytes);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mixed = now.rotate_left(37) ^ u128::from(std::process::id());
    format!("{now:032x}{mixed:032x}")
}

fn random_hex(len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; len];
    getrandom::fill(&mut bytes).context("failed to generate random bytes")?;
    Ok(hex_string(&bytes))
}

fn hex_string(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_auth_jwt_matches_walletconnect_relay_auth_vector() {
        let mut seed = [0_u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(index).expect("test seed index fits in u8");
        }

        let jwt = client_auth_jwt_from_parts(
            &seed,
            "sub",
            "wss://relay.walletconnect.com",
            1_700_000_000,
            60,
        )
        .expect("jwt is generated");

        assert_eq!(
            jwt,
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.\
             eyJpc3MiOiJkaWQ6a2V5Ono2TWtlaFJnZjd5SmJnYUdmWXNkb0FzS2RCUEUzZGoyQ1lob3dRZGNqcVNKZ3ZWZCIsInN1YiI6InN1YiIsImF1ZCI6IndzczovL3JlbGF5LndhbGxldGNvbm5lY3QuY29tIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDAwNjB9.\
             x2lbadyJJB5GiaCXCp5VY-kKjBPak4oblHd-BhfZjRtuknFDQ8PXGlKWXbweONjWwzlbKZKk2s25-7Q1Dy_xCg"
        );
    }
}
