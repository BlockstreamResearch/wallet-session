//! THIS IS PLAYGROUND ONLY TO TEST THE API AND UNDERSTAND HOW IT WORKS
//!
//! Development harnesses for live `WalletConnect` protocol exploration.
//!
//! The first harness probes the Relay Server JSON-RPC contract before those
//! request/response shapes are promoted into stable library types.

use std::{
    collections::BTreeSet,
    env, fs,
    future::Future,
    io::{self, Read},
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
use wc_protocol::session::{
    Cacao, JsonRpcErrorResponse, JsonRpcResponse as SignJsonRpcResponse, SessionAckResponse,
    SessionAuthenticateParams, SessionAuthenticateResult, SessionDeleteParams, SessionEventParams,
    SessionExtendParams, SessionPingParams, SessionProposeResult, SessionRequestParams,
    SessionRequestResponse, SessionSettleParams, SessionUpdateParams,
};
use wc_protocol::{
    dto::pairing::{
        PairingDeleteParams, PairingJsonRpcRequest, PairingJsonRpcResponse, PairingMethod,
        PairingPingParams,
    },
    envelope::{Envelope, EnvelopeEncoding, EnvelopeType},
    pairing::{PairingSymKey, PairingUri},
    relay::{
        DEFAULT_RELAY_URL, IrnBatchFetchMessages, IrnBatchFetchMessagesResponse, IrnBatchPublish,
        IrnBatchSubscribe, IrnBatchUnsubscribe, IrnFetchMessages, IrnFetchMessagesResponse,
        IrnPublish, IrnSubscribe, IrnSubscription, IrnSubscriptionData, IrnUnsubscribe,
        RelayAuthToken, RelayConnectionUrl, RelayJsonRpcRequest, RelayJsonRpcResponse,
        RelayJsonRpcSuccess, RelayRequest, RelayRpcId, RelayTopic, relay_auth_audience,
    },
    session::{JsonRpcRequest, Session, SessionProposeParams, SignMethod},
};

const READ_TIMEOUT: Duration = Duration::from_secs(20);
const NO_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn main() -> Result<()> {
    match env::args().nth(1).as_deref() {
        Some("relay-probe") => run_async(relay_probe(parse_probe_mode()?)),
        Some("auth-probe") => auth_probe(parse_auth_probe_input()?),
        Some("session-probe") => session_probe(parse_session_probe_input()?),
        Some("pairing-probe") => pairing_probe(parse_pairing_probe_input()?),
        Some("--help" | "-h") | None => {
            print_usage();
            Ok(())
        }
        Some(other) => bail!("unknown xtask command: {other}"),
    }
}

fn print_usage() {
    eprintln!("usage: cargo run -p xtask -- relay-probe");
    eprintln!("       cargo run -p xtask -- relay-probe --matrix");
    eprintln!("       cargo run -p xtask -- relay-probe --pairing-uri '<wc uri>'");
    eprintln!("       cargo run -p xtask -- auth-probe --sample");
    eprintln!("       cargo run -p xtask -- auth-probe --json '<json>'");
    eprintln!("       cargo run -p xtask -- auth-probe --file payload.json");
    eprintln!("       cargo run -p xtask -- auth-probe --stdin");
    eprintln!("       cargo run -p xtask -- pairing-probe --sample");
    eprintln!("       cargo run -p xtask -- pairing-probe --json '<json>'");
    eprintln!("       cargo run -p xtask -- pairing-probe --file payload.json");
    eprintln!("       cargo run -p xtask -- pairing-probe --stdin");
    eprintln!("       cargo run -p xtask -- session-probe --sample");
    eprintln!("       cargo run -p xtask -- session-probe --json '<json>'");
    eprintln!("       cargo run -p xtask -- session-probe --file payload.json");
    eprintln!("       cargo run -p xtask -- session-probe --stdin");
    eprintln!("env: REOWN_PROJECT_ID=<project id>");
    eprintln!("env: WC_AUTH_PROBE_JSON=<json>");
    eprintln!("env: WC_AUTH_PROBE_FILE=<path>");
    eprintln!("env: WC_PAIRING_PROBE_JSON=<json>");
    eprintln!("env: WC_PAIRING_PROBE_FILE=<path>");
    eprintln!("env: WC_SESSION_PROBE_JSON=<json>");
    eprintln!("env: WC_SESSION_PROBE_FILE=<path>");
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeMode {
    Basic,
    Matrix,
    PairingUri(String),
}

enum AuthProbeInput {
    Json(String),
    Sample,
}

enum SessionProbeInput {
    Json(String),
    Sample,
}

enum PairingProbeInput {
    Json(String),
    Sample,
}

fn parse_auth_probe_input() -> Result<AuthProbeInput> {
    let mut arguments = env::args().skip(2);
    let Some(argument) = arguments.next() else {
        if let Ok(json) = env::var("WC_AUTH_PROBE_JSON") {
            return Ok(AuthProbeInput::Json(json));
        }

        if let Ok(path) = env::var("WC_AUTH_PROBE_FILE") {
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read auth probe file {path}"))?;
            return Ok(AuthProbeInput::Json(json));
        }

        return Ok(AuthProbeInput::Sample);
    };

    match argument.as_str() {
        "--sample" => Ok(AuthProbeInput::Sample),
        "--json" => {
            let json = arguments
                .next()
                .or_else(|| env::var("WC_AUTH_PROBE_JSON").ok())
                .context("pass JSON after --json or set WC_AUTH_PROBE_JSON")?;
            Ok(AuthProbeInput::Json(json))
        }
        "--file" => {
            let path = arguments
                .next()
                .or_else(|| env::var("WC_AUTH_PROBE_FILE").ok())
                .context("pass a path after --file or set WC_AUTH_PROBE_FILE")?;
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read auth probe file {path}"))?;
            Ok(AuthProbeInput::Json(json))
        }
        "--stdin" => {
            let mut json = String::new();
            io::stdin()
                .read_to_string(&mut json)
                .context("failed to read auth probe JSON from stdin")?;
            Ok(AuthProbeInput::Json(json))
        }
        "--help" | "-h" => {
            print_usage();
            Ok(AuthProbeInput::Sample)
        }
        other => bail!("unknown auth-probe argument: {other}"),
    }
}

fn parse_session_probe_input() -> Result<SessionProbeInput> {
    let mut arguments = env::args().skip(2);
    let Some(argument) = arguments.next() else {
        if let Ok(json) = env::var("WC_SESSION_PROBE_JSON") {
            return Ok(SessionProbeInput::Json(json));
        }

        if let Ok(path) = env::var("WC_SESSION_PROBE_FILE") {
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read session probe file {path}"))?;
            return Ok(SessionProbeInput::Json(json));
        }

        return Ok(SessionProbeInput::Sample);
    };

    match argument.as_str() {
        "--sample" => Ok(SessionProbeInput::Sample),
        "--json" => {
            let json = arguments
                .next()
                .or_else(|| env::var("WC_SESSION_PROBE_JSON").ok())
                .context("pass JSON after --json or set WC_SESSION_PROBE_JSON")?;
            Ok(SessionProbeInput::Json(json))
        }
        "--file" => {
            let path = arguments
                .next()
                .or_else(|| env::var("WC_SESSION_PROBE_FILE").ok())
                .context("pass a path after --file or set WC_SESSION_PROBE_FILE")?;
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read session probe file {path}"))?;
            Ok(SessionProbeInput::Json(json))
        }
        "--stdin" => {
            let mut json = String::new();
            io::stdin()
                .read_to_string(&mut json)
                .context("failed to read session probe JSON from stdin")?;
            Ok(SessionProbeInput::Json(json))
        }
        "--help" | "-h" => {
            print_usage();
            Ok(SessionProbeInput::Sample)
        }
        other => bail!("unknown session-probe argument: {other}"),
    }
}

fn parse_pairing_probe_input() -> Result<PairingProbeInput> {
    let mut arguments = env::args().skip(2);
    let Some(argument) = arguments.next() else {
        if let Ok(json) = env::var("WC_PAIRING_PROBE_JSON") {
            return Ok(PairingProbeInput::Json(json));
        }

        if let Ok(path) = env::var("WC_PAIRING_PROBE_FILE") {
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read pairing probe file {path}"))?;
            return Ok(PairingProbeInput::Json(json));
        }

        return Ok(PairingProbeInput::Sample);
    };

    match argument.as_str() {
        "--sample" => Ok(PairingProbeInput::Sample),
        "--json" => {
            let json = arguments
                .next()
                .or_else(|| env::var("WC_PAIRING_PROBE_JSON").ok())
                .context("pass JSON after --json or set WC_PAIRING_PROBE_JSON")?;
            Ok(PairingProbeInput::Json(json))
        }
        "--file" => {
            let path = arguments
                .next()
                .or_else(|| env::var("WC_PAIRING_PROBE_FILE").ok())
                .context("pass a path after --file or set WC_PAIRING_PROBE_FILE")?;
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read pairing probe file {path}"))?;
            Ok(PairingProbeInput::Json(json))
        }
        "--stdin" => {
            let mut json = String::new();
            io::stdin()
                .read_to_string(&mut json)
                .context("failed to read pairing probe JSON from stdin")?;
            Ok(PairingProbeInput::Json(json))
        }
        "--help" | "-h" => {
            print_usage();
            Ok(PairingProbeInput::Sample)
        }
        other => bail!("unknown pairing-probe argument: {other}"),
    }
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
                eprintln!("env: WC_PAIRING_URI_PRINT_JSON=1");
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

fn auth_probe(input: AuthProbeInput) -> Result<()> {
    let json = match input {
        AuthProbeInput::Json(json) => json,
        AuthProbeInput::Sample => SAMPLE_AUTH_RESULT_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("auth probe input is not JSON")?;

    println!(
        "auth-probe shape={} bytes={}",
        auth_probe_shape(&value),
        json.len()
    );

    if let Some(method) = value.get("method").and_then(Value::as_str) {
        println!("auth-probe jsonrpc_method={method}");
    }

    if value.get("method").and_then(Value::as_str) == Some("wc_sessionAuthenticate") {
        let request = serde_json::from_value::<JsonRpcRequest<SessionAuthenticateParams>>(value)
            .context("failed to parse wc_sessionAuthenticate request")?;
        println!(
            "auth-probe authenticate_request id={} requester={} expiry={} chains=[{}] domain={} aud={} resources={}",
            request.id,
            request.params.requester.metadata.name,
            request.params.expiry_timestamp,
            request
                .params
                .auth_payload
                .chains
                .iter()
                .map(wc_protocol::caip::Caip2ChainId::as_str)
                .collect::<Vec<_>>()
                .join(","),
            request.params.auth_payload.domain,
            request.params.auth_payload.aud,
            request.params.auth_payload.resources.len()
        );
        return Ok(());
    }

    if value
        .get("result")
        .and_then(|result| result.get("cacaos"))
        .is_some()
    {
        let response =
            serde_json::from_value::<SignJsonRpcResponse<SessionAuthenticateResult>>(value)
                .context("failed to parse wc_sessionAuthenticate result")?;
        println!(
            "auth-probe authenticate_result id={} responder={} cacaos={}",
            response.id,
            response.result.responder.metadata.name,
            response.result.cacaos.len()
        );
        for (index, cacao) in response.result.cacaos.iter().enumerate() {
            print_cacao_summary("auth-probe", index, cacao);
        }
        return Ok(());
    }

    if value.get("h").is_some() && value.get("p").is_some() && value.get("s").is_some() {
        let cacao = serde_json::from_value::<Cacao>(value).context("failed to parse CACAO")?;
        print_cacao_summary("auth-probe", 0, &cacao);
        return Ok(());
    }

    bail!("unsupported auth probe JSON shape")
}

fn session_probe(input: SessionProbeInput) -> Result<()> {
    let json = match input {
        SessionProbeInput::Json(json) => json,
        SessionProbeInput::Sample => SAMPLE_SESSION_PROBE_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("session probe input is not JSON")?;
    let values = match value {
        Value::Array(values) => values,
        value => vec![value],
    };
    let context = session_probe_context(&values);

    println!("session-probe items={} bytes={}", values.len(), json.len());

    for (index, value) in values.iter().enumerate() {
        let shape = session_probe_shape(value);
        println!("session-probe item={index} shape={shape}");
        session_probe_value(index, value, &context)?;
    }

    Ok(())
}

fn pairing_probe(input: PairingProbeInput) -> Result<()> {
    let json = match input {
        PairingProbeInput::Json(json) => json,
        PairingProbeInput::Sample => SAMPLE_PAIRING_PROBE_JSON.to_owned(),
    };
    let value = serde_json::from_str::<Value>(&json).context("pairing probe input is not JSON")?;
    let values = match value {
        Value::Array(values) => values,
        value => vec![value],
    };

    println!("pairing-probe items={} bytes={}", values.len(), json.len());

    for (index, value) in values.iter().enumerate() {
        let shape = pairing_probe_shape(value);
        println!("pairing-probe item={index} shape={shape}");
        pairing_probe_value(index, value)?;
    }

    Ok(())
}

struct SessionProbeContext {
    proposal_ids: BTreeSet<u64>,
}

fn session_probe_context(values: &[Value]) -> SessionProbeContext {
    let proposal_ids = values
        .iter()
        .filter(|value| value.get("method").and_then(Value::as_str) == Some("wc_sessionPropose"))
        .filter_map(|value| {
            serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value.clone()).ok()
        })
        .flat_map(|request| [request.id, request.params.effective_id(request.id)])
        .collect();

    SessionProbeContext { proposal_ids }
}

fn session_probe_shape(value: &Value) -> String {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return format!("{method}-request");
    }

    if value.get("error").is_some() {
        return "jsonrpc-error".to_owned();
    }

    if let Some(result) = value.get("result") {
        if result.get("cacaos").is_some() {
            return "wc_sessionAuthenticate-result".to_owned();
        }

        if result.get("responderPublicKey").is_some() {
            return "wc_sessionPropose-result".to_owned();
        }

        return format!("jsonrpc-result-{}", json_kind(result));
    }

    if value.get("topic").is_some()
        && value.get("pairingTopic").is_some()
        && value.get("namespaces").is_some()
    {
        return "stored-session".to_owned();
    }

    "unknown".to_owned()
}

fn pairing_probe_shape(value: &Value) -> String {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        return format!("{method}-request");
    }

    if value.get("error").is_some() {
        return "jsonrpc-error".to_owned();
    }

    if let Some(result) = value.get("result") {
        return format!("pairing-result-{}", json_kind(result));
    }

    "unknown".to_owned()
}

fn session_probe_value(index: usize, value: &Value, context: &SessionProbeContext) -> Result<()> {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let method = SignMethod::from_wire(method)
            .with_context(|| format!("session-probe item={index} unknown Sign method {method}"))?;
        return session_probe_request(index, method, value);
    }

    if value.get("error").is_some() {
        return session_probe_error(index, value, context);
    }

    if let Some(result) = value.get("result") {
        return session_probe_result(index, value, result);
    }

    if value.get("topic").is_some()
        && value.get("pairingTopic").is_some()
        && value.get("namespaces").is_some()
    {
        return session_probe_stored_session(index, value);
    }

    bail!("session-probe item={index} unsupported JSON shape")
}

fn session_probe_error(index: usize, value: &Value, context: &SessionProbeContext) -> Result<()> {
    let response = serde_json::from_value::<JsonRpcErrorResponse>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse error response"))?;
    let label = if context.proposal_ids.contains(&response.id) {
        "proposal_rejection"
    } else {
        "error"
    };
    println!(
        "session-probe item={index} {label} id={} code={} message={} data_present={} data_kind={}",
        response.id,
        response.error.code.as_i64(),
        response.error.message,
        response.error.data.is_some(),
        response.error.data.as_ref().map_or("<none>", json_kind)
    );
    Ok(())
}

fn session_probe_result(index: usize, value: &Value, result: &Value) -> Result<()> {
    if result.get("cacaos").is_some() {
        return session_probe_authenticate_result(index, value);
    }

    if result.get("responderPublicKey").is_some() {
        return session_probe_proposal_approval(index, value);
    }

    if result.is_boolean() {
        return session_probe_ack(index, value);
    }

    let response =
        serde_json::from_value::<SessionRequestResponse>(value.clone()).with_context(|| {
            format!("session-probe item={index} failed to parse session request result")
        })?;
    println!(
        "session-probe item={index} session_request_result id={} result_kind={}",
        response.id,
        json_kind(response.result.as_value())
    );
    Ok(())
}

fn session_probe_authenticate_result(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SignJsonRpcResponse<SessionAuthenticateResult>>(value.clone())
            .with_context(|| {
                format!("session-probe item={index} failed to parse authenticate result")
            })?;
    println!(
        "session-probe item={index} authenticate_result id={} responder={} cacaos={}",
        response.id,
        response.result.responder.metadata.name,
        response.result.cacaos.len()
    );
    for (cacao_index, cacao) in response.result.cacaos.iter().enumerate() {
        print_cacao_summary("session-probe", cacao_index, cacao);
    }
    Ok(())
}

fn session_probe_proposal_approval(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SignJsonRpcResponse<SessionProposeResult>>(value.clone())
            .with_context(|| {
                format!("session-probe item={index} failed to parse session propose result")
            })?;
    println!(
        "session-probe item={index} proposal_approval id={} relay={} responder_public_key={}",
        response.id, response.result.relay.protocol, response.result.responder_public_key
    );
    Ok(())
}

fn session_probe_ack(index: usize, value: &Value) -> Result<()> {
    let response =
        serde_json::from_value::<SessionAckResponse>(value.clone()).with_context(|| {
            format!("session-probe item={index} failed to parse session ack result")
        })?;
    println!(
        "session-probe item={index} session_ack id={} result=true",
        response.id
    );
    Ok(())
}

fn session_probe_stored_session(index: usize, value: &Value) -> Result<()> {
    let session = serde_json::from_value::<Session>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse stored session"))?;
    println!(
        "session-probe item={index} stored_session topic={} pairing_topic={} self={} peer={} namespaces={} expiry={} expired_now={} transport={}",
        session.topic,
        session.pairing_topic,
        session.self_participant.metadata.name,
        session.peer.metadata.name,
        session.namespaces.len(),
        session.expiry,
        session.is_expired_at(unix_timestamp()),
        session
            .transport_type
            .as_ref()
            .map_or("<none>", wc_protocol::session::SessionTransportType::as_str)
    );
    Ok(())
}

fn pairing_probe_value(index: usize, value: &Value) -> Result<()> {
    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let method = PairingMethod::from_wire(method).with_context(|| {
            format!("pairing-probe item={index} unknown Pairing method {method}")
        })?;
        return pairing_probe_request(index, method, value);
    }

    if value.get("error").is_some() {
        let response =
            serde_json::from_value::<JsonRpcErrorResponse>(value.clone()).with_context(|| {
                format!("pairing-probe item={index} failed to parse error response")
            })?;
        println!(
            "pairing-probe item={index} error id={} code={} message={} data_present={} data_kind={}",
            response.id,
            response.error.code.as_i64(),
            response.error.message,
            response.error.data.is_some(),
            response.error.data.as_ref().map_or("<none>", json_kind)
        );
        return Ok(());
    }

    if value.get("result").is_some() {
        let response = serde_json::from_value::<PairingJsonRpcResponse<bool>>(value.clone())
            .with_context(|| {
                format!("pairing-probe item={index} failed to parse pairing result")
            })?;
        println!(
            "pairing-probe item={index} pairing_ack id={} result={}",
            response.id, response.result
        );
        return Ok(());
    }

    bail!("pairing-probe item={index} unsupported JSON shape")
}

fn session_probe_request(index: usize, method: SignMethod, value: &Value) -> Result<()> {
    match method {
        SignMethod::SessionPropose => print_session_propose_request(index, value),
        SignMethod::SessionSettle => print_session_settle_request(index, value),
        SignMethod::SessionUpdate => print_session_update_request(index, value),
        SignMethod::SessionExtend => print_session_extend_request(index, value),
        SignMethod::SessionDelete => print_session_delete_request(index, value),
        SignMethod::SessionPing => print_session_ping_request(index, value),
        SignMethod::SessionRequest => print_session_request_request(index, value),
        SignMethod::SessionEvent => print_session_event_request(index, value),
        SignMethod::SessionAuthenticate => print_session_authenticate_request(index, value),
    }
}

fn pairing_probe_request(index: usize, method: PairingMethod, value: &Value) -> Result<()> {
    match method {
        PairingMethod::Ping => {
            let parsed =
                serde_json::from_value::<PairingJsonRpcRequest<PairingPingParams>>(value.clone());
            let request = parsed.with_context(|| {
                format!("pairing-probe item={index} failed to parse wc_pairingPing")
            })?;
            println!(
                "pairing-probe item={index} request method={} id={} params=empty",
                request.method, request.id
            );
        }
        PairingMethod::Delete => {
            let parsed =
                serde_json::from_value::<PairingJsonRpcRequest<PairingDeleteParams>>(value.clone());
            let request = parsed.with_context(|| {
                format!("pairing-probe item={index} failed to parse wc_pairingDelete")
            })?;
            println!(
                "pairing-probe item={index} request method={} id={} code={} message={}",
                request.method, request.id, request.params.code, request.params.message
            );
        }
    }

    Ok(())
}

fn print_session_propose_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionProposeParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} proposer={} relays={} required_namespaces={} optional_namespaces={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.proposer.metadata.name,
        request.params.relays.len(),
        request.params.required_namespaces.len(),
        request.params.optional_namespaces.len(),
        request.params.effective_expiry_timestamp(),
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_settle_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionSettleParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} controller={} relay={} namespaces={} expiry={} expired_now={} session_config_present={} special_namespaces={}",
        request.method,
        request.id,
        request.params.controller.metadata.name,
        request.params.relay.protocol,
        request.params.namespaces.len(),
        request.params.expiry,
        request.params.is_expired_at(unix_timestamp()),
        request.params.session_config.is_some(),
        request
            .params
            .special_namespaces
            .as_ref()
            .map_or(0, std::collections::BTreeMap::len)
    );
    Ok(())
}

fn print_session_update_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionUpdateParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} namespaces={}",
        request.method,
        request.id,
        request.params.namespaces.len()
    );
    Ok(())
}

fn print_session_extend_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionExtendParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.expiry,
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_delete_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionDeleteParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} code={} message={}",
        request.method, request.id, request.params.code, request.params.message
    );
    Ok(())
}

fn print_session_ping_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionPingParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} params=empty",
        request.method, request.id
    );
    Ok(())
}

fn print_session_request_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionRequestParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} chain={} routed_method={} params_kind={} expiry={:?} expired_now={}",
        request.method,
        request.id,
        request.params.chain_id,
        request.params.request.method,
        json_kind(&request.params.request.params),
        request.params.request.expiry_timestamp,
        request.params.is_expired_at(unix_timestamp())
    );
    Ok(())
}

fn print_session_event_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionEventParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} chain={} event={} data_kind={}",
        request.method,
        request.id,
        request.params.chain_id,
        request.params.event.name,
        json_kind(&request.params.event.data)
    );
    Ok(())
}

fn print_session_authenticate_request(index: usize, value: &Value) -> Result<()> {
    let request = typed_session_request::<SessionAuthenticateParams>(index, value)?;
    println!(
        "session-probe item={index} request method={} id={} requester={} expiry={} expired_now={} chains=[{}] domain={} aud={} resources={}",
        request.method,
        request.id,
        request.params.requester.metadata.name,
        request.params.expiry_timestamp,
        request.params.is_expired_at(unix_timestamp()),
        request
            .params
            .auth_payload
            .chains
            .iter()
            .map(wc_protocol::caip::Caip2ChainId::as_str)
            .collect::<Vec<_>>()
            .join(","),
        request.params.auth_payload.domain,
        request.params.auth_payload.aud,
        request.params.auth_payload.resources.len()
    );
    Ok(())
}

fn typed_session_request<T>(index: usize, value: &Value) -> Result<JsonRpcRequest<T>>
where
    T: DeserializeOwned,
{
    serde_json::from_value::<JsonRpcRequest<T>>(value.clone())
        .with_context(|| format!("session-probe item={index} failed to parse typed request"))
}

const fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn auth_probe_shape(value: &Value) -> &'static str {
    if value.get("method").and_then(Value::as_str) == Some("wc_sessionAuthenticate") {
        "wc_sessionAuthenticate-request"
    } else if value
        .get("result")
        .and_then(|result| result.get("cacaos"))
        .is_some()
    {
        "wc_sessionAuthenticate-result"
    } else if value.get("h").is_some() && value.get("p").is_some() && value.get("s").is_some() {
        "cacao"
    } else {
        "unknown"
    }
}

fn print_cacao_summary(prefix: &str, index: usize, cacao: &Cacao) {
    println!(
        "{} cacao index={} header={} signature_type={} iss={} account={} chain={} address={} domain={} aud={} resources={}",
        prefix,
        index,
        cacao.h.kind.as_str(),
        cacao.s.kind.as_str(),
        cacao.p.iss.as_str(),
        cacao.p.iss.account_id_str(),
        cacao.p.iss.chain_id(),
        cacao.p.iss.address(),
        cacao.p.domain,
        cacao.p.aud,
        cacao.p.resources.len()
    );
}

const SAMPLE_SESSION_PROBE_JSON: &str = r#"[
  {
    "id": 1,
    "jsonrpc": "2.0",
    "method": "wc_sessionPropose",
    "params": {
      "id": 1,
      "pairingTopic": "1111111111111111111111111111111111111111111111111111111111111111",
      "expiryTimestamp": 4102444800,
      "relays": [{"protocol": "irn"}],
      "proposer": {
        "publicKey": "dapp-public-key",
        "metadata": {
          "name": "Probe Dapp",
          "description": "Probe dapp",
          "url": "https://example.com/dapp",
          "icons": []
        }
      },
      "requiredNamespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "methods": ["personal_sign"],
          "events": ["accountsChanged"]
        }
      },
      "optionalNamespaces": {}
    }
  },
  {
    "id": 1,
    "jsonrpc": "2.0",
    "result": {
      "relay": {"protocol": "irn"},
      "responderPublicKey": "wallet-public-key"
    }
  },
  {
    "id": 1,
    "jsonrpc": "2.0",
    "error": {"code": 5000, "message": "User rejected."}
  },
  {
    "id": 2,
    "jsonrpc": "2.0",
    "method": "wc_sessionSettle",
    "params": {
      "relay": {"protocol": "irn"},
      "namespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
          "methods": ["personal_sign"],
          "events": ["accountsChanged"]
        }
      },
      "controller": {
        "publicKey": "wallet-public-key",
        "metadata": {
          "name": "Probe Wallet",
          "description": "Probe wallet",
          "url": "https://example.com/wallet",
          "icons": []
        }
      },
      "expiry": 4102444800,
      "sessionConfig": {"disableDeepLink": true}
    }
  },
  {
    "id": 3,
    "jsonrpc": "2.0",
    "method": "wc_sessionUpdate",
    "params": {
      "namespaces": {
        "eip155": {
          "chains": ["eip155:1"],
          "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
          "methods": ["personal_sign", "eth_signTypedData"],
          "events": ["accountsChanged", "chainChanged"]
        }
      }
    }
  },
  {
    "id": 4,
    "jsonrpc": "2.0",
    "method": "wc_sessionExtend",
    "params": {"expiry": 4102444800}
  },
  {
    "id": 5,
    "jsonrpc": "2.0",
    "method": "wc_sessionDelete",
    "params": {"code": 6000, "message": "User disconnected."}
  },
  {
    "id": 6,
    "jsonrpc": "2.0",
    "method": "wc_sessionPing",
    "params": {}
  },
  {
    "id": 7,
    "jsonrpc": "2.0",
    "method": "wc_sessionRequest",
    "params": {
      "chainId": "eip155:1",
      "request": {
        "method": "personal_sign",
        "params": [
          "0x68656c6c6f",
          "0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
        ],
        "expiryTimestamp": 4102444800
      }
    }
  },
  {
    "id": 8,
    "jsonrpc": "2.0",
    "method": "wc_sessionEvent",
    "params": {
      "chainId": "eip155:1",
      "event": {
        "name": "accountsChanged",
        "data": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"]
      }
    }
  },
  {
    "id": 9,
    "jsonrpc": "2.0",
    "method": "wc_sessionAuthenticate",
    "params": {
      "requester": {
        "publicKey": "dapp-public-key",
        "metadata": {
          "name": "Probe Dapp",
          "description": "Probe dapp",
          "url": "https://example.com/dapp",
          "icons": []
        }
      },
      "authPayload": {
        "type": "caip122",
        "chains": ["eip155:1"],
        "aud": "https://example.com/login",
        "domain": "example.com",
        "version": "1",
        "nonce": "1234567890",
        "iat": "2026-05-27T06:10:58.791Z",
        "resources": []
      },
      "expiryTimestamp": 4102444800
    }
  },
  {
    "id": 9,
    "jsonrpc": "2.0",
    "result": {
      "responder": {
        "publicKey": "wallet-public-key",
        "metadata": {
          "name": "Probe Wallet",
          "description": "Probe wallet",
          "url": "https://example.com/wallet",
          "icons": []
        }
      },
      "cacaos": [{
        "h": {"t": "caip122"},
        "p": {
          "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
          "domain": "example.com",
          "aud": "https://example.com/login",
          "version": "1",
          "nonce": "1234567890",
          "iat": "2026-05-27T06:10:58.791Z",
          "resources": []
        },
        "s": {"t": "eip191", "s": "0x00"}
      }]
    }
  },
  {
    "id": 10,
    "jsonrpc": "2.0",
    "result": true
  },
  {
    "id": 11,
    "jsonrpc": "2.0",
    "error": {"code": 5000, "message": "User rejected."}
  },
  {
    "topic": "2222222222222222222222222222222222222222222222222222222222222222",
    "pairingTopic": "1111111111111111111111111111111111111111111111111111111111111111",
    "relay": {"protocol": "irn"},
    "expiry": 4102444800,
    "acknowledged": true,
    "controller": "wallet-public-key",
    "namespaces": {
      "eip155": {
        "chains": ["eip155:1"],
        "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
        "methods": ["personal_sign"],
        "events": ["accountsChanged"]
      }
    },
    "requiredNamespaces": {},
    "optionalNamespaces": {},
    "self": {
      "publicKey": "wallet-public-key",
      "metadata": {
        "name": "Probe Wallet",
        "description": "Probe wallet",
        "url": "https://example.com/wallet",
        "icons": []
      }
    },
    "peer": {
      "publicKey": "dapp-public-key",
      "metadata": {
        "name": "Probe Dapp",
        "description": "Probe dapp",
        "url": "https://example.com/dapp",
        "icons": []
      }
    },
    "transportType": "relay"
  }
]"#;

const SAMPLE_PAIRING_PROBE_JSON: &str = r#"[
  {
    "id": 1779866795062281,
    "jsonrpc": "2.0",
    "method": "wc_pairingPing",
    "params": {}
  },
  {
    "id": 1779866795062281,
    "jsonrpc": "2.0",
    "result": true
  },
  {
    "id": 1779866796850380,
    "jsonrpc": "2.0",
    "method": "wc_pairingDelete",
    "params": {
      "message": "User disconnected.",
      "code": 6000
    }
  }
]"#;

const SAMPLE_AUTH_RESULT_JSON: &str = r#"{
  "id": 1779862258791507,
  "jsonrpc": "2.0",
  "result": {
    "cacaos": [
      {
        "h": {
          "t": "caip122"
        },
        "p": {
          "iss": "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
          "domain": "example.com",
          "aud": "https://example.com/login",
          "version": "1",
          "nonce": "1234567890",
          "iat": "2026-05-27T06:10:58.791Z",
          "statement": "",
          "resources": [
            "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ"
          ]
        },
        "s": {
          "t": "eip191",
          "s": "0x5851cc642b66ba30b0073bd3a46c141d46d426eb013465aead257597ca3282a5530db47176d8400e79ac6ed0f8e53ffe87f5d52df421d712be2cbeb02e4768011b"
        }
      }
    ],
    "responder": {
      "publicKey": "977b7da860028df30993e70f25cc6d4f8dd67c4c2e8bb7a84b091a0f9cc37809",
      "metadata": {
        "name": "wc-rs live auth wallet",
        "description": "Temporary live probe wallet",
        "url": "https://example.com/wallet",
        "icons": [
          ""
        ]
      }
    }
  }
}"#;

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
        print_pairing_payload_metadata(
            &format!("pairing-uri fetched index={index}"),
            message,
            pairing.sym_key(),
        )?;
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
            print_pairing_payload_metadata(
                "pairing-uri live_message",
                &subscription.data,
                pairing.sym_key(),
            )?;
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

fn print_pairing_payload_metadata(
    label: &str,
    data: &IrnSubscriptionData,
    sym_key: &PairingSymKey,
) -> Result<()> {
    let envelope = Envelope::decode(&data.message, EnvelopeEncoding::Base64)
        .with_context(|| format!("{label} failed to decode envelope"))?;
    let plaintext = match envelope.envelope_type() {
        EnvelopeType::Type0 | EnvelopeType::Type1 => envelope
            .decrypt(sym_key)
            .with_context(|| format!("{label} failed to decrypt envelope"))?,
        EnvelopeType::Type2 => envelope
            .plaintext()
            .with_context(|| format!("{label} failed to decode plaintext envelope"))?
            .to_owned(),
    };
    let json: Value = serde_json::from_str(&plaintext)
        .with_context(|| format!("{label} decrypted payload is not JSON"))?;

    println!(
        "{label} envelope_type={:?} decrypted_len={} jsonrpc={} id={} method={} params_keys={}",
        envelope.envelope_type(),
        plaintext.len(),
        json.get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or("<none>"),
        json_id(&json),
        json.get("method")
            .and_then(Value::as_str)
            .unwrap_or("<none>"),
        params_keys(&json)
    );

    if json
        .get("method")
        .and_then(Value::as_str)
        .and_then(SignMethod::from_wire)
        == Some(SignMethod::SessionPropose)
    {
        print_session_proposal_summary(label, json.clone())?;
    }

    if let Some(method) = json
        .get("method")
        .and_then(Value::as_str)
        .and_then(PairingMethod::from_wire)
    {
        print_pairing_payload_summary(label, method, json.clone())?;
    }

    if pairing_uri_print_json() {
        let pretty = serde_json::to_string_pretty(&json)
            .with_context(|| format!("{label} failed to format decrypted JSON"))?;
        println!("{label} decrypted_json=\n{pretty}");
    }

    Ok(())
}

fn print_pairing_payload_summary(label: &str, method: PairingMethod, json: Value) -> Result<()> {
    match method {
        PairingMethod::Ping => {
            let request = serde_json::from_value::<PairingJsonRpcRequest<PairingPingParams>>(json)
                .with_context(|| format!("{label} failed to parse wc_pairingPing DTO"))?;
            println!(
                "{label} pairing_request method={} id={} params=empty",
                request.method, request.id
            );
        }
        PairingMethod::Delete => {
            let request =
                serde_json::from_value::<PairingJsonRpcRequest<PairingDeleteParams>>(json)
                    .with_context(|| format!("{label} failed to parse wc_pairingDelete DTO"))?;
            println!(
                "{label} pairing_request method={} id={} code={} message={}",
                request.method, request.id, request.params.code, request.params.message
            );
        }
    }

    Ok(())
}

fn print_session_proposal_summary(label: &str, json: Value) -> Result<()> {
    let request = serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(json)
        .with_context(|| format!("{label} failed to parse wc_sessionPropose DTO"))?;
    let proposal = request.params;
    let expiry = proposal
        .effective_expiry_timestamp()
        .map_or_else(|| "<none>".to_owned(), |expiry| expiry.to_string());
    let pairing_topic = proposal
        .pairing_topic
        .as_ref()
        .map_or_else(|| "<from relay topic>".to_owned(), ToString::to_string);
    let relays = proposal
        .relays
        .iter()
        .map(|relay| relay.protocol.as_str())
        .collect::<Vec<_>>()
        .join(",");

    println!(
        "{label} session_proposal id={} pairing_topic={} expiry={} relays=[{}] required_namespaces={} optional_namespaces={} dapp_name={} dapp_url={} icons={}",
        proposal.effective_id(request.id),
        pairing_topic,
        expiry,
        relays,
        proposal.required_namespaces.len(),
        proposal.optional_namespaces.len(),
        proposal.proposer.metadata.name,
        proposal.proposer.metadata.url,
        proposal.proposer.metadata.icons.len()
    );

    Ok(())
}

fn json_id(json: &Value) -> String {
    json.get("id")
        .map_or_else(|| "<none>".to_owned(), ToString::to_string)
}

fn params_keys(json: &Value) -> String {
    let Some(params) = json.get("params").and_then(Value::as_object) else {
        return "<non-object>".to_owned();
    };
    let mut keys = params.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    format!("[{}]", keys.join(","))
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

fn pairing_uri_print_json() -> bool {
    matches!(
        env::var("WC_PAIRING_URI_PRINT_JSON").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return "<redacted>".to_owned();
    }
    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}
