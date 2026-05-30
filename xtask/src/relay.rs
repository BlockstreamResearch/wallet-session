use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crate::relay_socket::{RawRelaySocket, RelaySocket, SuppressedDelivery};
use crate::util::{
    client_auth_jwt, generated_sym_key, generated_topic, pairing_uri_print_json,
    pairing_uri_wait_timeout, redact, rpc_id, unix_timestamp,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::time::sleep;
use wc_core::{
    DEFAULT_SESSION_EXPIRY_SECONDS, PairingPayload, PairingReceivedMessage,
    SessionAuthenticateApproval, SessionAuthenticateReview, SessionClientEvent,
    SessionLifecycleResponseMessage, SessionLifecycleResponsePayload, SessionPayload,
    SessionProposalApproval, SessionReceivedMessage, SessionRequestRejection, SessionRequestReview,
    SingleSessionAuthenticate, SingleSessionClient, SingleSessionClientConfig,
    SingleSessionClientEvent, SingleSessionProposal, WalletCapabilities, WalletChainCapability,
    low_level::{
        ApprovedSession, PAIRING_PING_RESPONSE_TAG, PairingClient, PairingClientConfig,
        PairingSubscription, SESSION_AUTHENTICATE_REJECT_TAG, SESSION_AUTHENTICATE_RESPONSE_TAG,
        SESSION_REQUEST_RESPONSE_TAG, SessionSettleResponseMessage, SessionSettleResponsePayload,
        SessionSubscription,
    },
};
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, NamespaceKey},
    dto::pairing::{PairingDeleteParams, PairingJsonRpcRequest, PairingMethod, PairingPingParams},
    envelope::{Envelope, EnvelopeEncoding},
    key::{X25519KeyPair, derive_shared_sym_key, derive_topic_from_sym_key},
    pairing::{PairingSymKey, PairingUri},
    pairing_message::{PairingMessage, PairingMessageMethod},
    relay::{
        DEFAULT_RELAY_URL, IrnPublish, IrnSubscription, IrnSubscriptionData, IrnUnsubscribe,
        RelayConnectionUrl, RelayTopic, relay_auth_audience,
    },
    session::{
        Cacao, DappMetadata, Session, SessionDeleteParams, SessionEvent, SessionEventName,
        SessionEventParams, SessionMethod, SessionNamespace, SessionNamespaces, WalletCallRequest,
    },
    session::{
        JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse, JsonRpcRequest, SessionProposeParams,
        SignMethod,
    },
};

const READ_TIMEOUT: Duration = Duration::from_secs(20);
const NO_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
const JS_HARNESS_URI_READY_TIMEOUT: Duration = Duration::from_secs(30);
const JS_HARNESS_URI_FILE_STEM: &str = "live-pairing-uri";
const JS_HARNESS_RESULT_FILE_STEM: &str = "live-pairing-result";

#[derive(Debug, serde::Deserialize)]
struct SignedAuthFixture {
    address: String,
    iss: String,
    cacao: Cacao,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeMode {
    Basic,
    Matrix,
    JsProposal,
    CoreJsProposal,
    CoreJsApproveProposal,
    CoreJsRejectProposal,
    CoreJsPairingLifecycle,
    CoreJsSessionRequest,
    CoreJsSessionLifecycle,
    CoreSingleSessionClientSessionRequest,
    CoreSingleSessionClientSessionLifecycle,
    CoreSingleSessionClientDisconnect,
    CoreSingleSessionClientSessionAuthenticate,
    PairingUri(String),
}

pub async fn run(mode: ProbeMode) -> Result<()> {
    let config = RelayProbeConfig::from_env()?;

    match mode {
        ProbeMode::Basic => Box::pin(run_basic_probe(&config)).await,
        ProbeMode::Matrix => Box::pin(run_probe_matrix(&config)).await,
        ProbeMode::JsProposal => Box::pin(run_js_proposal_probe(&config)).await,
        ProbeMode::CoreJsProposal => Box::pin(run_core_js_proposal_probe(&config)).await,
        ProbeMode::CoreJsApproveProposal => {
            Box::pin(run_core_js_approve_proposal_probe(&config)).await
        }
        ProbeMode::CoreJsRejectProposal => {
            Box::pin(run_core_js_reject_proposal_probe(&config)).await
        }
        ProbeMode::CoreJsPairingLifecycle => {
            Box::pin(run_core_js_pairing_lifecycle_probe(&config)).await
        }
        ProbeMode::CoreJsSessionRequest => {
            Box::pin(run_core_js_session_request_probe(&config)).await
        }
        ProbeMode::CoreJsSessionLifecycle => {
            Box::pin(run_core_js_session_lifecycle_probe(&config)).await
        }
        ProbeMode::CoreSingleSessionClientSessionRequest => {
            Box::pin(run_core_single_session_client_session_request_probe(
                &config,
            ))
            .await
        }
        ProbeMode::CoreSingleSessionClientSessionLifecycle => {
            Box::pin(run_core_single_session_client_session_lifecycle_probe(
                &config,
            ))
            .await
        }
        ProbeMode::CoreSingleSessionClientDisconnect => {
            Box::pin(run_core_single_session_client_disconnect_probe(&config)).await
        }
        ProbeMode::CoreSingleSessionClientSessionAuthenticate => {
            Box::pin(run_core_single_session_client_session_authenticate_probe(
                &config,
            ))
            .await
        }
        ProbeMode::PairingUri(uri) => Box::pin(run_pairing_uri_probe(&config, &uri)).await,
    }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest directory has no workspace parent")
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    const fn new(child: Child) -> Self {
        Self { child }
    }

    const fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    fn terminate(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

struct SessionHarness {
    result_file: PathBuf,
    guard: ChildGuard,
}

struct PairingHarness {
    result_file: PathBuf,
    guard: ChildGuard,
}

struct AuthHarness {
    result_file: PathBuf,
    guard: ChildGuard,
}

impl AuthHarness {
    async fn start(label: &str) -> Result<(Self, String)> {
        let workspace_root = workspace_root()?;
        let harness_dir = workspace_root.join("tools/js-harness");
        let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
        let result_file = js_harness_file(&workspace_root, JS_HARNESS_RESULT_FILE_STEM, "json");
        if let Some(parent) = uri_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let _ = fs::remove_file(&uri_file);
        let _ = fs::remove_file(&result_file);

        let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());

        println!(
            "core-single-session-client-session-authenticate harness_dir={} uri_file={} result_file={} hold_ms={hold_ms} label={label}",
            harness_dir.display(),
            uri_file.display(),
            result_file.display()
        );

        let child = Command::new("bun")
            .args(["run", "authenticate"])
            .current_dir(&harness_dir)
            .env("WC_JS_URI_FILE", &uri_file)
            .env("WC_JS_RESULT_FILE", &result_file)
            .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
            .env_remove("WC_JS_PRINT_URI")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start auth Bun harness in {}",
                    harness_dir.display()
                )
            })?;
        let mut guard = ChildGuard::new(child);
        let uri = wait_for_js_pairing_uri(&uri_file, guard.child_mut()).await?;
        Ok((Self { result_file, guard }, uri))
    }

    async fn expect_result(&mut self, expected_outcome: &str) -> Result<Value> {
        let result = wait_for_js_result(&self.result_file, self.guard.child_mut()).await?;
        if result.get("outcome").and_then(Value::as_str) != Some(expected_outcome) {
            bail!("expected JS {expected_outcome} result, got {result}");
        }
        Ok(result)
    }

    fn terminate(&mut self) {
        self.guard.terminate();
    }
}

impl PairingHarness {
    async fn start(action: &str, label: &str) -> Result<(Self, String)> {
        let workspace_root = workspace_root()?;
        let harness_dir = workspace_root.join("tools/js-harness");
        let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
        let result_file = js_harness_file(&workspace_root, JS_HARNESS_RESULT_FILE_STEM, "json");
        if let Some(parent) = uri_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let _ = fs::remove_file(&uri_file);
        let _ = fs::remove_file(&result_file);

        let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "30000".to_owned());

        println!(
            "core-js-pairing-lifecycle harness_dir={} uri_file={} result_file={} hold_ms={hold_ms} action={action} label={label}",
            harness_dir.display(),
            uri_file.display(),
            result_file.display()
        );

        let child = Command::new("bun")
            .args(["run", "pairing-lifecycle"])
            .current_dir(&harness_dir)
            .env("WC_JS_URI_FILE", &uri_file)
            .env("WC_JS_RESULT_FILE", &result_file)
            .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
            .env("WC_JS_PAIRING_ACTION", action)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start pairing Bun harness in {}",
                    harness_dir.display()
                )
            })?;
        let mut guard = ChildGuard::new(child);
        let uri = wait_for_js_pairing_uri(&uri_file, guard.child_mut()).await?;
        Ok((Self { result_file, guard }, uri))
    }

    async fn expect_result(&mut self, expected_outcome: &str) -> Result<Value> {
        let result = wait_for_js_result(&self.result_file, self.guard.child_mut()).await?;
        if result.get("outcome").and_then(Value::as_str) != Some(expected_outcome) {
            bail!("expected JS {expected_outcome} result, got {result}");
        }
        Ok(result)
    }

    fn terminate(&mut self) {
        self.guard.terminate();
    }
}

impl SessionHarness {
    async fn start(action: &str, label: &str) -> Result<(Self, String)> {
        let workspace_root = workspace_root()?;
        let harness_dir = workspace_root.join("tools/js-harness");
        let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
        let result_file = js_harness_file(&workspace_root, JS_HARNESS_RESULT_FILE_STEM, "json");
        if let Some(parent) = uri_file.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let _ = fs::remove_file(&uri_file);
        let _ = fs::remove_file(&result_file);

        let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());
        let request_hold_ms =
            env::var("WC_JS_SESSION_REQUEST_HOLD_MS").unwrap_or_else(|_| hold_ms.clone());

        println!(
            "core-js-session harness_dir={} uri_file={} result_file={} hold_ms={hold_ms} request_hold_ms={request_hold_ms} action={action} label={label}",
            harness_dir.display(),
            uri_file.display(),
            result_file.display()
        );

        let mut command = Command::new("bun");
        command
            .args(["run", "propose-session"])
            .current_dir(&harness_dir)
            .env("WC_JS_URI_FILE", &uri_file)
            .env("WC_JS_RESULT_FILE", &result_file)
            .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
            .env("WC_JS_SESSION_REQUEST_HOLD_MS", &request_hold_ms)
            .env("WC_JS_AFTER_APPROVAL_ACTION", action)
            .env_remove("WC_JS_PRINT_URI")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if action == "session_request" {
            command
                .env("WC_JS_SEND_SESSION_REQUEST", "1")
                .env("WC_JS_SESSION_REQUEST_WAIT_FOR_RESPONSE", "1");
        }

        let child = command
            .spawn()
            .with_context(|| format!("failed to start Bun harness in {}", harness_dir.display()))?;
        let mut guard = ChildGuard::new(child);
        let uri = wait_for_js_pairing_uri(&uri_file, guard.child_mut()).await?;
        Ok((Self { result_file, guard }, uri))
    }

    async fn expect_result(&mut self, expected_outcome: &str) -> Result<Value> {
        let result = wait_for_js_result(&self.result_file, self.guard.child_mut()).await?;
        if result.get("outcome").and_then(Value::as_str) != Some(expected_outcome) {
            bail!("expected JS {expected_outcome} result, got {result}");
        }
        Ok(result)
    }

    fn terminate(&mut self) {
        self.guard.terminate();
    }
}

async fn wait_for_js_pairing_uri(uri_file: &Path, child: &mut Child) -> Result<String> {
    let started_at = Instant::now();

    loop {
        if let Ok(uri) = fs::read_to_string(uri_file) {
            if !uri.trim().is_empty() {
                return Ok(uri);
            }
        }

        if let Some(status) = child
            .try_wait()
            .context("failed to poll Bun harness process")?
        {
            bail!("Bun harness exited before writing pairing URI: {status}");
        }

        if started_at.elapsed() >= JS_HARNESS_URI_READY_TIMEOUT {
            bail!(
                "timed out waiting {}s for Bun harness URI file {}",
                JS_HARNESS_URI_READY_TIMEOUT.as_secs(),
                uri_file.display()
            );
        }

        sleep(Duration::from_millis(100)).await;
    }
}

fn js_harness_file(workspace_root: &Path, stem: &str, extension: &str) -> PathBuf {
    workspace_root
        .join("target")
        .join(format!("{stem}-{}.{extension}", std::process::id()))
}

async fn wait_for_js_result(result_file: &Path, child: &mut Child) -> Result<Value> {
    let started_at = Instant::now();

    loop {
        if let Ok(result) = fs::read_to_string(result_file) {
            if !result.trim().is_empty() {
                return serde_json::from_str(&result)
                    .with_context(|| format!("failed to parse {}", result_file.display()));
            }
        }

        if let Some(status) = child
            .try_wait()
            .context("failed to poll Bun harness process")?
        {
            bail!("Bun harness exited before writing result: {status}");
        }

        if started_at.elapsed() >= READ_TIMEOUT {
            bail!(
                "timed out waiting {}s for Bun harness result file {}",
                READ_TIMEOUT.as_secs(),
                result_file.display()
            );
        }

        sleep(Duration::from_millis(100)).await;
    }
}

fn parse_json_env(value: &str) -> Result<Value> {
    serde_json::from_str(value).with_context(|| format!("failed to parse JSON env value: {value}"))
}

fn assert_optional_json_env_matches<T>(
    env_name: &str,
    actual: Option<&T>,
    label: &str,
) -> Result<()>
where
    T: Serialize,
{
    let Ok(expected_raw) = env::var(env_name) else {
        return Ok(());
    };

    let expected = parse_json_env(&expected_raw)?;
    let actual = actual
        .map(serde_json::to_value)
        .transpose()
        .with_context(|| format!("failed to serialize {label}"))?
        .unwrap_or(Value::Null);

    if actual != expected {
        bail!("{label} mismatch for {env_name}: expected {expected}, got {actual}");
    }

    println!("{label} {env_name}=matched");
    Ok(())
}

fn assert_string_env_matches(env_name: &str, actual: &str, label: &str) -> Result<()> {
    let Ok(expected) = env::var(env_name) else {
        return Ok(());
    };

    if actual != expected {
        bail!("{label} mismatch for {env_name}: expected {expected}, got {actual}");
    }

    println!("{label} {env_name}=matched");
    Ok(())
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

    async fn connect_raw(&self, role: &'static str) -> Result<RawRelaySocket> {
        let url = self.connection_url(role)?;
        RawRelaySocket::connect(role, url.as_str()).await
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

async fn run_js_proposal_probe(config: &RelayProbeConfig) -> Result<()> {
    let workspace_root = workspace_root()?;
    let harness_dir = workspace_root.join("tools/js-harness");
    let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
    if let Some(parent) = uri_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let _ = fs::remove_file(&uri_file);

    let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());
    println!(
        "js-proposal harness_dir={} uri_file={} hold_ms={hold_ms}",
        harness_dir.display(),
        uri_file.display()
    );

    let child = Command::new("bun")
        .args(["run", "propose-session"])
        .current_dir(&harness_dir)
        .env("WC_JS_URI_FILE", &uri_file)
        .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
        .env_remove("WC_JS_PRINT_URI")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start Bun harness in {}", harness_dir.display()))?;
    let mut harness = ChildGuard::new(child);
    let uri = wait_for_js_pairing_uri(&uri_file, harness.child_mut()).await?;

    run_pairing_uri_probe(config, uri.trim()).await?;
    harness.terminate();

    Ok(())
}

async fn run_core_js_proposal_probe(config: &RelayProbeConfig) -> Result<()> {
    let workspace_root = workspace_root()?;
    let harness_dir = workspace_root.join("tools/js-harness");
    let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
    if let Some(parent) = uri_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let _ = fs::remove_file(&uri_file);

    let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());
    println!(
        "core-js-proposal harness_dir={} uri_file={} hold_ms={hold_ms}",
        harness_dir.display(),
        uri_file.display()
    );

    let child = Command::new("bun")
        .args(["run", "propose-session"])
        .current_dir(&harness_dir)
        .env("WC_JS_URI_FILE", &uri_file)
        .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
        .env_remove("WC_JS_PRINT_URI")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start Bun harness in {}", harness_dir.display()))?;
    let mut harness = ChildGuard::new(child);
    let uri = wait_for_js_pairing_uri(&uri_file, harness.child_mut()).await?;

    run_core_pairing_uri_probe(config, uri.trim()).await?;
    harness.terminate();

    Ok(())
}

async fn run_core_js_reject_proposal_probe(config: &RelayProbeConfig) -> Result<()> {
    let workspace_root = workspace_root()?;
    let harness_dir = workspace_root.join("tools/js-harness");
    let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
    let result_file = js_harness_file(&workspace_root, JS_HARNESS_RESULT_FILE_STEM, "json");
    if let Some(parent) = uri_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let _ = fs::remove_file(&uri_file);
    let _ = fs::remove_file(&result_file);

    let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());
    println!(
        "core-js-reject-proposal harness_dir={} uri_file={} result_file={} hold_ms={hold_ms}",
        harness_dir.display(),
        uri_file.display(),
        result_file.display()
    );

    let child = Command::new("bun")
        .args(["run", "propose-session"])
        .current_dir(&harness_dir)
        .env("WC_JS_URI_FILE", &uri_file)
        .env("WC_JS_RESULT_FILE", &result_file)
        .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
        .env_remove("WC_JS_PRINT_URI")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start Bun harness in {}", harness_dir.display()))?;
    let mut harness = ChildGuard::new(child);
    let uri = wait_for_js_pairing_uri(&uri_file, harness.child_mut()).await?;

    run_core_pairing_uri_reject_probe(config, uri.trim()).await?;
    let result = wait_for_js_result(&result_file, harness.child_mut()).await?;
    if result.get("outcome").and_then(Value::as_str) != Some("approval_error") {
        bail!("expected JS approval_error result, got {result}");
    }
    println!("core-js-reject-proposal js_result={result}");
    harness.terminate();

    Ok(())
}

async fn run_core_js_approve_proposal_probe(config: &RelayProbeConfig) -> Result<()> {
    let workspace_root = workspace_root()?;
    let harness_dir = workspace_root.join("tools/js-harness");
    let uri_file = js_harness_file(&workspace_root, JS_HARNESS_URI_FILE_STEM, "txt");
    let result_file = js_harness_file(&workspace_root, JS_HARNESS_RESULT_FILE_STEM, "json");
    if let Some(parent) = uri_file.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let _ = fs::remove_file(&uri_file);
    let _ = fs::remove_file(&result_file);

    let hold_ms = env::var("WC_JS_HARNESS_HOLD_MS").unwrap_or_else(|_| "120000".to_owned());
    println!(
        "core-js-approve-proposal harness_dir={} uri_file={} result_file={} hold_ms={hold_ms}",
        harness_dir.display(),
        uri_file.display(),
        result_file.display()
    );

    let child = Command::new("bun")
        .args(["run", "propose-session"])
        .current_dir(&harness_dir)
        .env("WC_JS_URI_FILE", &uri_file)
        .env("WC_JS_RESULT_FILE", &result_file)
        .env("WC_JS_HARNESS_HOLD_MS", &hold_ms)
        .env_remove("WC_JS_PRINT_URI")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start Bun harness in {}", harness_dir.display()))?;
    let mut harness = ChildGuard::new(child);
    let uri = wait_for_js_pairing_uri(&uri_file, harness.child_mut()).await?;

    let (mut client, pairing_subscription, approved, _session) =
        run_core_pairing_uri_approve_probe(config, uri.trim()).await?;
    let result = wait_for_js_result(&result_file, harness.child_mut()).await?;
    if result.get("outcome").and_then(Value::as_str) != Some("approved") {
        bail!("expected JS approved result, got {result}");
    }
    println!("core-js-approve-proposal js_result={result}");

    let unsubscribe_result = client.unsubscribe_pairing(&pairing_subscription).await?;
    println!("core-pairing-approve unsubscribe_ack={unsubscribe_result}");
    println!(
        "core-pairing-approve session_topic={} session_subscription_id={} responder_public_key={} proposal_response_ack={} session_settle_ack={}",
        approved.session_topic(),
        approved.subscription().subscription_id(),
        approved.responder_public_key(),
        approved.proposal_response_ack(),
        approved.session_settle_ack()
    );
    harness.terminate();

    Ok(())
}

async fn run_core_js_pairing_lifecycle_probe(config: &RelayProbeConfig) -> Result<()> {
    let action = PairingLifecycleAction::from_env()?;
    let (mut harness, uri) = PairingHarness::start(action.js_action(), action.label()).await?;
    let (mut client, subscription, message) =
        receive_core_js_pairing_lifecycle_message(config, uri.trim(), action).await?;

    match action {
        PairingLifecycleAction::Ping => {
            let ack = client.respond_pairing_ping(&subscription, &message).await?;
            println!(
                "core-js-pairing-lifecycle pairing_ping_response_ack={ack} response_tag={PAIRING_PING_RESPONSE_TAG}"
            );
            let result = harness.expect_result(action.expected_result()).await?;
            println!("core-js-pairing-lifecycle js_result={result}");
            let unsubscribe_result = client.unsubscribe_pairing(&subscription).await?;
            println!("core-js-pairing-lifecycle unsubscribe_ack={unsubscribe_result}");
        }
        PairingLifecycleAction::Delete => {
            let unsubscribe_result = client.unsubscribe_pairing(&subscription).await?;
            println!(
                "core-js-pairing-lifecycle delete_cleanup_unsubscribe_ack={unsubscribe_result}"
            );
            let result = harness.expect_result(action.expected_result()).await?;
            println!("core-js-pairing-lifecycle js_result={result}");
        }
    }

    harness.terminate();
    Ok(())
}

async fn receive_core_js_pairing_lifecycle_message(
    config: &RelayProbeConfig,
    uri: &str,
    action: PairingLifecycleAction,
) -> Result<(PairingClient, PairingSubscription, PairingReceivedMessage)> {
    let pairing = PairingUri::parse(uri).context("failed to parse pairing URI")?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!("xtask-core-pairing-{}", rpc_id()?.as_u64()),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    println!(
        "core-js-pairing-lifecycle project_id={} relay_url={} topic={} version={} relay_protocol={} sym_key={} expiry={:?} expired_now={} action={}",
        redact(&config.project_id),
        config.relay_url,
        pairing.topic(),
        pairing.version(),
        pairing.relay().protocol(),
        redact(pairing.sym_key().as_str()),
        pairing.expiry_timestamp(),
        pairing.is_expired_at(unix_timestamp()),
        action.label()
    );

    let mut client = PairingClient::connect(&client_config).await?;
    println!(
        "core-js-pairing-lifecycle connected status={}",
        client.status()
    );

    let fetched = client.fetch_pairing_messages(&pairing).await?;
    println!(
        "core-js-pairing-lifecycle fetch_messages count={}",
        fetched.len()
    );
    let subscription = client.subscribe_pairing(&pairing).await?;
    println!(
        "core-js-pairing-lifecycle subscription_id={}",
        subscription.subscription_id()
    );

    for (index, message) in fetched.into_iter().enumerate() {
        print_core_pairing_payload_metadata(
            &format!("core-js-pairing-lifecycle fetched index={index}"),
            &message,
        )?;
        if action.matches(&message) {
            return Ok((client, subscription, message));
        }
    }

    loop {
        let message = client
            .next_pairing_message(&subscription)
            .await?
            .context("no pairing lifecycle message received")?;
        print_core_pairing_payload_metadata("core-js-pairing-lifecycle live_message", &message)?;
        if action.matches(&message) {
            return Ok((client, subscription, message));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PairingLifecycleAction {
    Ping,
    Delete,
}

impl PairingLifecycleAction {
    fn from_env() -> Result<Self> {
        match env::var("WC_CORE_PAIRING_LIFECYCLE_ACTION")
            .unwrap_or_else(|_| "ping".to_owned())
            .as_str()
        {
            "ping" => Ok(Self::Ping),
            "delete" => Ok(Self::Delete),
            other => {
                bail!("unknown WC_CORE_PAIRING_LIFECYCLE_ACTION={other}; expected ping or delete")
            }
        }
    }

    const fn js_action(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Delete => "delete",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Delete => "delete",
        }
    }

    const fn expected_result(self) -> &'static str {
        match self {
            Self::Ping => "pairing_ping_response",
            Self::Delete => "pairing_delete_sent",
        }
    }

    const fn matches(self, message: &PairingReceivedMessage) -> bool {
        matches!(
            (self, message.payload()),
            (Self::Ping, PairingPayload::PairingPing(_))
                | (Self::Delete, PairingPayload::PairingDelete(_))
        )
    }
}

async fn run_core_js_session_request_probe(config: &RelayProbeConfig) -> Result<()> {
    let response_mode =
        env::var("WC_CORE_SESSION_REQUEST_RESPONSE").unwrap_or_else(|_| "success".to_owned());
    let raw_invalid_request = response_mode.starts_with("auto-reject-");
    let action = if raw_invalid_request {
        "approved"
    } else {
        "session_request"
    };
    let (mut harness, uri) = SessionHarness::start(action, &response_mode).await?;

    let (mut client, pairing_subscription, approved, session) =
        run_core_pairing_uri_approve_probe(config, uri.trim()).await?;

    if raw_invalid_request {
        run_core_raw_invalid_session_request_probe(
            config,
            &mut client,
            approved.subscription(),
            &session,
            &response_mode,
        )
        .await?;
        let result = harness.expect_result("approved").await?;
        println!("core-js-session-request js_result={result}");
    } else {
        run_core_valid_session_request_probe(
            &mut client,
            approved.subscription(),
            &session,
            &response_mode,
            &mut harness,
        )
        .await?;
    }

    let unsubscribe_result = client.unsubscribe_pairing(&pairing_subscription).await?;
    println!("core-js-session-request pairing_unsubscribe_ack={unsubscribe_result}");
    harness.terminate();

    Ok(())
}

async fn run_core_single_session_client_session_request_probe(
    config: &RelayProbeConfig,
) -> Result<()> {
    let response_mode =
        env::var("WC_CORE_SESSION_REQUEST_RESPONSE").unwrap_or_else(|_| "success".to_owned());
    let (mut harness, uri) = SessionHarness::start("session_request", &response_mode).await?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!("xtask-core-single-session-client-{}", rpc_id()?.as_u64()),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    let mut client =
        SingleSessionClient::connect(&SingleSessionClientConfig::new(client_config)).await?;
    println!(
        "core-single-session-client-session-request connected status={}",
        client.status()
    );
    let pairing_topic = client.pair(uri.trim()).await?;
    println!("core-single-session-client-session-request pairing_topic={pairing_topic}");

    let proposal = wait_for_single_session_client_proposal(&mut client).await?;
    print_and_assert_single_session_proposal_properties(&proposal)?;
    let approval = approval_for_probe(proposal.request())?;
    let session = client.approve_session(&proposal, approval).await?;
    print_and_assert_single_session_approved_session_properties(&session)?;

    let session_message = wait_for_single_session_client_session_request_event(&mut client).await?;
    print_session_message(
        "core-single-session-client-session-request live_event",
        &session_message,
    );
    let review = client.session_request_review(&session_message)?;
    print_session_request_review(&review);
    validate_session_request_review(&review)?;
    let response_ack = match response_mode.as_str() {
        "success" => {
            let result = env::var("WC_CORE_SESSION_REQUEST_RESULT_JSON").map_or_else(
                |_| Ok(json!("0xsigned-by-rust-client")),
                |value| parse_json_env(&value),
            )?;
            client
                .respond_session_request_success(&session_message, result)
                .await?
        }
        "error" => {
            client
                .respond_session_request_error(
                    &session_message,
                    JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected request."),
                )
                .await?
        }
        other => {
            bail!("unknown WC_CORE_SESSION_REQUEST_RESPONSE={other}; expected success or error")
        }
    };
    println!(
        "core-single-session-client-session-request response_ack={response_ack} mode={response_mode}"
    );

    let expected_outcome = match response_mode.as_str() {
        "success" => "session_request_response",
        "error" => "session_request_error",
        _ => unreachable!("validated response mode"),
    };
    let result = harness.expect_result(expected_outcome).await?;
    println!("core-single-session-client-session-request js_result={result}");
    harness.terminate();

    Ok(())
}

fn print_and_assert_single_session_proposal_properties(
    proposal: &SingleSessionProposal,
) -> Result<()> {
    println!(
        "core-single-session-client-session-request proposal_id={} pairing_topic={} verify_origin={} verify_validation={} verify_risk={:?} session_properties={} scoped_properties={}",
        proposal.proposal_id(),
        proposal.pairing_topic(),
        proposal.verify_context().verified.origin.as_str(),
        proposal.verify_context().verified.validation.as_str(),
        proposal.verify_risk(),
        proposal
            .request()
            .params
            .session_properties
            .as_ref()
            .map_or(0, BTreeMap::len),
        proposal
            .request()
            .params
            .scoped_properties
            .as_ref()
            .map_or(0, BTreeMap::len)
    );
    assert_optional_json_env_matches(
        "WC_JS_SESSION_PROPERTIES_JSON",
        proposal.request().params.session_properties.as_ref(),
        "core-single-session-client-session-request proposal_session_properties",
    )?;
    assert_optional_json_env_matches(
        "WC_JS_SCOPED_PROPERTIES_JSON",
        proposal.request().params.scoped_properties.as_ref(),
        "core-single-session-client-session-request proposal_scoped_properties",
    )?;
    assert_string_env_matches(
        "WC_JS_METADATA_URL",
        &proposal.request().params.proposer.metadata.url,
        "core-single-session-client-session-request proposal_metadata_url",
    )?;
    assert_optional_json_env_matches(
        "WC_JS_METADATA_REDIRECT_JSON",
        proposal
            .request()
            .params
            .proposer
            .metadata
            .redirect
            .as_ref(),
        "core-single-session-client-session-request proposal_metadata_redirect",
    )
}

fn print_and_assert_single_session_approved_session_properties(session: &Session) -> Result<()> {
    println!(
        "core-single-session-client-session-request active_session topic={} acknowledged={} namespaces={} expiry={} session_properties={} scoped_properties={}",
        session.topic,
        session.acknowledged,
        session.namespaces.len(),
        session.expiry,
        session.session_properties.as_ref().map_or(0, BTreeMap::len),
        session.scoped_properties.as_ref().map_or(0, BTreeMap::len)
    );
    assert_optional_json_env_matches(
        "WC_APPROVAL_SESSION_PROPERTIES_JSON",
        session.session_properties.as_ref(),
        "core-single-session-client-session-request approved_session_properties",
    )?;
    assert_optional_json_env_matches(
        "WC_APPROVAL_SCOPED_PROPERTIES_JSON",
        session.scoped_properties.as_ref(),
        "core-single-session-client-session-request approved_scoped_properties",
    )
}

async fn run_core_single_session_client_session_authenticate_probe(
    config: &RelayProbeConfig,
) -> Result<()> {
    let response_mode =
        env::var("WC_CORE_SESSION_AUTHENTICATE_RESPONSE").unwrap_or_else(|_| "reject".to_owned());
    if !matches!(response_mode.as_str(), "reject" | "approve") {
        bail!(
            "unknown WC_CORE_SESSION_AUTHENTICATE_RESPONSE={response_mode}; expected reject or approve"
        );
    }
    let (mut harness, uri) = AuthHarness::start(&response_mode).await?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!(
            "xtask-core-single-session-client-authenticate-{}",
            rpc_id()?.as_u64()
        ),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    let mut client =
        SingleSessionClient::connect(&SingleSessionClientConfig::new(client_config)).await?;
    println!(
        "core-single-session-client-session-authenticate connected status={}",
        client.status()
    );
    let pairing_topic = client.pair(uri.trim()).await?;
    println!("core-single-session-client-session-authenticate pairing_topic={pairing_topic}");

    let authenticate = wait_for_single_session_client_authenticate(&mut client).await?;
    println!(
        "core-single-session-client-session-authenticate request_id={} pairing_topic={}",
        authenticate.request_id(),
        authenticate.pairing_topic()
    );
    let review = client.session_authenticate_review(&authenticate)?;
    print_session_authenticate_review(&review);
    validate_session_authenticate_review(&review)?;

    let mut adopted_session_topic = None;
    let expected_outcome = match response_mode.as_str() {
        "approve" => {
            let cacao = signed_auth_cacao_from_review(&review)?;
            let namespaces = auth_session_namespaces(&review, &cacao)?;
            let approval = SessionAuthenticateApproval::new(auth_wallet_metadata(), vec![cacao])?
                .with_session_namespaces(namespaces);
            let outcome = client
                .approve_session_authenticate(&authenticate, approval)
                .await?;
            let adopted_session = outcome
                .session()
                .context("session authenticate approval did not adopt a session")?;
            println!(
                "core-single-session-client-session-authenticate approve_ack={} response_tag={} active_session_topic={} acknowledged={} namespaces={} expiry={}",
                outcome.response_ack(),
                SESSION_AUTHENTICATE_RESPONSE_TAG,
                adopted_session.topic,
                adopted_session.acknowledged,
                adopted_session.namespaces.len(),
                adopted_session.expiry
            );
            adopted_session_topic = Some(adopted_session.topic.to_string());
            "authenticate_response"
        }
        "reject" => {
            let reject_ack = client
                .reject_session_authenticate(
                    &authenticate,
                    JsonRpcError::new(
                        JsonRpcErrorCode::UserRejected,
                        "User rejected authentication.",
                    ),
                )
                .await?;
            println!(
                "core-single-session-client-session-authenticate reject_ack={reject_ack} response_tag={SESSION_AUTHENTICATE_REJECT_TAG}"
            );
            "authenticate_error"
        }
        _ => unreachable!("validated response mode"),
    };

    let result = harness.expect_result(expected_outcome).await?;
    if let Some(topic) = adopted_session_topic {
        validate_authenticate_response_session(&result, &topic)?;
    }
    println!("core-single-session-client-session-authenticate js_result={result}");
    harness.terminate();

    Ok(())
}

async fn run_core_single_session_client_disconnect_probe(config: &RelayProbeConfig) -> Result<()> {
    let (mut harness, uri) = SessionHarness::start("wait_session_delete", "disconnect").await?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!(
            "xtask-core-single-session-client-disconnect-{}",
            rpc_id()?.as_u64()
        ),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    let mut client =
        SingleSessionClient::connect(&SingleSessionClientConfig::new(client_config)).await?;
    println!(
        "core-single-session-client-disconnect connected status={}",
        client.status()
    );
    let pairing_topic = client.pair(uri.trim()).await?;
    println!("core-single-session-client-disconnect pairing_topic={pairing_topic}");

    let proposal = wait_for_single_session_client_proposal(&mut client).await?;
    println!(
        "core-single-session-client-disconnect proposal_id={} pairing_topic={} verify_origin={} verify_validation={} verify_risk={:?}",
        proposal.proposal_id(),
        proposal.pairing_topic(),
        proposal.verify_context().verified.origin.as_str(),
        proposal.verify_context().verified.validation.as_str(),
        proposal.verify_risk()
    );
    let approval = approval_for_probe(proposal.request())?;
    let session = client.approve_session(&proposal, approval).await?;
    println!(
        "core-single-session-client-disconnect active_session topic={} acknowledged={} namespaces={} expiry={}",
        session.topic,
        session.acknowledged,
        session.namespaces.len(),
        session.expiry
    );

    let request = client
        .disconnect(&session.topic, SessionDeleteParams::user_disconnected())
        .await?;
    println!(
        "core-single-session-client-disconnect request id={} method={} request_tag={} publish_ack={} active_session={}",
        request.request_id(),
        request.method(),
        request.request_tag(),
        request.publish_ack(),
        client.active_session().is_some()
    );

    let result = harness.expect_result("session_delete_received").await?;
    println!("core-single-session-client-disconnect js_result={result}");
    harness.terminate();

    Ok(())
}

async fn run_core_single_session_client_session_lifecycle_probe(
    config: &RelayProbeConfig,
) -> Result<()> {
    let action = CoreSingleSessionClientSessionLifecycleAction::from_env()?;
    let (mut harness, uri) = SessionHarness::start(action.harness_action(), action.label()).await?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!(
            "xtask-core-single-session-client-lifecycle-{}",
            rpc_id()?.as_u64()
        ),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    let mut client =
        SingleSessionClient::connect(&SingleSessionClientConfig::new(client_config)).await?;
    println!(
        "core-single-session-client-session-lifecycle connected status={}",
        client.status()
    );
    let pairing_topic = client.pair(uri.trim()).await?;
    println!("core-single-session-client-session-lifecycle pairing_topic={pairing_topic}");

    let proposal = wait_for_single_session_client_proposal(&mut client).await?;
    println!(
        "core-single-session-client-session-lifecycle proposal_id={} pairing_topic={} verify_origin={} verify_validation={} verify_risk={:?}",
        proposal.proposal_id(),
        proposal.pairing_topic(),
        proposal.verify_context().verified.origin.as_str(),
        proposal.verify_context().verified.validation.as_str(),
        proposal.verify_risk()
    );
    let approval = approval_for_probe(proposal.request())?;
    let session = client.approve_session(&proposal, approval).await?;
    println!(
        "core-single-session-client-session-lifecycle active_session topic={} acknowledged={} namespaces={} expiry={}",
        session.topic,
        session.acknowledged,
        session.namespaces.len(),
        session.expiry
    );

    run_core_single_session_client_session_lifecycle_action(&mut client, action, &session).await?;

    let result = harness.expect_result(action.expected_outcome()).await?;
    println!("core-single-session-client-session-lifecycle js_result={result}");
    harness.terminate();

    Ok(())
}

async fn run_core_single_session_client_session_lifecycle_action(
    client: &mut SingleSessionClient,
    action: CoreSingleSessionClientSessionLifecycleAction,
    session: &Session,
) -> Result<()> {
    match action {
        CoreSingleSessionClientSessionLifecycleAction::Ping
        | CoreSingleSessionClientSessionLifecycleAction::Delete
        | CoreSingleSessionClientSessionLifecycleAction::IncomingExtend
        | CoreSingleSessionClientSessionLifecycleAction::IncomingEvent => {
            let event =
                wait_for_single_session_client_session_lifecycle_event(client, action.label())
                    .await?;
            if let Some(message) = event.message() {
                print_session_message(
                    "core-single-session-client-session-lifecycle live_event",
                    message,
                );
                if action == CoreSingleSessionClientSessionLifecycleAction::IncomingEvent {
                    validate_incoming_session_event(message)?;
                }
            }
            println!(
                "core-single-session-client-session-lifecycle handled={} active_session={}",
                action.label(),
                client.active_session().is_some()
            );
            match action {
                CoreSingleSessionClientSessionLifecycleAction::IncomingExtend => {
                    let active_expiry = client
                        .active_session()
                        .map(|session| session.expiry)
                        .context("extended session was not retained")?;
                    println!("core-single-session-client-session-lifecycle active_session_expiry={active_expiry}");
                }
                CoreSingleSessionClientSessionLifecycleAction::Ping
                | CoreSingleSessionClientSessionLifecycleAction::Delete
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdatePending
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateApprove
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateReject
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsPending
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsApprove
                | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsReject
                | CoreSingleSessionClientSessionLifecycleAction::IncomingEvent
                | CoreSingleSessionClientSessionLifecycleAction::Update
                | CoreSingleSessionClientSessionLifecycleAction::Extend
                | CoreSingleSessionClientSessionLifecycleAction::Event => {}
            }
        }
        CoreSingleSessionClientSessionLifecycleAction::IncomingUpdatePending
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateApprove
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateReject
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsPending
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsApprove
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsReject => {
            handle_incoming_single_session_client_session_update(client, action).await?;
        }
        CoreSingleSessionClientSessionLifecycleAction::Update => {
            let response = client
                .update_session(&session.topic, &session.namespaces)
                .await?;
            print_session_lifecycle_response(&response);
        }
        CoreSingleSessionClientSessionLifecycleAction::Extend => {
            let response = client.extend_session(&session.topic).await?;
            print_session_lifecycle_response(&response);
            let active_expiry = client
                .active_session()
                .map(|session| session.expiry)
                .context("extended session was not retained")?;
            println!(
                "core-single-session-client-session-lifecycle active_session_expiry={active_expiry}"
            );
        }
        CoreSingleSessionClientSessionLifecycleAction::Event => {
            let params = session_event_params()?;
            let request = client.emit_session_event(&session.topic, &params).await?;
            println!(
                "core-single-session-client-session-lifecycle request id={} method={} request_tag={} publish_ack={}",
                request.request_id(),
                request.method(),
                request.request_tag(),
                request.publish_ack()
            );
        }
    }

    Ok(())
}

async fn handle_incoming_single_session_client_session_update(
    client: &mut SingleSessionClient,
    action: CoreSingleSessionClientSessionLifecycleAction,
) -> Result<()> {
    let event =
        wait_for_single_session_client_session_lifecycle_event(client, action.label()).await?;
    let message = event
        .message()
        .context("session update event did not carry a message")?;
    print_session_message(
        "core-single-session-client-session-lifecycle live_event",
        message,
    );
    let diff = client.session_update_diff(message)?;
    print_session_update_diff(&diff);
    assert_session_update_diff(action, &diff)?;

    match action {
        CoreSingleSessionClientSessionLifecycleAction::IncomingUpdatePending
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsPending => {
            println!(
                "core-single-session-client-session-lifecycle explicit_approval_required=true active_session={}",
                client.active_session().is_some()
            );
        }
        CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateApprove
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsApprove => {
            let response_ack = client.approve_session_update(message).await?;
            println!(
                "core-single-session-client-session-lifecycle update_approval_ack={response_ack}"
            );
            print_active_session_namespaces(client)?;
        }
        CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateReject
        | CoreSingleSessionClientSessionLifecycleAction::IncomingUpdateAddPermissionsReject => {
            let response_ack = client
                .reject_session_update(
                    message,
                    JsonRpcError::new(
                        JsonRpcErrorCode::UserRejected,
                        "User rejected session update.",
                    ),
                )
                .await?;
            println!(
                "core-single-session-client-session-lifecycle update_rejection_ack={response_ack}"
            );
            print_active_session_namespaces(client)?;
        }
        CoreSingleSessionClientSessionLifecycleAction::Ping
        | CoreSingleSessionClientSessionLifecycleAction::Delete
        | CoreSingleSessionClientSessionLifecycleAction::IncomingExtend
        | CoreSingleSessionClientSessionLifecycleAction::IncomingEvent
        | CoreSingleSessionClientSessionLifecycleAction::Update
        | CoreSingleSessionClientSessionLifecycleAction::Extend
        | CoreSingleSessionClientSessionLifecycleAction::Event => {
            unreachable!("validated incoming update action")
        }
    }

    Ok(())
}

fn assert_session_update_diff(
    action: CoreSingleSessionClientSessionLifecycleAction,
    diff: &wc_core::SessionNamespacesDiff,
) -> Result<()> {
    let Some((expected_added, expected_removed, expected_empty)) = action.expected_update_diff()
    else {
        return Ok(());
    };
    let added = count_permission_changes(diff.added());
    let removed = count_permission_changes(diff.removed());
    let empty = diff.is_empty();
    if (added, removed, empty) != (expected_added, expected_removed, expected_empty) {
        bail!(
            "unexpected session update diff for action {}: expected added={expected_added} removed={expected_removed} empty={expected_empty}, got added={added} removed={removed} empty={empty}",
            action.label()
        );
    }

    Ok(())
}

fn print_active_session_namespaces(client: &SingleSessionClient) -> Result<()> {
    let active_namespaces = client
        .active_session()
        .map(|session| session.namespaces.len())
        .context("updated session was not retained")?;
    println!(
        "core-single-session-client-session-lifecycle active_session_namespaces={active_namespaces}"
    );

    Ok(())
}

fn print_session_update_diff(diff: &wc_core::SessionNamespacesDiff) {
    println!(
        "core-single-session-client-session-lifecycle update_diff added={} removed={} empty={}",
        count_permission_changes(diff.added()),
        count_permission_changes(diff.removed()),
        diff.is_empty()
    );
}

fn count_permission_changes(set: &wc_core::SessionNamespacePermissionSet) -> usize {
    set.namespaces()
        .values()
        .map(|permissions| {
            permissions.chains().len()
                + permissions.accounts().len()
                + permissions.methods().len()
                + permissions.events().len()
        })
        .sum()
}

fn validate_incoming_session_event(message: &SessionReceivedMessage) -> Result<()> {
    let expected_chain =
        env::var("WC_JS_SESSION_EVENT_CHAIN_ID").unwrap_or_else(|_| "eip155:1".to_owned());
    let expected_event =
        env::var("WC_JS_SESSION_EVENT_NAME").unwrap_or_else(|_| "accountsChanged".to_owned());
    let SessionPayload::SessionEvent(request) = message.payload() else {
        bail!("incoming session event action received non-event payload");
    };
    if request.params.chain_id.as_str() != expected_chain {
        bail!(
            "incoming session event chain mismatch: expected {expected_chain}, got {}",
            request.params.chain_id
        );
    }
    if request.params.event.name.as_str() != expected_event {
        bail!(
            "incoming session event name mismatch: expected {expected_event}, got {}",
            request.params.event.name
        );
    }
    if let Ok(data_json) = env::var("WC_JS_SESSION_EVENT_DATA_JSON") {
        let expected_data = parse_json_env(&data_json)?;
        if request.params.event.data != expected_data {
            bail!(
                "incoming session event data mismatch: expected {expected_data}, got {}",
                request.params.event.data
            );
        }
    }

    Ok(())
}

async fn run_core_valid_session_request_probe(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    response_mode: &str,
    harness: &mut SessionHarness,
) -> Result<()> {
    let session_message =
        wait_for_valid_session_request_message(client, subscription, session).await?;
    print_session_message("core-js-session-request live_message", &session_message);

    let response_ack = match response_mode {
        "success" => {
            let result = env::var("WC_CORE_SESSION_REQUEST_RESULT_JSON").map_or_else(
                |_| Ok(json!("0xsigned-by-rust")),
                |value| parse_json_env(&value),
            )?;
            client
                .respond_session_request_success(subscription, &session_message, result)
                .await?
        }
        "error" => {
            client
                .respond_session_request_error(
                    subscription,
                    &session_message,
                    JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected request."),
                )
                .await?
        }
        other => {
            bail!("unknown WC_CORE_SESSION_REQUEST_RESPONSE={other}; expected success or error")
        }
    };
    println!("core-js-session-request response_ack={response_ack} mode={response_mode}");

    let expected_outcome = match response_mode {
        "success" => "session_request_response",
        "error" => "session_request_error",
        _ => unreachable!("validated response mode"),
    };
    let result = harness.expect_result(expected_outcome).await?;
    println!("core-js-session-request js_result={result}");

    Ok(())
}

async fn run_core_js_session_lifecycle_probe(config: &RelayProbeConfig) -> Result<()> {
    let action = CoreJsSessionLifecycleAction::from_env()?;
    let (mut harness, uri) = SessionHarness::start(action.harness_action(), action.label()).await?;

    let (mut client, pairing_subscription, approved, session) =
        run_core_pairing_uri_approve_probe(config, uri.trim()).await?;

    run_core_js_session_lifecycle_action(&mut client, approved.subscription(), &session, action)
        .await?;

    let result = harness.expect_result(action.expected_outcome()).await?;
    println!("core-js-session-lifecycle js_result={result}");

    let unsubscribe_result = client.unsubscribe_pairing(&pairing_subscription).await?;
    println!("core-js-session-lifecycle pairing_unsubscribe_ack={unsubscribe_result}");
    harness.terminate();

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreJsSessionLifecycleAction {
    Ping,
    Delete,
    IncomingUpdate,
    IncomingExtend,
    Update,
    Extend,
    Event,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreSingleSessionClientSessionLifecycleAction {
    Ping,
    Delete,
    IncomingUpdatePending,
    IncomingUpdateApprove,
    IncomingUpdateReject,
    IncomingUpdateAddPermissionsPending,
    IncomingUpdateAddPermissionsApprove,
    IncomingUpdateAddPermissionsReject,
    IncomingExtend,
    IncomingEvent,
    Update,
    Extend,
    Event,
}

impl CoreSingleSessionClientSessionLifecycleAction {
    fn from_env() -> Result<Self> {
        let value =
            env::var("WC_CORE_SESSION_LIFECYCLE_ACTION").unwrap_or_else(|_| "update".to_owned());
        match value.as_str() {
            "ping" => Ok(Self::Ping),
            "delete" => Ok(Self::Delete),
            "incoming-update" | "incoming-update-pending" => Ok(Self::IncomingUpdatePending),
            "incoming-update-approve" => Ok(Self::IncomingUpdateApprove),
            "incoming-update-reject" => Ok(Self::IncomingUpdateReject),
            "incoming-update-add-permissions" | "incoming-update-add-permissions-pending" => {
                Ok(Self::IncomingUpdateAddPermissionsPending)
            }
            "incoming-update-add-permissions-approve" => {
                Ok(Self::IncomingUpdateAddPermissionsApprove)
            }
            "incoming-update-add-permissions-reject" => {
                Ok(Self::IncomingUpdateAddPermissionsReject)
            }
            "incoming-extend" => Ok(Self::IncomingExtend),
            "incoming-event" => Ok(Self::IncomingEvent),
            "update" => Ok(Self::Update),
            "extend" => Ok(Self::Extend),
            "event" => Ok(Self::Event),
            other => {
                bail!(
                    "unknown WC_CORE_SESSION_LIFECYCLE_ACTION={other}; expected ping, delete, incoming-update, incoming-update-approve, incoming-update-reject, incoming-update-add-permissions, incoming-update-add-permissions-approve, incoming-update-add-permissions-reject, incoming-extend, incoming-event, update, extend, or event"
                )
            }
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Delete => "delete",
            Self::IncomingUpdatePending
            | Self::IncomingUpdateApprove
            | Self::IncomingUpdateReject
            | Self::IncomingUpdateAddPermissionsPending
            | Self::IncomingUpdateAddPermissionsApprove
            | Self::IncomingUpdateAddPermissionsReject
            | Self::Update => "update",
            Self::IncomingExtend | Self::Extend => "extend",
            Self::IncomingEvent | Self::Event => "event",
        }
    }

    const fn harness_action(self) -> &'static str {
        match self {
            Self::Ping => "session_ping",
            Self::Delete => "session_delete",
            Self::IncomingUpdatePending
            | Self::IncomingUpdateApprove
            | Self::IncomingUpdateReject => "session_update",
            Self::IncomingUpdateAddPermissionsPending
            | Self::IncomingUpdateAddPermissionsApprove
            | Self::IncomingUpdateAddPermissionsReject => "session_update_add_permissions",
            Self::IncomingExtend => "session_extend",
            Self::IncomingEvent => "session_event",
            Self::Update => "wait_session_update",
            Self::Extend => "wait_session_extend",
            Self::Event => "wait_session_event",
        }
    }

    const fn expected_outcome(self) -> &'static str {
        match self {
            Self::Ping => "session_ping_response",
            Self::Delete => "session_delete_sent",
            Self::IncomingUpdatePending | Self::IncomingUpdateAddPermissionsPending => {
                "session_update_timeout"
            }
            Self::IncomingUpdateApprove | Self::IncomingUpdateAddPermissionsApprove => {
                "session_update_acknowledged"
            }
            Self::IncomingUpdateReject | Self::IncomingUpdateAddPermissionsReject => {
                "session_update_error"
            }
            Self::IncomingExtend => "session_extend_acknowledged",
            Self::IncomingEvent => "session_event_sent",
            Self::Update => "session_update_received",
            Self::Extend => "session_extend_received",
            Self::Event => "session_event_received",
        }
    }

    const fn expected_update_diff(self) -> Option<(usize, usize, bool)> {
        match self {
            Self::IncomingUpdatePending
            | Self::IncomingUpdateApprove
            | Self::IncomingUpdateReject => Some((0, 0, true)),
            Self::IncomingUpdateAddPermissionsPending
            | Self::IncomingUpdateAddPermissionsApprove
            | Self::IncomingUpdateAddPermissionsReject => Some((4, 0, false)),
            Self::Ping
            | Self::Delete
            | Self::IncomingExtend
            | Self::IncomingEvent
            | Self::Update
            | Self::Extend
            | Self::Event => None,
        }
    }
}

impl CoreJsSessionLifecycleAction {
    fn from_env() -> Result<Self> {
        let value =
            env::var("WC_CORE_SESSION_LIFECYCLE_ACTION").unwrap_or_else(|_| "ping".to_owned());
        match value.as_str() {
            "ping" => Ok(Self::Ping),
            "delete" => Ok(Self::Delete),
            "incoming-update" => Ok(Self::IncomingUpdate),
            "incoming-extend" => Ok(Self::IncomingExtend),
            "update" => Ok(Self::Update),
            "extend" => Ok(Self::Extend),
            "event" => Ok(Self::Event),
            other => {
                bail!(
                    "unknown WC_CORE_SESSION_LIFECYCLE_ACTION={other}; expected ping, delete, incoming-update, incoming-extend, update, extend, or event"
                )
            }
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Delete => "delete",
            Self::IncomingUpdate | Self::Update => "update",
            Self::IncomingExtend | Self::Extend => "extend",
            Self::Event => "event",
        }
    }

    const fn harness_action(self) -> &'static str {
        match self {
            Self::Ping => "session_ping",
            Self::Delete => "session_delete",
            Self::IncomingUpdate => "session_update",
            Self::IncomingExtend => "session_extend",
            Self::Update => "wait_session_update",
            Self::Extend => "wait_session_extend",
            Self::Event => "wait_session_event",
        }
    }

    const fn expected_outcome(self) -> &'static str {
        match self {
            Self::Ping => "session_ping_response",
            Self::Delete => "session_delete_sent",
            Self::IncomingUpdate => "session_update_acknowledged",
            Self::IncomingExtend => "session_extend_acknowledged",
            Self::Update => "session_update_received",
            Self::Extend => "session_extend_received",
            Self::Event => "session_event_received",
        }
    }
}

async fn run_core_js_session_lifecycle_action(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    action: CoreJsSessionLifecycleAction,
) -> Result<()> {
    match action {
        CoreJsSessionLifecycleAction::Ping
        | CoreJsSessionLifecycleAction::Delete
        | CoreJsSessionLifecycleAction::IncomingUpdate
        | CoreJsSessionLifecycleAction::IncomingExtend => {
            respond_to_js_session_lifecycle_message(client, subscription, session, action).await
        }
        CoreJsSessionLifecycleAction::Update | CoreJsSessionLifecycleAction::Extend => {
            publish_js_session_lifecycle_request(client, subscription, session, action).await
        }
        CoreJsSessionLifecycleAction::Event => {
            publish_js_session_event(client, subscription, session).await
        }
    }
}

async fn publish_js_session_lifecycle_request(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    action: CoreJsSessionLifecycleAction,
) -> Result<()> {
    let request = match action {
        CoreJsSessionLifecycleAction::Update => {
            client
                .update_session(subscription, session, &session.namespaces)
                .await?
        }
        CoreJsSessionLifecycleAction::Extend => {
            client.extend_session(subscription, session).await?
        }
        _ => unreachable!("validated outbound lifecycle request action"),
    };
    println!(
        "core-js-session-lifecycle request id={} method={} request_tag={} publish_ack={}",
        request.request_id(),
        request.method(),
        request.request_tag(),
        request.publish_ack()
    );
    let response = client
        .next_session_lifecycle_response(subscription, &request)
        .await?
        .context("no outbound session lifecycle response received")?;
    print_session_lifecycle_response(&response);
    if let SessionLifecycleResponsePayload::Error(error) = response.payload() {
        bail!(
            "outbound session lifecycle request was rejected: id={} code={:?} message={}",
            error.id,
            error.error.code,
            error.error.message
        );
    }

    Ok(())
}

async fn publish_js_session_event(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
) -> Result<()> {
    let params = session_event_params()?;
    let request = client
        .emit_session_event(subscription, session, &params)
        .await?;
    println!(
        "core-js-session-lifecycle request id={} method={} request_tag={} publish_ack={}",
        request.request_id(),
        request.method(),
        request.request_tag(),
        request.publish_ack()
    );

    Ok(())
}

async fn respond_to_js_session_lifecycle_message(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    action: CoreJsSessionLifecycleAction,
) -> Result<()> {
    let message =
        wait_for_session_lifecycle_message(client, subscription, session, action.label()).await?;
    print_session_message("core-js-session-lifecycle live_message", &message);
    let response_ack = match action {
        CoreJsSessionLifecycleAction::Ping => {
            client.respond_session_ping(subscription, &message).await?
        }
        CoreJsSessionLifecycleAction::Delete => {
            client
                .respond_session_delete(subscription, &message)
                .await?
        }
        CoreJsSessionLifecycleAction::IncomingUpdate => {
            client
                .respond_session_update(subscription, &message)
                .await?
        }
        CoreJsSessionLifecycleAction::IncomingExtend => {
            client
                .respond_session_extend(subscription, &message)
                .await?
        }
        _ => unreachable!("validated inbound lifecycle response action"),
    };
    println!(
        "core-js-session-lifecycle response_ack={response_ack} action={}",
        action.label()
    );

    Ok(())
}

async fn wait_for_session_lifecycle_message(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    lifecycle_action: &str,
) -> Result<SessionReceivedMessage> {
    loop {
        let event = client
            .next_session_event(subscription, session)
            .await?
            .context("no session lifecycle message received")?;
        match (lifecycle_action, event) {
            ("ping", SessionClientEvent::SessionPing(message))
            | ("delete", SessionClientEvent::SessionDelete(message))
            | ("update", SessionClientEvent::SessionUpdate(message))
            | ("extend", SessionClientEvent::SessionExtend(message)) => return Ok(message),
            (_, SessionClientEvent::RejectedSessionRequest(rejection)) => {
                print_ignored_session_request_rejection(&rejection);
            }
            (_, event) => {
                if let Some(message) = event.message() {
                    print_ignored_session_message(message);
                }
            }
        }
    }
}

fn session_event_params() -> Result<SessionEventParams> {
    Ok(SessionEventParams {
        event: SessionEvent {
            name: SessionEventName::parse("accountsChanged")?,
            data: json!(["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]),
        },
        chain_id: "eip155:1".parse()?,
    })
}

async fn wait_for_valid_session_request_message(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
) -> Result<SessionReceivedMessage> {
    loop {
        let event = client
            .next_session_event(subscription, session)
            .await?
            .context("no wc_sessionRequest message received")?;
        match event {
            SessionClientEvent::SessionRequest(message) => return Ok(message),
            SessionClientEvent::RejectedSessionRequest(rejection) => {
                print_ignored_session_request_rejection(&rejection);
            }
            event => {
                if let Some(message) = event.message() {
                    print_ignored_session_message(message);
                }
            }
        }
    }
}

async fn wait_for_single_session_client_proposal(
    client: &mut SingleSessionClient,
) -> Result<SingleSessionProposal> {
    loop {
        let event = client
            .next_event()
            .await?
            .context("no single-session client proposal event received")?;
        match event {
            SingleSessionClientEvent::SessionProposal(proposal) => return Ok(*proposal),
            SingleSessionClientEvent::SessionAuthenticate(authenticate) => {
                print_ignored_single_session_client_authenticate(&authenticate);
            }
            SingleSessionClientEvent::SessionProposalExpired(expired) => {
                print_ignored_single_session_client_proposal_expired(&expired);
            }
            SingleSessionClientEvent::SessionAuthenticateExpired(expired) => {
                print_ignored_single_session_client_authenticate_expired(&expired);
            }
            SingleSessionClientEvent::PairingMessage(message) => {
                print_core_pairing_payload_metadata(
                    "core-single-session-client-session-request ignored_pairing_message",
                    &message,
                )?;
            }
            SingleSessionClientEvent::Session(event) => {
                print_ignored_single_session_client_event(&event);
            }
            SingleSessionClientEvent::SessionExpired(expired) => {
                print_ignored_single_session_client_expired(&expired);
            }
        }
    }
}

async fn wait_for_single_session_client_authenticate(
    client: &mut SingleSessionClient,
) -> Result<SingleSessionAuthenticate> {
    loop {
        let event = client
            .next_event()
            .await?
            .context("no single-session client authenticate event received")?;
        match event {
            SingleSessionClientEvent::SessionAuthenticate(authenticate) => {
                return Ok(*authenticate);
            }
            SingleSessionClientEvent::PairingMessage(message) => {
                print_core_pairing_payload_metadata(
                    "core-single-session-client-session-authenticate ignored_pairing_message",
                    &message,
                )?;
            }
            SingleSessionClientEvent::SessionProposal(proposal) => {
                println!(
                    "core-single-session-client-session-authenticate ignored_proposal id={} pairing_topic={}",
                    proposal.proposal_id(),
                    proposal.pairing_topic()
                );
            }
            SingleSessionClientEvent::SessionProposalExpired(expired) => {
                print_ignored_single_session_client_proposal_expired(&expired);
            }
            SingleSessionClientEvent::SessionAuthenticateExpired(expired) => {
                print_ignored_single_session_client_authenticate_expired(&expired);
            }
            SingleSessionClientEvent::Session(event) => {
                print_ignored_single_session_client_event(&event);
            }
            SingleSessionClientEvent::SessionExpired(expired) => {
                print_ignored_single_session_client_expired(&expired);
            }
        }
    }
}

async fn wait_for_single_session_client_session_request_event(
    client: &mut SingleSessionClient,
) -> Result<SessionReceivedMessage> {
    loop {
        let event = client
            .next_event()
            .await?
            .context("no single-session client session request event received")?;
        match event {
            SingleSessionClientEvent::Session(SessionClientEvent::SessionRequest(message)) => {
                return Ok(message);
            }
            SingleSessionClientEvent::Session(event) => {
                print_ignored_single_session_client_event(&event);
            }
            SingleSessionClientEvent::PairingMessage(message) => {
                print_core_pairing_payload_metadata(
                    "core-single-session-client-session-request ignored_pairing_message",
                    &message,
                )?;
            }
            SingleSessionClientEvent::SessionProposal(proposal) => {
                println!(
                    "core-single-session-client-session-request ignored_proposal id={} pairing_topic={}",
                    proposal.proposal_id(),
                    proposal.pairing_topic()
                );
            }
            SingleSessionClientEvent::SessionAuthenticate(authenticate) => {
                print_ignored_single_session_client_authenticate(&authenticate);
            }
            SingleSessionClientEvent::SessionProposalExpired(expired) => {
                print_ignored_single_session_client_proposal_expired(&expired);
            }
            SingleSessionClientEvent::SessionAuthenticateExpired(expired) => {
                print_ignored_single_session_client_authenticate_expired(&expired);
            }
            SingleSessionClientEvent::SessionExpired(expired) => {
                print_ignored_single_session_client_expired(&expired);
            }
        }
    }
}

async fn wait_for_single_session_client_session_lifecycle_event(
    client: &mut SingleSessionClient,
    lifecycle_action: &str,
) -> Result<SessionClientEvent> {
    loop {
        let event = client
            .next_event()
            .await?
            .context("no single-session client session lifecycle event received")?;
        match (lifecycle_action, event) {
            (
                "ping",
                SingleSessionClientEvent::Session(event @ SessionClientEvent::SessionPing(_)),
            )
            | (
                "delete",
                SingleSessionClientEvent::Session(event @ SessionClientEvent::SessionDelete(_)),
            )
            | (
                "update",
                SingleSessionClientEvent::Session(event @ SessionClientEvent::SessionUpdate(_)),
            )
            | (
                "extend",
                SingleSessionClientEvent::Session(event @ SessionClientEvent::SessionExtend(_)),
            )
            | (
                "event",
                SingleSessionClientEvent::Session(event @ SessionClientEvent::SessionEvent(_)),
            ) => {
                return Ok(event);
            }
            (_, SingleSessionClientEvent::Session(event)) => {
                print_ignored_single_session_client_event(&event);
            }
            (_, SingleSessionClientEvent::PairingMessage(message)) => {
                print_core_pairing_payload_metadata(
                    "core-single-session-client-session-lifecycle ignored_pairing_message",
                    &message,
                )?;
            }
            (_, SingleSessionClientEvent::SessionProposal(proposal)) => {
                println!(
                    "core-single-session-client-session-lifecycle ignored_proposal id={} pairing_topic={}",
                    proposal.proposal_id(),
                    proposal.pairing_topic()
                );
            }
            (_, SingleSessionClientEvent::SessionAuthenticate(authenticate)) => {
                print_ignored_single_session_client_authenticate(&authenticate);
            }
            (_, SingleSessionClientEvent::SessionProposalExpired(expired)) => {
                print_ignored_single_session_client_proposal_expired(&expired);
            }
            (_, SingleSessionClientEvent::SessionAuthenticateExpired(expired)) => {
                print_ignored_single_session_client_authenticate_expired(&expired);
            }
            (_, SingleSessionClientEvent::SessionExpired(expired)) => {
                print_ignored_single_session_client_expired(&expired);
            }
        }
    }
}

fn print_ignored_single_session_client_authenticate(authenticate: &SingleSessionAuthenticate) {
    println!(
        "ignored_single_session_client_authenticate id={} pairing_topic={}",
        authenticate.request_id(),
        authenticate.pairing_topic()
    );
}

fn print_ignored_single_session_client_proposal_expired(expired: &wc_core::SessionProposalExpired) {
    println!(
        "ignored_single_session_client_proposal_expired id={} pairing_topic={} expiry={} now={}",
        expired.proposal_id(),
        expired.pairing_topic(),
        expired.expiry(),
        expired.now_unix_seconds()
    );
}

fn print_ignored_single_session_client_authenticate_expired(
    expired: &wc_core::SessionAuthenticateRequestExpired,
) {
    println!(
        "ignored_single_session_client_authenticate_expired id={} pairing_topic={} expiry={} now={}",
        expired.request_id(),
        expired.pairing_topic(),
        expired.expiry(),
        expired.now_unix_seconds()
    );
}

fn print_ignored_single_session_client_expired(expired: &wc_core::SessionExpired) {
    println!(
        "ignored_single_session_client_expired topic={} expiry={}",
        expired.topic(),
        expired.expiry()
    );
}

fn print_ignored_single_session_client_event(event: &SessionClientEvent) {
    if let Some(message) = event.message() {
        print_ignored_session_message(message);
    } else if let Some(rejection) = event.rejection() {
        print_ignored_session_request_rejection(rejection);
    }
}

async fn run_core_raw_invalid_session_request_probe(
    config: &RelayProbeConfig,
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
    response_mode: &str,
) -> Result<()> {
    let mut peer = config.connect("publisher").await?;
    let subscription_id = peer.subscribe(subscription.topic().clone()).await?;
    println!("core-js-session-request adversarial_subscription_id={subscription_id}");

    let request = RawInvalidSessionRequest::new(response_mode, subscription)?;
    publish_raw_invalid_session_request(&mut peer, subscription, &request).await?;

    let rejection = wait_for_session_request_rejection(client, subscription, session).await?;
    validate_session_request_rejection(&rejection, &request)?;

    let response = read_session_request_error_response(&mut peer, subscription, &request).await?;
    println!(
        "core-js-session-request auto_reject id={} code={:?} message={} response_ack={}",
        response.id,
        response.error.code,
        response.error.message,
        rejection.response_ack()
    );

    peer.unsubscribe(subscription.topic(), &subscription_id)
        .await?;
    Ok(())
}

struct RawInvalidSessionRequest {
    chain_id: &'static str,
    method: &'static str,
    expiry_timestamp: u64,
    expected_code: JsonRpcErrorCode,
    message: String,
    request_id: u64,
}

impl RawInvalidSessionRequest {
    fn new(response_mode: &str, subscription: &SessionSubscription) -> Result<Self> {
        let now = unix_timestamp();
        let (chain_id, method, expiry_timestamp, expected_code) = match response_mode {
            "auto-reject-unauthorized-method" => (
                "eip155:1",
                "eth_sendTransaction",
                now + 300,
                JsonRpcErrorCode::UnauthorizedMethod,
            ),
            "auto-reject-unauthorized-chain" => (
                "eip155:137",
                "personal_sign",
                now + 300,
                JsonRpcErrorCode::UnsupportedChains,
            ),
            "auto-reject-expired" => (
                "eip155:1",
                "personal_sign",
                now.saturating_sub(1),
                JsonRpcErrorCode::Other(6),
            ),
            other => bail!("unknown raw invalid request mode: {other}"),
        };

        let request_id = rpc_id()?.as_u64();
        let plaintext = serde_json::to_string(&raw_session_request_json(
            request_id,
            chain_id,
            method,
            expiry_timestamp,
        ))
        .context("failed to serialize adversarial session request")?;
        let envelope = Envelope::encrypt_type_0(&plaintext, subscription.sym_key())
            .context("failed to encrypt adversarial session request")?;

        Ok(Self {
            chain_id,
            method,
            expiry_timestamp,
            expected_code,
            message: envelope.encode(EnvelopeEncoding::Base64),
            request_id,
        })
    }
}

fn raw_session_request_json(
    request_id: u64,
    chain_id: &str,
    method: &str,
    expiry_timestamp: u64,
) -> Value {
    json!({
        "id": request_id,
        "jsonrpc": "2.0",
        "method": "wc_sessionRequest",
        "params": {
            "chainId": chain_id,
            "request": {
                "method": method,
                "params": ["0x68656c6c6f", "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
                "expiryTimestamp": expiry_timestamp,
            },
        },
    })
}

async fn publish_raw_invalid_session_request(
    peer: &mut RelaySocket,
    subscription: &SessionSubscription,
    request: &RawInvalidSessionRequest,
) -> Result<()> {
    peer.publish(
        IrnPublish::new(
            subscription.topic().clone(),
            request.message.clone(),
            5 * 60,
            1108,
        )
        .with_prompt(true),
    )
    .await?;
    println!(
        "core-js-session-request adversarial_request id={} chain_id={} method={} expiry={} publish_ack=true",
        request.request_id, request.chain_id, request.method, request.expiry_timestamp
    );
    Ok(())
}

async fn wait_for_session_request_rejection(
    client: &mut PairingClient,
    subscription: &SessionSubscription,
    session: &Session,
) -> Result<SessionRequestRejection> {
    loop {
        let event = client
            .next_session_event(subscription, session)
            .await?
            .context("no adversarial wc_sessionRequest message received")?;
        match event {
            SessionClientEvent::RejectedSessionRequest(rejection) => return Ok(rejection),
            event => {
                if let Some(message) = event.message() {
                    print_ignored_session_message(message);
                }
            }
        }
    }
}

fn print_ignored_session_request_rejection(rejection: &SessionRequestRejection) {
    println!(
        "core-js-session-request ignored_session_request_rejection topic={} id={} code={:?} message={} response_ack={}",
        rejection.topic(),
        rejection.request_id(),
        rejection.error().code,
        rejection.error().message,
        rejection.response_ack()
    );
}

fn print_ignored_session_message(message: &SessionReceivedMessage) {
    println!(
        "core-js-session-request ignored_session_message tag_present={} tag={} payload={:?}",
        message.tag().is_some(),
        message.tag().unwrap_or_default(),
        message.payload()
    );
}

fn print_session_request_review(review: &SessionRequestReview) {
    let verify_hash = review
        .verify_attestation_hash()
        .map_or("missing", |hash| hash.as_str());
    println!(
        "core-single-session-client-session-request review topic={} id={} chain_id={} method={} expiry={:?} verify_hash={} verify_origin={} verify_validation={} verify_risk={:?} params={}",
        review.topic(),
        review.request_id(),
        review.chain_id(),
        review.method(),
        review.expiry_timestamp(),
        verify_hash,
        review.verify_context().verified.origin.as_str(),
        review.verify_context().verified.validation.as_str(),
        review.verify_risk(),
        review.params()
    );
    match review.wallet_call_request() {
        Ok(Some(WalletCallRequest::GetCapabilities(params))) => {
            println!(
                "core-single-session-client-session-request wallet_call method=wallet_getCapabilities address={} chains={}",
                params.0,
                params
                    .1
                    .as_ref()
                    .map_or_else(|| "<all>".to_owned(), |chains| chains.join(","))
            );
        }
        Ok(Some(WalletCallRequest::SendCalls(params))) => {
            println!(
                "core-single-session-client-session-request wallet_call method=wallet_sendCalls chain_id={} from={:?} atomic_required={} calls={}",
                params.0.chain_id,
                params.0.from,
                params.0.atomic_required,
                params.0.calls.len()
            );
        }
        Ok(Some(WalletCallRequest::GetCallsStatus(params))) => {
            println!(
                "core-single-session-client-session-request wallet_call method=wallet_getCallsStatus id={}",
                params.0
            );
        }
        Ok(Some(WalletCallRequest::ShowCallsStatus(params))) => {
            println!(
                "core-single-session-client-session-request wallet_call method=wallet_showCallsStatus id={}",
                params.0
            );
        }
        Ok(None) => {}
        Err(error) => {
            println!(
                "core-single-session-client-session-request wallet_call_parse_error method={} error={error}",
                review.method()
            );
        }
    }
}

fn print_session_authenticate_review(review: &SessionAuthenticateReview) {
    println!(
        "core-single-session-client-session-authenticate review topic={} id={} requester_name={} domain={} aud={} chains={} expiry={} verify_origin={} verify_validation={} verify_risk={:?}",
        review.topic(),
        review.request_id(),
        review.requester().metadata.name,
        review.auth_payload().domain,
        review.auth_payload().aud,
        review
            .auth_payload()
            .chains
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        review.expiry_timestamp(),
        review.verify_context().verified.origin.as_str(),
        review.verify_context().verified.validation.as_str(),
        review.verify_risk()
    );
}

fn validate_session_authenticate_review(review: &SessionAuthenticateReview) -> Result<()> {
    let expected_domain =
        env::var("WC_JS_AUTH_DOMAIN").unwrap_or_else(|_| "example.com".to_owned());
    let expected_aud =
        env::var("WC_JS_AUTH_URI").unwrap_or_else(|_| "https://example.com/login".to_owned());
    let expected_chains = env::var("WC_JS_AUTH_CHAINS").unwrap_or_else(|_| "eip155:1".to_owned());
    let chains = review
        .auth_payload()
        .chains
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");

    if review.auth_payload().domain != expected_domain {
        bail!(
            "session authenticate domain mismatch: expected {expected_domain}, got {}",
            review.auth_payload().domain
        );
    }
    if review.auth_payload().aud != expected_aud {
        bail!(
            "session authenticate audience mismatch: expected {expected_aud}, got {}",
            review.auth_payload().aud
        );
    }
    if chains != expected_chains {
        bail!("session authenticate chains mismatch: expected {expected_chains}, got {chains}");
    }
    if review.is_expired_at(unix_timestamp()) {
        bail!(
            "session authenticate review is expired: id={} expiry={}",
            review.request_id(),
            review.expiry_timestamp()
        );
    }

    Ok(())
}

/// Checks the maintained SDK session topic against the Rust-adopted topic.
///
/// The auth approval probe uses this as the live parity assertion: both peers
/// must derive the same authenticated session topic from the type-1 response
/// key agreement.
fn validate_authenticate_response_session(
    result: &Value,
    active_session_topic: &str,
) -> Result<()> {
    let session = result
        .get("result")
        .and_then(|result| result.get("session"))
        .context("authenticate response did not include a session")?;
    let js_topic = session
        .get("topic")
        .and_then(Value::as_str)
        .context("authenticate response session did not include a topic")?;
    if js_topic != active_session_topic {
        bail!("auth session topic mismatch: JS={js_topic}, Rust={active_session_topic}");
    }
    let acknowledged = session
        .get("acknowledged")
        .and_then(Value::as_bool)
        .context("authenticate response session did not include acknowledged")?;
    if !acknowledged {
        bail!("authenticate response session is not acknowledged");
    }

    Ok(())
}

fn auth_wallet_metadata() -> DappMetadata {
    DappMetadata {
        name: "walletconnect-client-poc Rust auth wallet".to_owned(),
        description: "Live WalletConnect authentication responder for Rust probes".to_owned(),
        url: "https://github.com/BlockstreamResearch/walletconnect-client-poc".to_owned(),
        icons: vec!["https://walletconnect.com/walletconnect-logo.png".to_owned()],
        verify_url: None,
        redirect: None,
    }
}

/// Builds the same default auth namespace shape used by the JS harness.
///
/// The maintained utility maps signed accounts to namespaces, copies approved
/// methods, and sets `chainChanged` plus `accountsChanged`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/namespaces.ts#L274-L287>
///
/// ```text
/// values.events = ["chainChanged", "accountsChanged"];
/// ```
fn auth_session_namespaces(
    review: &SessionAuthenticateReview,
    cacao: &Cacao,
) -> Result<SessionNamespaces> {
    let account = cacao.p.iss.account_id();
    let chain = account.chain_id();
    let methods = env::var("WC_JS_AUTH_METHODS")
        .unwrap_or_else(|_| "personal_sign".to_owned())
        .split(',')
        .filter(|method| !method.is_empty())
        .map(SessionMethod::parse)
        .collect::<Result<Vec<_>, _>>()?;
    if methods.is_empty() {
        bail!("auth approval session namespaces require at least one method");
    }
    if !review
        .auth_payload()
        .chains
        .iter()
        .any(|requested| requested == &chain)
    {
        bail!("signed auth chain {chain} was not requested by wc_sessionAuthenticate");
    }

    let namespace = NamespaceKey::parse(chain.namespace())?;
    let mut namespaces = BTreeMap::new();
    namespaces.insert(
        namespace,
        SessionNamespace {
            chains: Some(vec![chain]),
            accounts: vec![account],
            methods,
            events: vec![
                SessionEventName::parse("chainChanged")?,
                SessionEventName::parse("accountsChanged")?,
            ],
        },
    );

    Ok(namespaces)
}

fn signed_auth_cacao_from_review(review: &SessionAuthenticateReview) -> Result<Cacao> {
    let workspace_root = workspace_root()?;
    let harness_dir = workspace_root.join("tools/js-harness");
    let auth_payload = serde_json::to_string(review.auth_payload())?;
    let output = Command::new("bun")
        .args(["run", "sign-auth"])
        .current_dir(&harness_dir)
        .env("WC_JS_AUTH_PAYLOAD_JSON", auth_payload)
        .output()
        .with_context(|| {
            format!(
                "failed to run auth signing harness in {}",
                harness_dir.display()
            )
        })?;

    if !output.status.success() {
        bail!(
            "auth signing harness failed status={} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let signed = serde_json::from_slice::<SignedAuthFixture>(&output.stdout)
        .context("auth signing harness returned invalid JSON")?;
    println!(
        "core-single-session-client-session-authenticate signed_cacao address={} iss={}",
        signed.address, signed.iss
    );
    Ok(signed.cacao)
}

fn validate_session_request_review(review: &SessionRequestReview) -> Result<()> {
    let expected_chain =
        env::var("WC_JS_SESSION_REQUEST_CHAIN_ID").unwrap_or_else(|_| "eip155:1".to_owned());
    let expected_method =
        env::var("WC_JS_SESSION_REQUEST_METHOD").unwrap_or_else(|_| "personal_sign".to_owned());
    if review.chain_id().as_str() != expected_chain {
        bail!(
            "session request review chain mismatch: expected {expected_chain}, got {}",
            review.chain_id()
        );
    }
    if review.method().as_str() != expected_method {
        bail!(
            "session request review method mismatch: expected {expected_method}, got {}",
            review.method()
        );
    }
    if let Ok(params_json) = env::var("WC_JS_SESSION_REQUEST_PARAMS_JSON") {
        let expected_params = parse_json_env(&params_json)?;
        if review.params() != &expected_params {
            bail!(
                "session request review params mismatch: expected {expected_params}, got {}",
                review.params()
            );
        }
    }
    if review.is_expired_at(unix_timestamp()) {
        bail!(
            "session request review is expired: id={} expiry={:?}",
            review.request_id(),
            review.expiry_timestamp()
        );
    }

    Ok(())
}

fn validate_session_request_rejection(
    rejection: &SessionRequestRejection,
    request: &RawInvalidSessionRequest,
) -> Result<()> {
    if rejection.request_id() != request.request_id {
        bail!(
            "invalid request response id mismatch: expected {}, got {}",
            request.request_id,
            rejection.request_id()
        );
    }
    if rejection.error().code != request.expected_code {
        bail!(
            "invalid request error code mismatch: expected {:?}, got {:?}",
            request.expected_code,
            rejection.error().code
        );
    }
    if !rejection.response_ack() {
        bail!("invalid request error response was not acknowledged by relay");
    }
    Ok(())
}

async fn read_session_request_error_response(
    peer: &mut RelaySocket,
    subscription: &SessionSubscription,
    request: &RawInvalidSessionRequest,
) -> Result<JsonRpcErrorResponse> {
    for _ in 0..4 {
        let delivery = peer
            .read_any_subscription_for_topic(subscription.topic(), READ_TIMEOUT)
            .await?
            .context("timed out waiting for invalid request error response")?;
        if delivery.data.message == request.message {
            println!("core-js-session-request ignored_adversarial_echo=true");
            continue;
        }
        if delivery.data.tag != Some(SESSION_REQUEST_RESPONSE_TAG) {
            println!(
                "core-js-session-request ignored_session_delivery tag_present={} tag={}",
                delivery.data.tag.is_some(),
                delivery.data.tag.unwrap_or_default()
            );
            continue;
        }

        let envelope = Envelope::decode(&delivery.data.message, EnvelopeEncoding::Base64)
            .context("failed to decode invalid request error response envelope")?;
        let plaintext = envelope
            .decrypt(subscription.sym_key())
            .context("failed to decrypt invalid request error response")?;
        let response = serde_json::from_str::<JsonRpcErrorResponse>(&plaintext)
            .context("invalid request error response was not JSON-RPC error")?;
        if response.id != request.request_id {
            bail!(
                "invalid request error response id mismatch: expected {}, got {}",
                request.request_id,
                response.id
            );
        }
        if response.error.code != request.expected_code {
            bail!(
                "invalid request response code mismatch: expected {:?}, got {:?}",
                request.expected_code,
                response.error.code
            );
        }

        return Ok(response);
    }

    bail!("did not receive invalid request error response with tag {SESSION_REQUEST_RESPONSE_TAG}")
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

    let fetch_response = subscriber.fetch_messages(pairing.topic()).await?;
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

    let subscription_id = subscriber.subscribe(pairing.topic().clone()).await?;
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

    let unsubscribe_result = subscriber
        .unsubscribe(pairing.topic(), &subscription_id)
        .await?;
    println!("pairing-uri unsubscribe_ack={unsubscribe_result}");

    Ok(())
}

async fn run_core_pairing_uri_approve_probe(
    config: &RelayProbeConfig,
    uri: &str,
) -> Result<(PairingClient, PairingSubscription, ApprovedSession, Session)> {
    let pairing = PairingUri::parse(uri).context("failed to parse pairing URI")?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!("xtask-core-approve-{}", rpc_id()?.as_u64()),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    println!(
        "core-pairing-approve project_id={} relay_url={} topic={} version={} relay_protocol={} sym_key={} expiry={:?} expired_now={}",
        redact(&config.project_id),
        config.relay_url,
        pairing.topic(),
        pairing.version(),
        pairing.relay().protocol(),
        redact(pairing.sym_key().as_str()),
        pairing.expiry_timestamp(),
        pairing.is_expired_at(unix_timestamp())
    );

    let mut client = PairingClient::connect(&client_config).await?;
    println!("core-pairing-approve connected status={}", client.status());

    let fetched = client.fetch_pairing_messages(&pairing).await?;
    println!(
        "core-pairing-approve fetch_messages count={}",
        fetched.len()
    );
    for (index, message) in fetched.iter().enumerate() {
        print_core_pairing_payload_metadata(
            &format!("core-pairing-approve fetched index={index}"),
            message,
        )?;
    }

    let subscription = client.subscribe_pairing(&pairing).await?;
    println!(
        "core-pairing-approve subscription_id={}",
        subscription.subscription_id()
    );

    let proposal = if let Some(proposal) = first_session_proposal_request(&fetched) {
        proposal
    } else {
        match client.next_pairing_message(&subscription).await? {
            Some(message) => {
                print_core_pairing_payload_metadata("core-pairing-approve live_message", &message)?;
                first_session_proposal_request(std::slice::from_ref(&message))
                    .context("live pairing message was not wc_sessionPropose")?
            }
            None => bail!("no wc_sessionPropose message received"),
        }
    };

    let approval = approval_for_probe(&proposal)?;
    let approved = client
        .approve_session_proposal(&subscription, &proposal, approval)
        .await?;
    println!(
        "core-pairing-approve proposal_id={} session_topic={} settle_request_id={} proposal_response_ack={} session_settle_ack={}",
        proposal.id,
        approved.session_topic(),
        approved.session_settle_request_id(),
        approved.proposal_response_ack(),
        approved.session_settle_ack()
    );
    let session = receive_and_print_session_settle_response(&mut client, &approved).await?;

    Ok((client, subscription, approved, session))
}

async fn receive_and_print_session_settle_response(
    client: &mut PairingClient,
    approved: &ApprovedSession,
) -> Result<Session> {
    let settle_response = client
        .next_session_settle_response(approved)
        .await?
        .context("no wc_sessionSettle response received")?;
    print_session_settle_response(&settle_response);
    let session = approved.acknowledged_session(&settle_response)?;

    println!(
        "core-pairing-approve active_session topic={} acknowledged={} controller={} peer_name={} self_name={} namespaces={} expiry={} transport={:?}",
        session.topic,
        session.acknowledged,
        session.controller,
        session.peer.metadata.name,
        session.self_participant.metadata.name,
        session.namespaces.len(),
        session.expiry,
        session.transport_type
    );

    Ok(session)
}

fn print_session_settle_response(settle_response: &SessionSettleResponseMessage) {
    match settle_response.payload() {
        SessionSettleResponsePayload::Success(response) => println!(
            "core-pairing-approve settle_response success=true topic={} id={} tag_present={} tag={} published_at={} message_len={}",
            settle_response.topic(),
            response.id,
            settle_response.tag().is_some(),
            settle_response.tag().unwrap_or_default(),
            settle_response.published_at(),
            settle_response.encoded_message_len()
        ),
        SessionSettleResponsePayload::Error(response) => println!(
            "core-pairing-approve settle_response success=false topic={} id={} error_code={:?} error_message={} tag_present={} tag={} published_at={} message_len={}",
            settle_response.topic(),
            response.id,
            response.error.code,
            response.error.message,
            settle_response.tag().is_some(),
            settle_response.tag().unwrap_or_default(),
            settle_response.published_at(),
            settle_response.encoded_message_len()
        ),
    }
}

fn print_session_lifecycle_response(response: &SessionLifecycleResponseMessage) {
    match response.payload() {
        SessionLifecycleResponsePayload::Success(ack) => println!(
            "core-js-session-lifecycle response success=true topic={} id={} tag_present={} tag={} published_at={} message_len={}",
            response.topic(),
            ack.id,
            response.tag().is_some(),
            response.tag().unwrap_or_default(),
            response.published_at(),
            response.encoded_message_len()
        ),
        SessionLifecycleResponsePayload::Error(error) => println!(
            "core-js-session-lifecycle response success=false topic={} id={} error_code={:?} error_message={} tag_present={} tag={} published_at={} message_len={}",
            response.topic(),
            error.id,
            error.error.code,
            error.error.message,
            response.tag().is_some(),
            response.tag().unwrap_or_default(),
            response.published_at(),
            response.encoded_message_len()
        ),
    }
}

fn print_session_message(label: &str, message: &SessionReceivedMessage) {
    println!(
        "{label} topic={} message_len={} decrypted_len={} tag_present={} tag={} published_at={}",
        message.topic(),
        message.encoded_message_len(),
        message.plaintext_len(),
        message.tag().is_some(),
        message.tag().unwrap_or_default(),
        message.published_at()
    );

    match message.payload() {
        SessionPayload::SessionRequest(request) => println!(
            "{label} session_request id={} chain_id={} method={} params={}",
            request.id,
            request.params.chain_id,
            request.params.request.method,
            request.params.request.params
        ),
        SessionPayload::SessionUpdate(request) => println!(
            "{label} session_update id={} namespaces={}",
            request.id,
            request.params.namespaces.len()
        ),
        SessionPayload::SessionExtend(request) => {
            println!(
                "{label} session_extend id={} params={:?}",
                request.id, request.params
            );
        }
        SessionPayload::SessionEvent(request) => {
            println!(
                "{label} session_event id={} chain_id={} event_name={} data={}",
                request.id,
                request.params.chain_id,
                request.params.event.name,
                request.params.event.data
            );
        }
        SessionPayload::SessionPing(request) => {
            println!("{label} session_ping id={} params=empty", request.id);
        }
        SessionPayload::SessionDelete(request) => {
            println!(
                "{label} session_delete id={} code={} message={}",
                request.id, request.params.code, request.params.message
            );
        }
        SessionPayload::Sign(method) => {
            println!("{label} sign_request method={method}");
        }
        SessionPayload::Unknown(method) => {
            println!("{label} unknown_request method={method}");
        }
        SessionPayload::Missing => {
            println!("{label} missing_method=true");
        }
    }
}

async fn run_core_pairing_uri_reject_probe(config: &RelayProbeConfig, uri: &str) -> Result<()> {
    let pairing = PairingUri::parse(uri).context("failed to parse pairing URI")?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!("xtask-core-reject-{}", rpc_id()?.as_u64()),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    println!(
        "core-pairing-reject project_id={} relay_url={} topic={} version={} relay_protocol={} sym_key={} expiry={:?} expired_now={}",
        redact(&config.project_id),
        config.relay_url,
        pairing.topic(),
        pairing.version(),
        pairing.relay().protocol(),
        redact(pairing.sym_key().as_str()),
        pairing.expiry_timestamp(),
        pairing.is_expired_at(unix_timestamp())
    );

    let mut client = PairingClient::connect(&client_config).await?;
    println!("core-pairing-reject connected status={}", client.status());

    let fetched = client.fetch_pairing_messages(&pairing).await?;
    println!("core-pairing-reject fetch_messages count={}", fetched.len());
    for (index, message) in fetched.iter().enumerate() {
        print_core_pairing_payload_metadata(
            &format!("core-pairing-reject fetched index={index}"),
            message,
        )?;
    }

    let subscription = client.subscribe_pairing(&pairing).await?;
    println!(
        "core-pairing-reject subscription_id={}",
        subscription.subscription_id()
    );

    let proposal_id = if let Some(proposal_id) = first_session_proposal_id(&fetched) {
        proposal_id
    } else {
        match client.next_pairing_message(&subscription).await? {
            Some(message) => {
                print_core_pairing_payload_metadata("core-pairing-reject live_message", &message)?;
                first_session_proposal_id(std::slice::from_ref(&message))
                    .context("live pairing message was not wc_sessionPropose")?
            }
            None => bail!("no wc_sessionPropose message received"),
        }
    };

    let reject_ack = client
        .reject_session_proposal(
            &subscription,
            proposal_id,
            JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
        )
        .await?;
    println!("core-pairing-reject proposal_id={proposal_id} reject_publish_ack={reject_ack}");

    let unsubscribe_result = client.unsubscribe_pairing(&subscription).await?;
    println!("core-pairing-reject unsubscribe_ack={unsubscribe_result}");

    Ok(())
}

async fn run_core_pairing_uri_probe(config: &RelayProbeConfig, uri: &str) -> Result<()> {
    let pairing = PairingUri::parse(uri).context("failed to parse pairing URI")?;
    let mut client_config = PairingClientConfig::new(
        config.project_id.clone(),
        config.subscriber_auth_seed,
        format!("xtask-core-{}", rpc_id()?.as_u64()),
    );
    client_config.relay_url.clone_from(&config.relay_url);
    client_config.user_agent.clone_from(&config.user_agent);
    client_config.receive_timeout = pairing_uri_wait_timeout();

    println!(
        "core-pairing project_id={} relay_url={} topic={} version={} relay_protocol={} sym_key={} expiry={:?} expired_now={}",
        redact(&config.project_id),
        config.relay_url,
        pairing.topic(),
        pairing.version(),
        pairing.relay().protocol(),
        redact(pairing.sym_key().as_str()),
        pairing.expiry_timestamp(),
        pairing.is_expired_at(unix_timestamp())
    );

    let mut client = PairingClient::connect(&client_config).await?;
    println!("core-pairing connected status={}", client.status());

    let fetched = client.fetch_pairing_messages(&pairing).await?;
    println!("core-pairing fetch_messages count={}", fetched.len());
    for (index, message) in fetched.iter().enumerate() {
        print_core_pairing_payload_metadata(
            &format!("core-pairing fetched index={index}"),
            message,
        )?;
    }

    let subscription = client.subscribe_pairing(&pairing).await?;
    println!(
        "core-pairing subscription_id={}",
        subscription.subscription_id()
    );

    match client.next_pairing_message(&subscription).await? {
        Some(message) => {
            print_core_pairing_payload_metadata("core-pairing live_message", &message)?;
        }
        None => println!("core-pairing live_message=false"),
    }

    let unsubscribe_result = client.unsubscribe_pairing(&subscription).await?;
    println!("core-pairing unsubscribe_ack={unsubscribe_result}");

    Ok(())
}

fn first_session_proposal_id(messages: &[PairingReceivedMessage]) -> Option<u64> {
    messages.iter().find_map(|message| match message.payload() {
        PairingPayload::SessionProposal(request) => Some(request.id),
        _ => None,
    })
}

fn first_session_proposal_request(
    messages: &[PairingReceivedMessage],
) -> Option<JsonRpcRequest<SessionProposeParams>> {
    messages.iter().find_map(|message| match message.payload() {
        PairingPayload::SessionProposal(request) => Some((**request).clone()),
        _ => None,
    })
}

fn approval_for_probe(
    proposal: &JsonRpcRequest<SessionProposeParams>,
) -> Result<SessionProposalApproval> {
    probe_wallet_capabilities()?
        .plan_session_approval(
            proposal,
            probe_wallet_metadata(),
            unix_timestamp() + DEFAULT_SESSION_EXPIRY_SECONDS,
        )
        .map_err(Into::into)
}

fn probe_wallet_capabilities() -> Result<WalletCapabilities> {
    let chains = env_list("WC_APPROVAL_CHAINS", "eip155:1")?
        .into_iter()
        .map(Caip2ChainId::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let methods = env_list("WC_APPROVAL_METHODS", "personal_sign,eth_signTypedData_v4")?
        .into_iter()
        .map(SessionMethod::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let events = env_list("WC_APPROVAL_EVENTS", "accountsChanged,chainChanged")?
        .into_iter()
        .map(SessionEventName::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let address = env::var("WC_APPROVAL_ACCOUNT_ADDRESS")
        .unwrap_or_else(|_| "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".to_owned());

    let mut capabilities = Vec::new();
    for chain in chains {
        let account = Caip10AccountId::from_parts(&chain, &address)?;
        capabilities.push(WalletChainCapability::new(
            chain,
            vec![account],
            methods.clone(),
            events.clone(),
        )?);
    }

    let mut capabilities = WalletCapabilities::new(capabilities)?;
    if let Ok(value) = env::var("WC_APPROVAL_SESSION_PROPERTIES_JSON") {
        capabilities =
            capabilities.with_session_properties(serde_json::from_value(parse_json_env(&value)?)?);
    }
    if let Ok(value) = env::var("WC_APPROVAL_SCOPED_PROPERTIES_JSON") {
        capabilities =
            capabilities.with_scoped_properties(serde_json::from_value(parse_json_env(&value)?)?);
    }

    Ok(capabilities)
}

fn env_list(name: &str, default: &str) -> Result<Vec<String>> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    let values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();

    if values.is_empty() {
        bail!("{name} must contain at least one comma-separated value");
    }

    Ok(values)
}

fn probe_wallet_metadata() -> DappMetadata {
    DappMetadata {
        name: "walletconnect-client-poc Rust wallet".to_owned(),
        description: "Live WalletConnect approval probe for Rust core".to_owned(),
        url: "https://github.com/BlockstreamResearch/walletconnect-client-poc".to_owned(),
        icons: vec!["https://walletconnect.com/walletconnect-logo.png".to_owned()],
        verify_url: None,
        redirect: None,
    }
}

fn print_pairing_payload_metadata(
    label: &str,
    data: &IrnSubscriptionData,
    sym_key: &PairingSymKey,
) -> Result<()> {
    let payload = PairingMessage::decode_relay_message(&data.message, sym_key)
        .with_context(|| format!("{label} failed to decode pairing message"))?;

    println!(
        "{label} envelope_type={:?} decrypted_len={} jsonrpc={} id={} method={} params_keys={}",
        payload.envelope_type(),
        payload.plaintext().len(),
        payload
            .json()
            .get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or("<none>"),
        json_id(payload.json()),
        pairing_message_method_label(payload.method()),
        params_keys(payload.json())
    );

    match payload.method() {
        PairingMessageMethod::Sign(SignMethod::SessionPropose) => {
            print_session_proposal_summary(label, payload.json().clone())?;
        }
        PairingMessageMethod::Sign(method) => {
            println!("{label} sign_request method={method}");
        }
        PairingMessageMethod::Pairing(method) => {
            print_pairing_payload_summary(label, *method, payload.json().clone())?;
        }
        PairingMessageMethod::Unknown(method) => {
            println!("{label} unknown_request method={method}");
        }
        PairingMessageMethod::Missing => {
            println!("{label} missing_method=true");
        }
    }

    if pairing_uri_print_json() {
        let pretty = serde_json::to_string_pretty(payload.json())
            .with_context(|| format!("{label} failed to format decrypted JSON"))?;
        println!("{label} decrypted_json=\n{pretty}");
    }

    Ok(())
}

fn print_core_pairing_payload_metadata(
    label: &str,
    received: &PairingReceivedMessage,
) -> Result<()> {
    let payload = received.message();

    println!(
        "{label} topic={} message_len={} tag_present={} tag={} published_at={} envelope_type={:?} decrypted_len={} jsonrpc={} id={} method={} params_keys={}",
        received.topic(),
        received.encoded_message_len(),
        received.tag().is_some(),
        received.tag().unwrap_or_default(),
        received.published_at(),
        payload.envelope_type(),
        payload.plaintext().len(),
        payload
            .json()
            .get("jsonrpc")
            .and_then(Value::as_str)
            .unwrap_or("<none>"),
        json_id(payload.json()),
        pairing_message_method_label(payload.method()),
        params_keys(payload.json())
    );

    match received.payload() {
        PairingPayload::SessionProposal(request) => {
            print_session_proposal_request_summary(label, request);
        }
        PairingPayload::SessionAuthenticate(request) => {
            println!(
                "{label} session_authenticate id={} requester_name={} domain={} chains={} expiry={}",
                request.id,
                request.params.requester.metadata.name,
                request.params.auth_payload.domain,
                request
                    .params
                    .auth_payload
                    .chains
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                request.params.expiry_timestamp
            );
        }
        PairingPayload::Sign(method) => {
            println!("{label} sign_request method={method}");
        }
        PairingPayload::PairingPing(request) => {
            println!(
                "{label} pairing_request method={} id={} params=empty",
                request.method, request.id
            );
        }
        PairingPayload::PairingDelete(request) => {
            println!(
                "{label} pairing_request method={} id={} code={} message={}",
                request.method, request.id, request.params.code, request.params.message
            );
        }
        PairingPayload::Unknown(method) => {
            println!("{label} unknown_request method={method}");
        }
        PairingPayload::Missing => {
            println!("{label} missing_method=true");
        }
    }

    if pairing_uri_print_json() {
        let pretty = serde_json::to_string_pretty(payload.json())
            .with_context(|| format!("{label} failed to format decrypted JSON"))?;
        println!("{label} decrypted_json=\n{pretty}");
    }

    Ok(())
}

fn pairing_message_method_label(method: &PairingMessageMethod) -> String {
    match method {
        PairingMessageMethod::Sign(method) => method.to_string(),
        PairingMessageMethod::Pairing(method) => method.to_string(),
        PairingMessageMethod::Unknown(method) => method.clone(),
        PairingMessageMethod::Missing => "<none>".to_owned(),
    }
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
    print_session_proposal_request_summary(label, &request);

    Ok(())
}

fn print_session_proposal_request_summary(
    label: &str,
    request: &JsonRpcRequest<SessionProposeParams>,
) {
    let proposal = &request.params;
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

    run_encrypted_envelope_delivery(config).await?;
    run_key_agreement_envelope_delivery(config).await?;
    run_unsubscribe_suppresses_delivery(config).await?;
    run_batch_subscribe_delivery(config).await?;
    run_batch_fetch_offline_messages(config).await?;
    run_batch_unsubscribe_suppresses_delivery(config).await?;
    run_batch_publish_probe(config).await?;

    println!("relay-probe matrix ok");

    Ok(())
}

async fn run_encrypted_envelope_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-encrypted-envelope";
    let topic = generated_topic()?;
    let sym_key = generated_sym_key()?;
    let payload = json!({
        "id": rpc_id()?.as_u64(),
        "jsonrpc": "2.0",
        "method": "wc_probeEncryptedEnvelope",
        "params": {
            "label": label,
            "quote": "\"",
            "backslash": "\\",
            "slash": "/",
            "newline": "\n",
            "tab": "\t",
            "unicode_escape": "\u{2603}",
            "empty_object": {},
            "empty_array": [],
            "nested": {
                "numbers": [0, 1, -1],
                "bools": [true, false]
            }
        }
    });
    let plaintext = serde_json::to_string(&payload).context("failed to serialize probe payload")?;
    let envelope = Envelope::encrypt_type_0(&plaintext, &sym_key)
        .context("failed to encrypt relay probe envelope")?;
    let message = envelope.encode(EnvelopeEncoding::Base64);
    println!(
        "{label} topic={topic} plaintext_len={} encrypted_len={}",
        plaintext.len(),
        message.len()
    );

    let subscription = publish_and_receive_once(config, label, &topic, &message).await?;

    let received = Envelope::decode(&subscription.data.message, EnvelopeEncoding::Base64)
        .context("failed to decode received encrypted envelope")?;
    let decrypted = received
        .decrypt(&sym_key)
        .context("failed to decrypt received envelope")?;
    let decoded_payload =
        serde_json::from_str::<Value>(&decrypted).context("decrypted envelope was not JSON")?;
    if decoded_payload != payload {
        bail!("{label} decrypted payload mismatch");
    }

    println!(
        "{label} decrypt_ok=true envelope_type={:?} json_id={} params_keys={}",
        received.envelope_type(),
        json_id(&decoded_payload),
        params_keys(&decoded_payload)
    );

    Ok(())
}

async fn run_key_agreement_envelope_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-key-agreement-envelope";
    let proposer = X25519KeyPair::generate().context("failed to generate proposer key pair")?;
    let responder = X25519KeyPair::generate().context("failed to generate responder key pair")?;
    let proposer_sym_key = derive_shared_sym_key(proposer.private_key(), responder.public_key());
    let responder_sym_key = derive_shared_sym_key(responder.private_key(), proposer.public_key());
    if proposer_sym_key != responder_sym_key {
        bail!("{label} derived asymmetric symKeys");
    }

    // Maintained JS derives the symmetric key from the local private key plus
    // peer public key, then hashes that symmetric key into the relay topic:
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L49-L61
    // https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/crypto.ts#L81-L85
    let topic = derive_topic_from_sym_key(&proposer_sym_key);
    let payload = json!({
        "id": rpc_id()?.as_u64(),
        "jsonrpc": "2.0",
        "method": "wc_probeKeyAgreementEnvelope",
        "params": {
            "label": label,
            "proposerPublicKey": proposer.public_key().as_str(),
            "responderPublicKey": responder.public_key().as_str(),
            "derivedTopic": topic.as_str(),
            "edgeCases": {
                "empty": "",
                "unicode": "\u{2603}",
                "nested": [{ "ok": true }, { "count": 2 }]
            }
        }
    });
    let plaintext =
        serde_json::to_string(&payload).context("failed to serialize key-agreement payload")?;
    let envelope = Envelope::encrypt_type_0(&plaintext, &proposer_sym_key)
        .context("failed to encrypt key-agreement envelope")?;
    let message = envelope.encode(EnvelopeEncoding::Base64);
    println!(
        "{label} topic={topic} plaintext_len={} encrypted_len={} public_key_len={}",
        plaintext.len(),
        message.len(),
        proposer.public_key().as_str().len()
    );

    let subscription = publish_and_receive_once(config, label, &topic, &message).await?;
    let received = Envelope::decode(&subscription.data.message, EnvelopeEncoding::Base64)
        .context("failed to decode received key-agreement envelope")?;
    let decrypted = received
        .decrypt(&responder_sym_key)
        .context("failed to decrypt key-agreement envelope with responder key")?;
    let decoded_payload =
        serde_json::from_str::<Value>(&decrypted).context("decrypted envelope was not JSON")?;
    if decoded_payload != payload {
        bail!("{label} decrypted payload mismatch");
    }

    println!(
        "{label} decrypt_ok=true derived_sym_key_match=true envelope_type={:?} json_id={} params_keys={}",
        received.envelope_type(),
        json_id(&decoded_payload),
        params_keys(&decoded_payload)
    );

    Ok(())
}

async fn publish_and_receive_once(
    config: &RelayProbeConfig,
    label: &str,
    topic: &RelayTopic,
    message: &str,
) -> Result<IrnSubscription> {
    let mut subscriber = config.connect("subscriber").await?;
    let subscription_id = subscriber.subscribe(topic.clone()).await?;
    println!("{label} subscriber subscription_id={subscription_id}");

    let mut publisher = config.connect("publisher").await?;
    publisher
        .publish(IrnPublish::new(topic.clone(), message, 30, 0))
        .await?;
    println!("{label} publisher publish_ack=true");

    let subscription = subscriber
        .read_any_subscription_for_topic(topic, READ_TIMEOUT)
        .await?
        .ok_or_else(|| anyhow!("{label} timed out waiting for subscription"))?;
    if subscription.data.message != message {
        bail!("{label} message changed in transit");
    }

    subscriber.unsubscribe(topic, &subscription_id).await?;
    println!("{label} subscriber unsubscribe_ack=true");

    Ok(subscription)
}

async fn run_push_delivery(
    config: &RelayProbeConfig,
    label: &str,
    topic: RelayTopic,
    messages: Vec<String>,
) -> Result<()> {
    println!("{label} topic={topic} messages={}", messages.len());

    let mut subscriber = config.connect("subscriber").await?;
    let subscription_id = subscriber.subscribe(topic.clone()).await?;
    println!("{label} subscriber subscription_id={subscription_id}");

    let mut publisher = config.connect("publisher").await?;
    for (index, message) in messages.iter().enumerate() {
        publisher
            .publish(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
        println!("{label} publisher publish_ack index={index}");

        subscriber.read_subscription(&topic, message).await?;
    }

    let fetch_response = subscriber.fetch_messages(&topic).await?;
    println!(
        "{label} subscriber fetch_messages count={} has_more={}",
        fetch_response.messages.len(),
        fetch_response.has_more
    );
    if !fetch_response.messages.is_empty() || fetch_response.has_more {
        bail!("{label} expected empty mailbox after live delivery ack");
    }

    subscriber.unsubscribe(&topic, &subscription_id).await?;
    println!("{label} subscriber unsubscribe_ack=true");

    Ok(())
}

async fn run_unsubscribe_suppresses_delivery(config: &RelayProbeConfig) -> Result<()> {
    let label = "matrix-unsubscribe-suppression";
    let topic = generated_topic()?;
    let message = format!("{label} {}", rpc_id()?.as_u64());
    println!("{label} topic={topic}");

    let mut subscriber = config.connect("subscriber").await?;
    let subscription_id = subscriber.subscribe(topic.clone()).await?;
    println!("{label} subscriber subscription_id={subscription_id}");

    subscriber.unsubscribe(&topic, &subscription_id).await?;
    println!("{label} subscriber unsubscribe_ack=true");

    let mut publisher = config.connect("publisher").await?;
    publisher
        .publish(IrnPublish::new(topic.clone(), message, 30, 0))
        .await?;
    println!("{label} publisher publish_ack=true");

    match subscriber
        .read_suppressed_subscription_for_topics(std::slice::from_ref(&topic), NO_DELIVERY_TIMEOUT)
        .await?
    {
        SuppressedDelivery::NoDelivery => {
            println!("{label} no_delivery_after_unsubscribe=true");
        }
        SuppressedDelivery::InactiveTopicDropped { topic } => {
            println!("{label} inactive_delivery_after_unsubscribe_dropped=true topic={topic}");
        }
    }

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
    let subscribe_result = subscriber.batch_subscribe(topics.clone()).await?;
    println!(
        "{label} subscriber batch_subscribe_result={}",
        serde_json::to_string(&subscribe_result)
            .context("failed to print batch subscribe result")?
    );

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages.iter()).enumerate() {
        publisher
            .publish(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
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
        let subscription_ids = subscriber.batch_subscribe(topics.clone()).await?;
        println!(
            "{label} subscriber initial_batch_subscribe_ids={}",
            subscription_ids.len()
        );
        subscription_ids
    };

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages.iter()).enumerate() {
        publisher
            .publish(IrnPublish::new(topic.clone(), message.clone(), 30, 0))
            .await?;
        println!("{label} publisher publish_ack index={index}");
    }

    let mut subscriber = config.connect("subscriber").await?;
    let fetch_response = subscriber.batch_fetch_messages(&topics).await?;
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

    let subscriptions = topics
        .into_iter()
        .zip(subscription_ids)
        .map(|(topic, id)| IrnUnsubscribe::new(topic, id))
        .collect::<Vec<_>>();
    let unsubscribe_result = subscriber.batch_unsubscribe(&subscriptions).await?;
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
        let subscription_id = subscriber.subscribe(topic.clone()).await?;
        println!("{label} subscriber subscription_id={subscription_id}");
        subscriptions.push(IrnUnsubscribe::new(topic.clone(), subscription_id));
    }

    let unsubscribe_result = subscriber.batch_unsubscribe(&subscriptions).await?;
    println!("{label} subscriber batch_unsubscribe_result={unsubscribe_result}");

    let mut publisher = config.connect("publisher").await?;
    for (index, (topic, message)) in topics.iter().zip(messages).enumerate() {
        publisher
            .publish(IrnPublish::new(topic.clone(), message, 30, 0))
            .await?;
        println!("{label} publisher publish_ack index={index}");
    }

    match subscriber
        .read_suppressed_subscription_for_topics(&topics, NO_DELIVERY_TIMEOUT)
        .await?
    {
        SuppressedDelivery::NoDelivery => {
            println!("{label} no_delivery_after_batch_unsubscribe=true");
        }
        SuppressedDelivery::InactiveTopicDropped { topic } => {
            println!(
                "{label} inactive_delivery_after_batch_unsubscribe_dropped=true topic={topic}"
            );
        }
    }

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

    let mut publisher = config.connect_raw("publisher").await?;
    match publisher.probe_batch_publish_shapes(messages).await? {
        Some(result) => println!("{label} accepted=true result={result}"),
        None => println!("{label} accepted=false relay_error=-32600"),
    }

    Ok(())
}
