use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use crate::relay_socket::{RawRelaySocket, RelaySocket};
use crate::util::{
    client_auth_jwt, generated_sym_key, generated_topic, pairing_uri_print_json,
    pairing_uri_wait_timeout, redact, rpc_id, unix_timestamp,
};
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::time::sleep;
use wc_core::{
    ApprovedSession, DEFAULT_SESSION_EXPIRY_SECONDS, PairingClient, PairingClientConfig,
    PairingPayload, PairingReceivedMessage, PairingSubscription, SessionProposalApproval,
    SessionSettleResponseMessage, SessionSettleResponsePayload,
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
    session::{DappMetadata, ProposalNamespace, SessionNamespace, SessionNamespaces},
    session::{JsonRpcError, JsonRpcErrorCode, JsonRpcRequest, SessionProposeParams, SignMethod},
};

const READ_TIMEOUT: Duration = Duration::from_secs(20);
const NO_DELIVERY_TIMEOUT: Duration = Duration::from_secs(3);
const JS_HARNESS_URI_READY_TIMEOUT: Duration = Duration::from_secs(30);
const JS_HARNESS_URI_FILE_STEM: &str = "live-pairing-uri";
const JS_HARNESS_RESULT_FILE_STEM: &str = "live-pairing-result";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeMode {
    Basic,
    Matrix,
    JsProposal,
    CoreJsProposal,
    CoreJsApproveProposal,
    CoreJsRejectProposal,
    PairingUri(String),
}

pub async fn run(mode: ProbeMode) -> Result<()> {
    let config = RelayProbeConfig::from_env()?;

    match mode {
        ProbeMode::Basic => run_basic_probe(&config).await,
        ProbeMode::Matrix => run_probe_matrix(&config).await,
        ProbeMode::JsProposal => run_js_proposal_probe(&config).await,
        ProbeMode::CoreJsProposal => run_core_js_proposal_probe(&config).await,
        ProbeMode::CoreJsApproveProposal => run_core_js_approve_proposal_probe(&config).await,
        ProbeMode::CoreJsRejectProposal => run_core_js_reject_proposal_probe(&config).await,
        ProbeMode::PairingUri(uri) => run_pairing_uri_probe(&config, &uri).await,
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

    let (mut client, pairing_subscription, approved) =
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
) -> Result<(PairingClient, PairingSubscription, ApprovedSession)> {
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

    let namespaces = approved_namespaces_for_probe(&proposal)?;
    let approval = SessionProposalApproval::new(
        namespaces,
        probe_wallet_metadata(),
        unix_timestamp() + DEFAULT_SESSION_EXPIRY_SECONDS,
    );
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
    receive_and_print_session_settle_response(&mut client, &approved).await?;

    Ok((client, subscription, approved))
}

async fn receive_and_print_session_settle_response(
    client: &mut PairingClient,
    approved: &ApprovedSession,
) -> Result<()> {
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

    Ok(())
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

fn approved_namespaces_for_probe(
    proposal: &JsonRpcRequest<SessionProposeParams>,
) -> Result<SessionNamespaces> {
    let proposal_namespaces = if proposal.params.optional_namespaces.is_empty() {
        &proposal.params.required_namespaces
    } else {
        &proposal.params.optional_namespaces
    };

    if proposal_namespaces.is_empty() {
        bail!("session proposal has no required or optional namespaces");
    }

    let mut approved = BTreeMap::<NamespaceKey, SessionNamespace>::new();
    for (key, namespace) in proposal_namespaces {
        let chains = proposal_namespace_chains(key, namespace)?;
        let approved_key = NamespaceKey::parse(key.namespace())?;
        let entry = approved.entry(approved_key).or_insert(SessionNamespace {
            chains: Some(Vec::new()),
            accounts: Vec::new(),
            methods: Vec::new(),
            events: Vec::new(),
        });

        for chain in chains {
            insert_unique(entry.chains.get_or_insert_with(Vec::new), chain.clone());
            let account = probe_account_for_chain(&chain)?;
            insert_unique(&mut entry.accounts, account);
        }
        for method in &namespace.methods {
            insert_unique(&mut entry.methods, method.clone());
        }
        for event in &namespace.events {
            insert_unique(&mut entry.events, event.clone());
        }
    }

    Ok(approved)
}

fn proposal_namespace_chains(
    key: &NamespaceKey,
    namespace: &ProposalNamespace,
) -> Result<Vec<Caip2ChainId>> {
    if let Some(chains) = &namespace.chains {
        if !chains.is_empty() {
            return Ok(chains.clone());
        }
    }

    if let Some(chain_id) = key.chain_id() {
        return Ok(vec![chain_id.clone()]);
    }

    bail!("proposal namespace {key} has no chains")
}

fn probe_account_for_chain(chain: &Caip2ChainId) -> Result<Caip10AccountId> {
    let address = env::var("WC_APPROVAL_ACCOUNT_ADDRESS")
        .unwrap_or_else(|_| "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".to_owned());
    Caip10AccountId::parse(format!("{chain}:{address}")).map_err(Into::into)
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

fn insert_unique<T>(items: &mut Vec<T>, value: T)
where
    T: Eq,
{
    if !items.contains(&value) {
        items.push(value);
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

    let mut publisher = config.connect_raw("publisher").await?;
    match publisher.probe_batch_publish_shapes(messages).await? {
        Some(result) => println!("{label} accepted=true result={result}"),
        None => println!("{label} accepted=false relay_error=-32600"),
    }

    Ok(())
}
