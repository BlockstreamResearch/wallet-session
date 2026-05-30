use std::{
    env, fs,
    future::Future,
    io::{self, Read},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::{api_snapshot, lab, probe, relay, scenario};

#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    about = "Development harnesses for the WalletConnect client proof of concept"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "api-snapshot")]
    ApiSnapshot(ApiSnapshotArgs),
    #[command(name = "relay-probe")]
    Relay(RelayProbeArgs),
    #[command(name = "crypto-probe")]
    Crypto,
    #[command(name = "auth-probe")]
    Auth(JsonProbeArgs),
    #[command(name = "pairing-probe")]
    Pairing(JsonProbeArgs),
    #[command(name = "session-probe")]
    Session(JsonProbeArgs),
    #[command(name = "verify-probe")]
    Verify(VerifyProbeArgs),
    #[command(name = "scenario")]
    Scenario(ScenarioArgs),
    #[command(name = "lab")]
    Lab(LabArgs),
}

#[derive(Debug, Args)]
struct RelayProbeArgs {
    #[arg(long)]
    basic: bool,

    #[arg(long)]
    matrix: bool,

    #[arg(long)]
    js_proposal: bool,

    #[command(flatten)]
    core: CoreRelayProbeArgs,

    #[command(flatten)]
    core_pairing: CoreRelayPairingProbeArgs,

    #[command(flatten)]
    core_session: CoreRelaySessionProbeArgs,

    #[command(flatten)]
    core_single_session_client: CoreRelaySingleSessionClientProbeArgs,

    #[command(flatten)]
    core_single_session_client_auth: CoreRelaySingleSessionClientAuthProbeArgs,

    #[arg(long, value_name = "URI")]
    pairing_uri: Option<String>,
}

#[derive(Debug, Args)]
struct CoreRelayProbeArgs {
    #[arg(long)]
    core_js_proposal: bool,

    #[arg(long)]
    core_js_approve_proposal: bool,

    #[arg(long)]
    core_js_reject_proposal: bool,
}

#[derive(Debug, Args)]
struct CoreRelayPairingProbeArgs {
    #[arg(long)]
    core_js_pairing_lifecycle: bool,
}

#[derive(Debug, Args)]
struct CoreRelaySessionProbeArgs {
    #[arg(long)]
    core_js_session_request: bool,

    #[arg(long)]
    core_js_session_lifecycle: bool,
}

#[derive(Debug, Args)]
struct CoreRelaySingleSessionClientProbeArgs {
    #[arg(long)]
    core_single_session_client_session_request: bool,

    #[arg(long)]
    core_single_session_client_session_lifecycle: bool,

    #[arg(long)]
    core_single_session_client_disconnect: bool,
}

#[derive(Debug, Args)]
struct CoreRelaySingleSessionClientAuthProbeArgs {
    #[arg(long)]
    core_single_session_client_session_authenticate: bool,
}

#[derive(Debug, Args)]
struct JsonProbeArgs {
    #[arg(long)]
    sample: bool,

    #[arg(long, value_name = "JSON")]
    json: Option<String>,

    #[arg(long, value_name = "PATH")]
    file: Option<PathBuf>,

    #[arg(long)]
    stdin: bool,
}

#[derive(Debug, Args)]
struct VerifyProbeArgs {
    #[arg(long, value_name = "HASH")]
    hash: Option<String>,

    #[arg(long)]
    public_key: bool,

    #[arg(long, value_name = "JWT")]
    attestation_jwt: Option<String>,

    #[arg(long, value_name = "ID")]
    encrypted_id: Option<String>,

    #[arg(long, value_name = "SECONDS")]
    now_unix_seconds: Option<u64>,

    #[arg(long, value_name = "URL")]
    metadata_url: Option<String>,

    #[arg(long, value_name = "URL")]
    verify_url: Option<String>,
}

#[derive(Debug, Args)]
struct ScenarioArgs {
    #[arg(long)]
    list: bool,

    #[arg(value_enum, default_value_t = scenario::ScenarioName::DefaultLive)]
    name: scenario::ScenarioName,
}

#[derive(Debug, Args)]
struct LabArgs {
    #[command(subcommand)]
    command: LabCommand,
}

#[derive(Debug, Subcommand)]
enum LabCommand {
    #[command(name = "routes")]
    Routes(LabRoutesArgs),
    #[command(name = "catalog")]
    Catalog(LabCatalogArgs),
    #[command(name = "capture-uri")]
    CaptureUri(LabCaptureUriArgs),
}

#[derive(Debug, Args)]
struct LabRoutesArgs {
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,

    #[arg(long)]
    json: bool,

    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct LabCatalogArgs {
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    validate: bool,

    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct LabCaptureUriArgs {
    #[arg(long, value_name = "URL")]
    base_url: Option<String>,

    #[arg(long)]
    headed: bool,

    #[arg(long)]
    json: bool,

    #[arg(long, default_value = "wagmi")]
    scenario: String,

    #[arg(long)]
    show_uri: bool,

    #[arg(long, value_name = "MS")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Args)]
struct ApiSnapshotArgs {
    #[arg(long, default_value = "target/doc/wc_core.json")]
    rustdoc_json: PathBuf,

    #[arg(long, default_value = "api-snapshots/wc-core.txt")]
    output: PathBuf,

    #[arg(long)]
    check: bool,

    #[arg(long)]
    update: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonProbeInput {
    Json(String),
    Sample,
}

pub fn run() -> Result<()> {
    match Cli::parse().command {
        Command::ApiSnapshot(args) => run_api_snapshot(args),
        Command::Relay(args) => run_async(relay::run(args.into_probe_mode()?)),
        Command::Crypto => probe::crypto::run(),
        Command::Auth(args) => {
            probe::auth::run(args.into_input("WC_AUTH_PROBE_JSON", "WC_AUTH_PROBE_FILE")?)
        }
        Command::Pairing(args) => {
            probe::pairing::run(args.into_input("WC_PAIRING_PROBE_JSON", "WC_PAIRING_PROBE_FILE")?)
        }
        Command::Session(args) => {
            probe::session::run(args.into_input("WC_SESSION_PROBE_JSON", "WC_SESSION_PROBE_FILE")?)
        }
        Command::Verify(args) => run_async(probe::verify::run(args.into())),
        Command::Scenario(args) => {
            if args.list {
                scenario::list();
                Ok(())
            } else {
                scenario::run(args.name)
            }
        }
        Command::Lab(args) => lab::run(args.into()),
    }
}

fn run_api_snapshot(args: ApiSnapshotArgs) -> Result<()> {
    if args.check && args.update {
        bail!("choose only one of --check or --update");
    }

    let request = api_snapshot::ApiSnapshotRequest {
        rustdoc_json: args.rustdoc_json,
        output: args.output,
    };

    if args.check {
        api_snapshot::check(&request)
    } else if args.update {
        api_snapshot::update(&request)
    } else {
        api_snapshot::print(&request)
    }
}

impl From<VerifyProbeArgs> for probe::verify::VerifyProbeArgs {
    fn from(args: VerifyProbeArgs) -> Self {
        Self {
            hash: args.hash,
            public_key: args.public_key,
            attestation_jwt: args.attestation_jwt,
            encrypted_id: args.encrypted_id,
            now_unix_seconds: args.now_unix_seconds,
            metadata_url: args.metadata_url,
            verify_url: args.verify_url,
        }
    }
}

impl From<LabArgs> for lab::LabCommand {
    fn from(args: LabArgs) -> Self {
        match args.command {
            LabCommand::Routes(args) => Self::Routes(lab::LabRoutesRequest {
                base_url: args.base_url,
                json: args.json,
                timeout_ms: args.timeout_ms,
            }),
            LabCommand::Catalog(args) => Self::Catalog(lab::LabCatalogRequest {
                base_url: args.base_url,
                json: args.json,
                validate: args.validate,
                timeout_ms: args.timeout_ms,
            }),
            LabCommand::CaptureUri(args) => Self::CaptureUri(lab::LabCaptureUriRequest {
                base_url: args.base_url,
                headed: args.headed,
                json: args.json,
                scenario: args.scenario,
                show_uri: args.show_uri,
                timeout_ms: args.timeout_ms,
            }),
        }
    }
}

impl RelayProbeArgs {
    fn into_probe_mode(self) -> Result<relay::ProbeMode> {
        if self.selected_count() > 1 {
            bail!("choose only one relay probe mode");
        }

        if let Some(mode) = self.explicit_mode() {
            return Ok(mode);
        }

        probe_mode_from_env()
    }

    fn selected_count(&self) -> usize {
        usize::from(self.basic)
            + usize::from(self.matrix)
            + usize::from(self.js_proposal)
            + usize::from(self.core.core_js_proposal)
            + usize::from(self.core.core_js_approve_proposal)
            + usize::from(self.core.core_js_reject_proposal)
            + usize::from(self.core_pairing.core_js_pairing_lifecycle)
            + usize::from(self.core_session.core_js_session_request)
            + usize::from(self.core_session.core_js_session_lifecycle)
            + usize::from(
                self.core_single_session_client
                    .core_single_session_client_session_request,
            )
            + usize::from(
                self.core_single_session_client
                    .core_single_session_client_session_lifecycle,
            )
            + usize::from(
                self.core_single_session_client
                    .core_single_session_client_disconnect,
            )
            + usize::from(
                self.core_single_session_client_auth
                    .core_single_session_client_session_authenticate,
            )
            + usize::from(self.pairing_uri.is_some())
    }

    fn explicit_mode(&self) -> Option<relay::ProbeMode> {
        if self.basic {
            return Some(relay::ProbeMode::Basic);
        }
        if self.matrix {
            return Some(relay::ProbeMode::Matrix);
        }
        if self.js_proposal {
            return Some(relay::ProbeMode::JsProposal);
        }
        if self.core.core_js_proposal {
            return Some(relay::ProbeMode::CoreJsProposal);
        }
        if self.core.core_js_approve_proposal {
            return Some(relay::ProbeMode::CoreJsApproveProposal);
        }
        if self.core.core_js_reject_proposal {
            return Some(relay::ProbeMode::CoreJsRejectProposal);
        }
        if self.core_pairing.core_js_pairing_lifecycle {
            return Some(relay::ProbeMode::CoreJsPairingLifecycle);
        }
        if self.core_session.core_js_session_request {
            return Some(relay::ProbeMode::CoreJsSessionRequest);
        }
        if self.core_session.core_js_session_lifecycle {
            return Some(relay::ProbeMode::CoreJsSessionLifecycle);
        }
        if self
            .core_single_session_client
            .core_single_session_client_session_request
        {
            return Some(relay::ProbeMode::CoreSingleSessionClientSessionRequest);
        }
        if self
            .core_single_session_client
            .core_single_session_client_session_lifecycle
        {
            return Some(relay::ProbeMode::CoreSingleSessionClientSessionLifecycle);
        }
        if self
            .core_single_session_client
            .core_single_session_client_disconnect
        {
            return Some(relay::ProbeMode::CoreSingleSessionClientDisconnect);
        }
        if self
            .core_single_session_client_auth
            .core_single_session_client_session_authenticate
        {
            return Some(relay::ProbeMode::CoreSingleSessionClientSessionAuthenticate);
        }
        if let Some(uri) = self.pairing_uri.as_ref() {
            return Some(relay::ProbeMode::PairingUri(uri.clone()));
        }

        None
    }
}

fn probe_mode_from_env() -> Result<relay::ProbeMode> {
    match env::var("WC_RELAY_PROBE_MODE").as_deref() {
        Ok("basic") | Err(_) => Ok(relay::ProbeMode::Basic),
        Ok("matrix") => Ok(relay::ProbeMode::Matrix),
        Ok("js-proposal") => Ok(relay::ProbeMode::JsProposal),
        Ok("core-js-proposal") => Ok(relay::ProbeMode::CoreJsProposal),
        Ok("core-js-approve-proposal") => Ok(relay::ProbeMode::CoreJsApproveProposal),
        Ok("core-js-reject-proposal") => Ok(relay::ProbeMode::CoreJsRejectProposal),
        Ok("core-js-pairing-lifecycle") => Ok(relay::ProbeMode::CoreJsPairingLifecycle),
        Ok("core-js-session-request") => Ok(relay::ProbeMode::CoreJsSessionRequest),
        Ok("core-js-session-lifecycle") => Ok(relay::ProbeMode::CoreJsSessionLifecycle),
        Ok("core-single-session-client-session-request") => {
            Ok(relay::ProbeMode::CoreSingleSessionClientSessionRequest)
        }
        Ok("core-single-session-client-session-lifecycle") => {
            Ok(relay::ProbeMode::CoreSingleSessionClientSessionLifecycle)
        }
        Ok("core-single-session-client-disconnect") => {
            Ok(relay::ProbeMode::CoreSingleSessionClientDisconnect)
        }
        Ok("core-single-session-client-session-authenticate") => {
            Ok(relay::ProbeMode::CoreSingleSessionClientSessionAuthenticate)
        }
        Ok("pairing-uri") => {
            let uri = env::var("WC_PAIRING_URI")
                .context("set WC_PAIRING_URI when WC_RELAY_PROBE_MODE=pairing-uri")?;
            Ok(relay::ProbeMode::PairingUri(uri))
        }
        Ok(other) => bail!("unknown WC_RELAY_PROBE_MODE: {other}"),
    }
}

impl JsonProbeArgs {
    fn into_input(self, json_env: &str, file_env: &str) -> Result<JsonProbeInput> {
        let selected_count = usize::from(self.sample)
            + usize::from(self.json.is_some())
            + usize::from(self.file.is_some())
            + usize::from(self.stdin);
        if selected_count > 1 {
            bail!("choose only one JSON input source");
        }

        if self.sample {
            return Ok(JsonProbeInput::Sample);
        }
        if let Some(json) = self.json {
            return Ok(JsonProbeInput::Json(json));
        }
        if let Some(path) = self.file {
            return Ok(JsonProbeInput::Json(read_file(&path)?));
        }
        if self.stdin {
            return Ok(JsonProbeInput::Json(read_stdin()?));
        }
        if let Ok(json) = env::var(json_env) {
            return Ok(JsonProbeInput::Json(json));
        }
        if let Ok(path) = env::var(file_env) {
            return Ok(JsonProbeInput::Json(read_file(&PathBuf::from(path))?));
        }

        Ok(JsonProbeInput::Sample)
    }
}

fn run_async(task: impl Future<Output = Result<()>>) -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start tokio runtime")?
        .block_on(task)
}

fn read_file(path: &PathBuf) -> Result<String> {
    fs::read_to_string(path)
        .with_context(|| format!("failed to read probe file {}", path.display()))
}

fn read_stdin() -> Result<String> {
    let mut json = String::new();
    io::stdin()
        .read_to_string(&mut json)
        .context("failed to read probe JSON from stdin")?;
    Ok(json)
}
