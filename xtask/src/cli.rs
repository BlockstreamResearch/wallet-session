use std::{
    env, fs,
    future::Future,
    io::{self, Read},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::{probe, relay};

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
    core_session: CoreRelaySessionProbeArgs,

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
struct CoreRelaySessionProbeArgs {
    #[arg(long)]
    core_js_session_request: bool,

    #[arg(long)]
    core_js_session_lifecycle: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonProbeInput {
    Json(String),
    Sample,
}

pub fn run() -> Result<()> {
    match Cli::parse().command {
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
    }
}

impl RelayProbeArgs {
    fn into_probe_mode(self) -> Result<relay::ProbeMode> {
        let selected_count = usize::from(self.basic)
            + usize::from(self.matrix)
            + usize::from(self.js_proposal)
            + usize::from(self.core.core_js_proposal)
            + usize::from(self.core.core_js_approve_proposal)
            + usize::from(self.core.core_js_reject_proposal)
            + usize::from(self.core_session.core_js_session_request)
            + usize::from(self.core_session.core_js_session_lifecycle)
            + usize::from(self.pairing_uri.is_some());
        if selected_count > 1 {
            bail!("choose only one relay probe mode");
        }

        if self.basic {
            return Ok(relay::ProbeMode::Basic);
        }
        if self.matrix {
            return Ok(relay::ProbeMode::Matrix);
        }
        if self.js_proposal {
            return Ok(relay::ProbeMode::JsProposal);
        }
        if self.core.core_js_proposal {
            return Ok(relay::ProbeMode::CoreJsProposal);
        }
        if self.core.core_js_approve_proposal {
            return Ok(relay::ProbeMode::CoreJsApproveProposal);
        }
        if self.core.core_js_reject_proposal {
            return Ok(relay::ProbeMode::CoreJsRejectProposal);
        }
        if self.core_session.core_js_session_request {
            return Ok(relay::ProbeMode::CoreJsSessionRequest);
        }
        if self.core_session.core_js_session_lifecycle {
            return Ok(relay::ProbeMode::CoreJsSessionLifecycle);
        }
        if let Some(uri) = self.pairing_uri {
            return Ok(relay::ProbeMode::PairingUri(uri));
        }

        match env::var("WC_RELAY_PROBE_MODE").as_deref() {
            Ok("basic") | Err(_) => Ok(relay::ProbeMode::Basic),
            Ok("matrix") => Ok(relay::ProbeMode::Matrix),
            Ok("js-proposal") => Ok(relay::ProbeMode::JsProposal),
            Ok("core-js-proposal") => Ok(relay::ProbeMode::CoreJsProposal),
            Ok("core-js-approve-proposal") => Ok(relay::ProbeMode::CoreJsApproveProposal),
            Ok("core-js-reject-proposal") => Ok(relay::ProbeMode::CoreJsRejectProposal),
            Ok("core-js-session-request") => Ok(relay::ProbeMode::CoreJsSessionRequest),
            Ok("core-js-session-lifecycle") => Ok(relay::ProbeMode::CoreJsSessionLifecycle),
            Ok("pairing-uri") => {
                let uri = env::var("WC_PAIRING_URI")
                    .context("set WC_PAIRING_URI when WC_RELAY_PROBE_MODE=pairing-uri")?;
                Ok(relay::ProbeMode::PairingUri(uri))
            }
            Ok(other) => bail!("unknown WC_RELAY_PROBE_MODE: {other}"),
        }
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
