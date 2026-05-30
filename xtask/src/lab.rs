use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::{Context, Result, bail};

/// Runs one Lab harness command through the repo-local Bun script.
pub fn run(args: LabCommand) -> Result<()> {
    let workspace_root = workspace_root()?;
    let harness_root = workspace_root.join("tools/js-harness");
    let status = Command::new("bun")
        .arg("run")
        .arg("lab")
        .args(args.into_args())
        .current_dir(&harness_root)
        .status()
        .with_context(|| format!("failed to run Lab harness in {}", harness_root.display()))?;

    ensure_success(status)
}

/// Lab route and browser-interaction harness command.
#[derive(Debug, Clone)]
pub enum LabCommand {
    /// Fetch Lab's public route list and validate each route.
    Routes(LabRoutesRequest),
    /// Print or validate the checked Lab scenario catalog.
    Catalog(LabCatalogRequest),
    /// Capture a `WalletConnect` URI from a Lab browser scenario.
    CaptureUri(LabCaptureUriRequest),
}

impl LabCommand {
    fn into_args(self) -> Vec<String> {
        match self {
            Self::Routes(request) => request.into_args(),
            Self::Catalog(request) => request.into_args(),
            Self::CaptureUri(request) => request.into_args(),
        }
    }
}

/// Options for `lab routes`.
#[derive(Debug, Clone)]
pub struct LabRoutesRequest {
    /// Lab base URL.
    pub base_url: Option<String>,
    /// Print machine-readable JSON.
    pub json: bool,
    /// Request timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

impl LabRoutesRequest {
    fn into_args(self) -> Vec<String> {
        let mut args = vec!["routes".to_owned()];
        push_common_args(&mut args, self.base_url.as_deref(), self.timeout_ms);
        push_flag(&mut args, self.json, "--json");
        args
    }
}

/// Options for `lab catalog`.
#[derive(Debug, Clone)]
pub struct LabCatalogRequest {
    /// Lab base URL.
    pub base_url: Option<String>,
    /// Print machine-readable JSON.
    pub json: bool,
    /// Validate catalog routes against the live Lab deployment.
    pub validate: bool,
    /// Request timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

impl LabCatalogRequest {
    fn into_args(self) -> Vec<String> {
        let mut args = vec!["catalog".to_owned()];
        push_common_args(&mut args, self.base_url.as_deref(), self.timeout_ms);
        push_flag(&mut args, self.json, "--json");
        push_flag(&mut args, self.validate, "--validate");
        args
    }
}

/// Options for `lab capture-uri`.
#[derive(Debug, Clone)]
pub struct LabCaptureUriRequest {
    /// Lab base URL.
    pub base_url: Option<String>,
    /// Run the browser headed instead of headless.
    pub headed: bool,
    /// Print machine-readable JSON.
    pub json: bool,
    /// Lab scenario name.
    pub scenario: String,
    /// Print the full URI instead of only a redacted summary.
    pub show_uri: bool,
    /// Request and browser-action timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

impl LabCaptureUriRequest {
    fn into_args(self) -> Vec<String> {
        let mut args = vec!["capture-uri".to_owned()];
        push_common_args(&mut args, self.base_url.as_deref(), self.timeout_ms);
        args.push("--scenario".to_owned());
        args.push(self.scenario);
        push_flag(&mut args, self.headed, "--headed");
        push_flag(&mut args, self.json, "--json");
        push_flag(&mut args, self.show_uri, "--show-uri");
        args
    }
}

fn push_common_args(args: &mut Vec<String>, base_url: Option<&str>, timeout_ms: Option<u64>) {
    if let Some(base_url) = base_url {
        args.push("--base-url".to_owned());
        args.push(base_url.to_owned());
    }
    if let Some(timeout_ms) = timeout_ms {
        args.push("--timeout-ms".to_owned());
        args.push(timeout_ms.to_string());
    }
}

fn push_flag(args: &mut Vec<String>, enabled: bool, name: &str) {
    if enabled {
        args.push(name.to_owned());
    }
}

fn workspace_root() -> Result<PathBuf> {
    let manifest_dir =
        env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is not set for xtask")?;
    Path::new(&manifest_dir)
        .parent()
        .map(Path::to_path_buf)
        .context("xtask manifest directory does not have a parent")
}

fn ensure_success(status: ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }

    bail!("Lab harness failed with status {status}");
}
