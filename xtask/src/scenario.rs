use std::{
    env,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use anyhow::{Context, Result, bail};
use clap::ValueEnum;

/// Named live scenario suite built from existing probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScenarioName {
    /// Relay transport matrix plus current single-session client flows.
    DefaultLive,
    /// Relay transport matrix only.
    RelayMatrix,
    /// Current single-session client live flows.
    SingleSessionLive,
    /// Single-session proposal approval and session request response.
    SingleSessionRequest,
    /// Single-session proposal approval and session update handling.
    SingleSessionLifecycle,
    /// Single-session proposal approval and explicit disconnect.
    SingleSessionDisconnect,
    /// Single-session authentication request rejection.
    SingleSessionAuthenticate,
    /// Single-session authentication request rejection.
    SingleSessionAuthenticateReject,
    /// Single-session authentication approval with caller-supplied CACAO.
    SingleSessionAuthenticateApprove,
    /// Single-session `wallet_getCapabilities` request review and response.
    WalletCallGetCapabilities,
    /// Single-session `wallet_sendCalls` request review and response.
    WalletCallSendCalls,
    /// Wallet Call API request review scenarios.
    WalletCallLive,
    /// AppKit-style CAIP-25 capability proposal and Wallet Call response.
    AppkitCapabilityProposal,
    /// Verify public-key and JS SDK Verify context scenarios.
    VerifyLive,
    /// Auth, Verify, and Wallet Call SDK interop scenarios.
    InteropLive,
}

impl ScenarioName {
    const fn label(self) -> &'static str {
        match self {
            Self::DefaultLive => "default-live",
            Self::RelayMatrix => "relay-matrix",
            Self::SingleSessionLive => "single-session-live",
            Self::SingleSessionRequest => "single-session-request",
            Self::SingleSessionLifecycle => "single-session-lifecycle",
            Self::SingleSessionDisconnect => "single-session-disconnect",
            Self::SingleSessionAuthenticate => "single-session-authenticate",
            Self::SingleSessionAuthenticateReject => "single-session-authenticate-reject",
            Self::SingleSessionAuthenticateApprove => "single-session-authenticate-approve",
            Self::WalletCallGetCapabilities => "wallet-call-get-capabilities",
            Self::WalletCallSendCalls => "wallet-call-send-calls",
            Self::WalletCallLive => "wallet-call-live",
            Self::AppkitCapabilityProposal => "appkit-capability-proposal",
            Self::VerifyLive => "verify-live",
            Self::InteropLive => "interop-live",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::DefaultLive => {
                "relay matrix plus single-session request/lifecycle/disconnect/authenticate"
            }
            Self::RelayMatrix => "relay publish, subscribe, fetch, unsubscribe, batch, envelope",
            Self::SingleSessionLive => {
                "single-session request, lifecycle update, disconnect, and authenticate"
            }
            Self::SingleSessionRequest => "single-session proposal approval and request response",
            Self::SingleSessionLifecycle => "single-session proposal approval and session update",
            Self::SingleSessionDisconnect => "single-session proposal approval and disconnect",
            Self::SingleSessionAuthenticate | Self::SingleSessionAuthenticateReject => {
                "single-session authentication rejection"
            }
            Self::SingleSessionAuthenticateApprove => "single-session authentication approval",
            Self::WalletCallGetCapabilities => "Wallet Call wallet_getCapabilities request",
            Self::WalletCallSendCalls => "Wallet Call wallet_sendCalls request",
            Self::WalletCallLive => "Wallet Call request matrix",
            Self::AppkitCapabilityProposal => {
                "AppKit-style proposal with CAIP-25 session/scoped properties"
            }
            Self::VerifyLive => "Verify public key and JS SDK verifyContext",
            Self::InteropLive => "auth approval/rejection, Verify, and Wallet Call interop",
        }
    }

    const fn steps(self) -> &'static [ScenarioStep] {
        match self {
            Self::DefaultLive => &[
                RELAY_MATRIX,
                SINGLE_SESSION_REQUEST,
                SINGLE_SESSION_LIFECYCLE,
                SINGLE_SESSION_DISCONNECT,
                SINGLE_SESSION_AUTH_REJECT,
            ],
            Self::RelayMatrix => &[RELAY_MATRIX],
            Self::SingleSessionLive => &[
                SINGLE_SESSION_REQUEST,
                SINGLE_SESSION_LIFECYCLE,
                SINGLE_SESSION_DISCONNECT,
                SINGLE_SESSION_AUTH_REJECT,
            ],
            Self::SingleSessionRequest => &[SINGLE_SESSION_REQUEST],
            Self::SingleSessionLifecycle => &[SINGLE_SESSION_LIFECYCLE],
            Self::SingleSessionDisconnect => &[SINGLE_SESSION_DISCONNECT],
            Self::SingleSessionAuthenticate | Self::SingleSessionAuthenticateReject => {
                &[SINGLE_SESSION_AUTH_REJECT]
            }
            Self::SingleSessionAuthenticateApprove => &[SINGLE_SESSION_AUTH_APPROVE],
            Self::WalletCallGetCapabilities => &[WALLET_GET_CAPABILITIES],
            Self::WalletCallSendCalls => &[WALLET_SEND_CALLS],
            Self::WalletCallLive => &[WALLET_GET_CAPABILITIES, WALLET_SEND_CALLS],
            Self::AppkitCapabilityProposal => &[APPKIT_CAPABILITY_PROPOSAL],
            Self::VerifyLive => &[VERIFY_PUBLIC_KEY, VERIFY_CONTEXT],
            Self::InteropLive => &[
                SINGLE_SESSION_AUTH_REJECT,
                SINGLE_SESSION_AUTH_APPROVE,
                VERIFY_PUBLIC_KEY,
                VERIFY_CONTEXT,
                APPKIT_CAPABILITY_PROPOSAL,
                WALLET_GET_CAPABILITIES,
                WALLET_SEND_CALLS,
            ],
        }
    }
}

/// Prints available scenario names and their coverage.
pub fn list() {
    for scenario in ScenarioName::value_variants() {
        println!("{} - {}", scenario.label(), scenario.description());
    }
}

/// Runs one named scenario sequentially.
pub fn run(name: ScenarioName) -> Result<()> {
    require_reown_project_id()?;

    let steps = name.steps();
    let workspace_root = workspace_root()?;
    let current_exe = env::current_exe().context("failed to locate xtask executable")?;
    println!("scenario {} starting steps={}", name.label(), steps.len());

    for (index, step) in steps.iter().enumerate() {
        println!(
            "scenario {} step {}/{} {} starting",
            name.label(),
            index + 1,
            steps.len(),
            step.label
        );
        step.run(&workspace_root, &current_exe)
            .with_context(|| format!("scenario {} failed at {}", name.label(), step.label))?;
        println!(
            "scenario {} step {}/{} {} ok",
            name.label(),
            index + 1,
            steps.len(),
            step.label
        );
    }

    println!("scenario {} ok", name.label());
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ScenarioStep {
    label: &'static str,
    command: ScenarioCommand,
    env: &'static [(&'static str, &'static str)],
}

impl ScenarioStep {
    fn run(self, workspace_root: &Path, current_exe: &Path) -> Result<()> {
        let mut command = match self.command {
            ScenarioCommand::Xtask(args) => {
                let mut command = Command::new(current_exe);
                command.args(args);
                command
            }
            ScenarioCommand::JsHarness { script } => {
                let mut command = Command::new("bun");
                command
                    .arg("run")
                    .arg(script)
                    .current_dir(workspace_root.join("tools/js-harness"));
                command
            }
        };

        command.envs(self.env.iter().copied());
        let status = command
            .status()
            .with_context(|| format!("failed to run scenario step {}", self.label))?;
        ensure_success(self.label, status)
    }
}

#[derive(Debug, Clone, Copy)]
enum ScenarioCommand {
    Xtask(&'static [&'static str]),
    JsHarness { script: &'static str },
}

const RELAY_MATRIX: ScenarioStep = ScenarioStep {
    label: "relay-matrix",
    command: ScenarioCommand::Xtask(&["relay-probe", "--matrix"]),
    env: &[],
};

const SINGLE_SESSION_REQUEST: ScenarioStep = ScenarioStep {
    label: "single-session-request",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-request",
    ]),
    env: &[],
};

const SINGLE_SESSION_LIFECYCLE: ScenarioStep = ScenarioStep {
    label: "single-session-lifecycle",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-lifecycle",
    ]),
    env: &[],
};

const SINGLE_SESSION_DISCONNECT: ScenarioStep = ScenarioStep {
    label: "single-session-disconnect",
    command: ScenarioCommand::Xtask(&["relay-probe", "--core-single-session-client-disconnect"]),
    env: &[],
};

const SINGLE_SESSION_AUTH_REJECT: ScenarioStep = ScenarioStep {
    label: "single-session-authenticate-reject",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-authenticate",
    ]),
    env: &[("WC_CORE_SESSION_AUTHENTICATE_RESPONSE", "reject")],
};

const SINGLE_SESSION_AUTH_APPROVE: ScenarioStep = ScenarioStep {
    label: "single-session-authenticate-approve",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-authenticate",
    ]),
    env: &[
        ("WC_CORE_SESSION_AUTHENTICATE_RESPONSE", "approve"),
        ("WC_JS_HARNESS_HOLD_MS", "60000"),
    ],
};

const WALLET_GET_CAPABILITIES_PARAMS: &str =
    r#"["0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",["eip155:1"]]"#;
const WALLET_GET_CAPABILITIES_RESULT: &str = r#"{"eip155:1":{"atomic":{"status":"supported"}}}"#;
const WALLET_SEND_CALLS_PARAMS: &str = r#"[{"version":"2.0.0","from":"0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb","chainId":"0x1","atomicRequired":true,"calls":[{"to":"0xd46e8dd67c5d32be8058bb8eb970870f07244567","value":"0x0","data":"0x"}],"capabilities":{"paymasterService":{"url":"https://example.com/paymaster","optional":true}}}]"#;
const WALLET_SEND_CALLS_RESULT: &str =
    r#"{"id":"0x0000000000000000000000000000000000000000000000000000000000000001"}"#;
const APPKIT_PROPOSAL_SESSION_PROPERTIES: &str =
    r#"{"atomic":{"status":"supported"},"futureOptional":{"optional":true}}"#;
const APPKIT_APPROVAL_SESSION_PROPERTIES: &str = r#"{"atomic":{"status":"ready"}}"#;
const APPKIT_PROPOSAL_SCOPED_PROPERTIES: &str =
    r#"{"eip155:1":{"atomic":{"status":"supported"},"paymasterService":{"optional":true}}}"#;
const APPKIT_APPROVAL_SCOPED_PROPERTIES: &str = r#"{"eip155:1":{"atomic":{"status":"supported"}}}"#;

const WALLET_GET_CAPABILITIES: ScenarioStep = ScenarioStep {
    label: "wallet-call-get-capabilities",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-request",
    ]),
    env: &[
        ("WC_JS_HARNESS_HOLD_MS", "60000"),
        ("WC_JS_SESSION_REQUEST_HOLD_MS", "30000"),
        ("WC_JS_PROPOSAL_METHODS", "wallet_getCapabilities"),
        ("WC_APPROVAL_METHODS", "wallet_getCapabilities"),
        ("WC_JS_SESSION_REQUEST_METHOD", "wallet_getCapabilities"),
        (
            "WC_JS_SESSION_REQUEST_PARAMS_JSON",
            WALLET_GET_CAPABILITIES_PARAMS,
        ),
        (
            "WC_CORE_SESSION_REQUEST_RESULT_JSON",
            WALLET_GET_CAPABILITIES_RESULT,
        ),
    ],
};

const WALLET_SEND_CALLS: ScenarioStep = ScenarioStep {
    label: "wallet-call-send-calls",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-request",
    ]),
    env: &[
        ("WC_JS_HARNESS_HOLD_MS", "60000"),
        ("WC_JS_SESSION_REQUEST_HOLD_MS", "30000"),
        ("WC_JS_PROPOSAL_METHODS", "wallet_sendCalls"),
        ("WC_APPROVAL_METHODS", "wallet_sendCalls"),
        ("WC_JS_SESSION_REQUEST_METHOD", "wallet_sendCalls"),
        (
            "WC_JS_SESSION_REQUEST_PARAMS_JSON",
            WALLET_SEND_CALLS_PARAMS,
        ),
        (
            "WC_CORE_SESSION_REQUEST_RESULT_JSON",
            WALLET_SEND_CALLS_RESULT,
        ),
    ],
};

const APPKIT_CAPABILITY_PROPOSAL: ScenarioStep = ScenarioStep {
    label: "appkit-capability-proposal",
    command: ScenarioCommand::Xtask(&[
        "relay-probe",
        "--core-single-session-client-session-request",
    ]),
    env: &[
        ("WC_JS_HARNESS_HOLD_MS", "60000"),
        ("WC_JS_SESSION_REQUEST_HOLD_MS", "30000"),
        (
            "WC_JS_PROPOSAL_METHODS",
            "wallet_getCapabilities,wallet_sendCalls",
        ),
        (
            "WC_APPROVAL_METHODS",
            "wallet_getCapabilities,wallet_sendCalls",
        ),
        ("WC_JS_SESSION_REQUEST_METHOD", "wallet_getCapabilities"),
        (
            "WC_JS_SESSION_REQUEST_PARAMS_JSON",
            WALLET_GET_CAPABILITIES_PARAMS,
        ),
        (
            "WC_CORE_SESSION_REQUEST_RESULT_JSON",
            WALLET_GET_CAPABILITIES_RESULT,
        ),
        (
            "WC_JS_SESSION_PROPERTIES_JSON",
            APPKIT_PROPOSAL_SESSION_PROPERTIES,
        ),
        (
            "WC_APPROVAL_SESSION_PROPERTIES_JSON",
            APPKIT_APPROVAL_SESSION_PROPERTIES,
        ),
        (
            "WC_JS_SCOPED_PROPERTIES_JSON",
            APPKIT_PROPOSAL_SCOPED_PROPERTIES,
        ),
        (
            "WC_APPROVAL_SCOPED_PROPERTIES_JSON",
            APPKIT_APPROVAL_SCOPED_PROPERTIES,
        ),
    ],
};

const VERIFY_PUBLIC_KEY: ScenarioStep = ScenarioStep {
    label: "verify-public-key",
    command: ScenarioCommand::Xtask(&["verify-probe", "--public-key"]),
    env: &[],
};

const VERIFY_CONTEXT: ScenarioStep = ScenarioStep {
    label: "verify-context",
    command: ScenarioCommand::JsHarness {
        script: "verify-context",
    },
    env: &[("WC_JS_HARNESS_HOLD_MS", "45000")],
};

fn require_reown_project_id() -> Result<()> {
    env::var("REOWN_PROJECT_ID")
        .or_else(|_| env::var("WALLETCONNECT_PROJECT_ID"))
        .context("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID for live scenarios")?;
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    let xtask_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    xtask_dir
        .parent()
        .map(PathBuf::from)
        .context("xtask manifest directory has no workspace parent")
}

fn ensure_success(label: &str, status: ExitStatus) -> Result<()> {
    if status.success() {
        Ok(())
    } else {
        bail!("scenario step {label} exited with {status}")
    }
}

#[cfg(test)]
mod tests {
    use super::{ScenarioCommand, ScenarioName};

    #[test]
    fn interop_live_covers_auth_verify_and_wallet_call_steps() {
        let labels = ScenarioName::InteropLive
            .steps()
            .iter()
            .map(|step| step.label)
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            [
                "single-session-authenticate-reject",
                "single-session-authenticate-approve",
                "verify-public-key",
                "verify-context",
                "appkit-capability-proposal",
                "wallet-call-get-capabilities",
                "wallet-call-send-calls",
            ]
        );
    }

    #[test]
    fn wallet_call_steps_pin_methods_and_results() {
        let steps = ScenarioName::WalletCallLive.steps();

        assert_eq!(steps.len(), 2);
        assert!(
            steps[0]
                .env
                .contains(&("WC_JS_SESSION_REQUEST_METHOD", "wallet_getCapabilities"))
        );
        assert!(
            steps[1]
                .env
                .contains(&("WC_JS_SESSION_REQUEST_METHOD", "wallet_sendCalls"))
        );
        assert!(
            steps[0]
                .env
                .iter()
                .any(|(key, value)| *key == "WC_CORE_SESSION_REQUEST_RESULT_JSON"
                    && value.contains("supported"))
        );
        assert!(
            steps[1]
                .env
                .iter()
                .any(|(key, value)| *key == "WC_CORE_SESSION_REQUEST_RESULT_JSON"
                    && value.contains("0x000000"))
        );
    }

    #[test]
    fn verify_context_runs_the_js_sdk_harness() {
        let step = ScenarioName::VerifyLive
            .steps()
            .iter()
            .find(|step| step.label == "verify-context")
            .expect("verify-live should include verify-context");

        assert!(matches!(
            step.command,
            ScenarioCommand::JsHarness {
                script: "verify-context"
            }
        ));
    }
}
