use std::env;

use anyhow::{Context, Result};
use clap::ValueEnum;

use crate::relay::{self, ProbeMode};

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
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::DefaultLive => "relay matrix plus single-session request/lifecycle/disconnect",
            Self::RelayMatrix => "relay publish, subscribe, fetch, unsubscribe, batch, envelope",
            Self::SingleSessionLive => "single-session request, lifecycle update, and disconnect",
            Self::SingleSessionRequest => "single-session proposal approval and request response",
            Self::SingleSessionLifecycle => "single-session proposal approval and session update",
            Self::SingleSessionDisconnect => "single-session proposal approval and disconnect",
        }
    }

    const fn modes(self) -> &'static [ProbeMode] {
        match self {
            Self::DefaultLive => &[
                ProbeMode::Matrix,
                ProbeMode::CoreSingleSessionClientSessionRequest,
                ProbeMode::CoreSingleSessionClientSessionLifecycle,
                ProbeMode::CoreSingleSessionClientDisconnect,
            ],
            Self::RelayMatrix => &[ProbeMode::Matrix],
            Self::SingleSessionLive => &[
                ProbeMode::CoreSingleSessionClientSessionRequest,
                ProbeMode::CoreSingleSessionClientSessionLifecycle,
                ProbeMode::CoreSingleSessionClientDisconnect,
            ],
            Self::SingleSessionRequest => &[ProbeMode::CoreSingleSessionClientSessionRequest],
            Self::SingleSessionLifecycle => &[ProbeMode::CoreSingleSessionClientSessionLifecycle],
            Self::SingleSessionDisconnect => &[ProbeMode::CoreSingleSessionClientDisconnect],
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
pub async fn run(name: ScenarioName) -> Result<()> {
    require_reown_project_id()?;

    let modes = name.modes();
    println!("scenario {} starting probes={}", name.label(), modes.len());

    for (index, mode) in modes.iter().enumerate() {
        println!(
            "scenario {} probe {}/{} {} starting",
            name.label(),
            index + 1,
            modes.len(),
            mode.label()
        );
        relay::run(mode.clone())
            .await
            .with_context(|| format!("scenario {} failed at {}", name.label(), mode.label()))?;
        println!(
            "scenario {} probe {}/{} {} ok",
            name.label(),
            index + 1,
            modes.len(),
            mode.label()
        );
    }

    println!("scenario {} ok", name.label());
    Ok(())
}

fn require_reown_project_id() -> Result<()> {
    env::var("REOWN_PROJECT_ID")
        .or_else(|_| env::var("WALLETCONNECT_PROJECT_ID"))
        .context("set REOWN_PROJECT_ID or WALLETCONNECT_PROJECT_ID for live scenarios")?;
    Ok(())
}

impl ProbeMode {
    const fn label(&self) -> &'static str {
        match self {
            Self::Basic => "relay-basic",
            Self::Matrix => "relay-matrix",
            Self::JsProposal => "js-proposal",
            Self::CoreJsProposal => "core-js-proposal",
            Self::CoreJsApproveProposal => "core-js-approve-proposal",
            Self::CoreJsRejectProposal => "core-js-reject-proposal",
            Self::CoreJsPairingLifecycle => "core-js-pairing-lifecycle",
            Self::CoreJsSessionRequest => "core-js-session-request",
            Self::CoreJsSessionLifecycle => "core-js-session-lifecycle",
            Self::CoreSingleSessionClientSessionRequest => {
                "core-single-session-client-session-request"
            }
            Self::CoreSingleSessionClientSessionLifecycle => {
                "core-single-session-client-session-lifecycle"
            }
            Self::CoreSingleSessionClientDisconnect => "core-single-session-client-disconnect",
            Self::PairingUri(_) => "pairing-uri",
        }
    }
}
