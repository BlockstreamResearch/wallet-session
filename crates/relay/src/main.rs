//! Relay server entrypoint.
//!
//! Configuration comes from `configuration/*.yaml`: `base.yaml` plus the
//! overlay named by `APP_ENVIRONMENT`, with environment variables overriding
//! both. The relay speaks plain WebSocket and expects TLS to be terminated in
//! front of it. Logs are bunyan JSON on stdout, written by a thread of their
//! own: when stdout falls behind, records are dropped rather than waited for.

use std::sync::Arc;

use anyhow::Context;
use tokio::{net::TcpListener, sync::watch};
use wallet_session_relay::{
    config::NativeRelayTransportConfig,
    configuration::Settings,
    health,
    limits::Limiter,
    registry::Registry,
    server::serve,
    telemetry::{SERVICE_NAME, get_subscriber, init_subscriber, non_blocking},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (log_writer, _log_guard) =
        non_blocking(std::io::stdout()).context("failed to start the log writer")?;
    let subscriber = get_subscriber(SERVICE_NAME.to_owned(), "info".to_owned(), log_writer);
    init_subscriber(subscriber);

    let settings =
        Settings::get_configuration().context("failed to read the relay configuration")?;
    run(settings).await
}

async fn run(settings: Settings) -> anyhow::Result<()> {
    let relay_address = settings.application_address();
    let health_address = settings.health_address();

    let relay_listener = TcpListener::bind(relay_address)
        .await
        .with_context(|| format!("failed to bind the relay listener on {relay_address}"))?;
    let health_listener = TcpListener::bind(health_address)
        .await
        .with_context(|| format!("failed to bind the health listener on {health_address}"))?;

    if !relay_address.ip().is_loopback() {
        tracing::warn!(
            %relay_address,
            "listening without TLS; terminate TLS in front of the relay, \
             since connection tokens travel in the URL"
        );
    }
    tracing::info!(
        %relay_address,
        audience = %settings.application.audience,
        "accepting connection tokens"
    );
    tracing::info!(
        %health_address,
        health = health::HEALTH_PATH,
        ready = health::READY_PATH,
        "serving health probes"
    );

    let registry = Arc::new(Registry::new());
    let limiter = Arc::new(Limiter::new((&settings).into()));
    let transport = NativeRelayTransportConfig::from(&settings);

    let (shutdown_tx, shutdown_rx) = watch::channel(());
    tokio::spawn({
        let registry = Arc::clone(&registry);
        let limiter = Arc::clone(&limiter);
        async move {
            if let Err(error) = health::serve(health_listener, registry, limiter, shutdown_rx).await
            {
                tracing::error!(%error, "health endpoint stopped");
            }
        }
    });

    tokio::select! {
        result = serve(relay_listener, registry, limiter, transport) => {
            result.context("relay listener failed")?;
        }
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received; stopping");
        }
    }

    // Open connections are dropped rather than drained: peers reconnect and
    // recover un-ACKed messages through their own retries.
    let _ = shutdown_tx.send(());
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "could not listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };

    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "could not listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
