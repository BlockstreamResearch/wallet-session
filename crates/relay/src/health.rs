use std::{io, sync::Arc};

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde::Serialize;
use tokio::{net::TcpListener, sync::watch};

use crate::{limits::Limiter, registry::Registry};

/// Liveness path.
pub const HEALTH_PATH: &str = "/health";

/// Readiness path.
pub const READY_PATH: &str = "/ready";

/// Everything the health endpoints read.
#[derive(Clone)]
pub struct HealthState {
    registry: Arc<Registry>,
    limiter: Arc<Limiter>,
}

/// `{"status": "..."}` body.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    status: &'static str,
}

/// `{"status": "...", "connections": n, "sessions": n}` body.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    status: &'static str,
    connections: usize,
    sessions: usize,
}

/// Health routes, with their state attached.
pub fn routes(registry: Arc<Registry>, limiter: Arc<Limiter>) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route(READY_PATH, get(ready))
        .with_state(HealthState { registry, limiter })
}

/// Serve health probes until `shutdown` fires or the listener fails.
pub async fn serve(
    listener: TcpListener,
    registry: Arc<Registry>,
    limiter: Arc<Limiter>,
    mut shutdown: watch::Receiver<()>,
) -> io::Result<()> {
    match listener.local_addr() {
        Ok(addr) => log::info!("health endpoint listening on {addr}"),
        Err(error) => log::warn!("health listening address unavailable: {error}"),
    }

    axum::serve(listener, routes(registry, limiter))
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
}

/// Liveness: the process is running.
async fn health() -> Json<StatusResponse> {
    Json(StatusResponse { status: "ok" })
}

/// Readiness: shared state is usable, with what the relay is currently doing.
async fn ready(State(state): State<HealthState>) -> impl IntoResponse {
    match state.registry.session_count() {
        Ok(sessions) => (
            StatusCode::OK,
            Json(ReadinessResponse {
                status: "ok",
                connections: state.limiter.active_connections(),
                sessions,
            }),
        )
            .into_response(),
        Err(error) => {
            log::error!("readiness check failed: {error}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(StatusResponse {
                    status: "unavailable",
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    use tower::ServiceExt;
    use wallet_session_core::{
        did::DidKey,
        frame::{RelayFrame, RelayFrameBody},
        message::Topic,
    };

    use super::*;
    use crate::{
        limits::RelayLimitsConfig,
        session::{PeerHandle, Role},
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn state() -> (Arc<Registry>, Arc<Limiter>) {
        (
            Arc::new(Registry::new()),
            Arc::new(Limiter::new(RelayLimitsConfig::default())),
        )
    }

    async fn get(
        registry: Arc<Registry>,
        limiter: Arc<Limiter>,
        path: &str,
    ) -> (StatusCode, Vec<u8>) {
        let response = routes(registry, limiter)
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let status = response.status();
        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body")
            .to_vec();
        (status, body)
    }

    #[tokio::test]
    async fn health_reports_ok() -> TestResult {
        let (registry, limiter) = state();
        let (status, body) = get(registry, limiter, HEALTH_PATH).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({ "status": "ok" })
        );
        Ok(())
    }

    #[tokio::test]
    async fn readiness_reports_counts() -> TestResult {
        let (registry, limiter) = state();
        let topic = Topic::new([3u8; 32])?;
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        let identity = DidKey::from_ed25519_bytes([1u8; 32]);
        let permit = limiter.acquire_identity(&identity);
        registry.register(
            &topic,
            Role::Proposer,
            PeerHandle {
                identity: identity.clone(),
                tx,
            },
            permit,
            &RelayFrame {
                v: 1,
                id: "ready".to_owned(),
                topic: topic.clone(),
                body: RelayFrameBody::SessionReady,
            },
            usize::MAX,
        )?;
        let _slot = limiter.acquire_total();

        let (status, body) = get(registry, limiter, READY_PATH).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({ "status": "ok", "connections": 1, "sessions": 1 })
        );
        Ok(())
    }

    #[tokio::test]
    async fn readiness_reports_unavailable_when_the_registry_is_broken() -> TestResult {
        let (registry, limiter) = state();
        registry.poison_for_test();

        let (status, body) = get(registry, limiter, READY_PATH).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body)?,
            serde_json::json!({ "status": "unavailable" })
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_paths_and_methods_are_rejected() -> TestResult {
        let (registry, limiter) = state();

        let (status, _) = get(Arc::clone(&registry), Arc::clone(&limiter), "/healthz").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let response = routes(registry, limiter)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(HEALTH_PATH)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }

    /// Serve over a real listener and speak HTTP/1.1 to it.
    async fn exchange(addr: std::net::SocketAddr, request: &str) -> io::Result<String> {
        let mut stream = TcpStream::connect(addr).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut out = String::new();
        stream.read_to_string(&mut out).await?;
        Ok(out)
    }

    /// A served health endpoint. Holds the shutdown sender, because dropping
    /// it stops the server.
    struct TestServer {
        addr: std::net::SocketAddr,
        _shutdown: watch::Sender<()>,
    }

    impl std::ops::Deref for TestServer {
        type Target = std::net::SocketAddr;

        fn deref(&self) -> &Self::Target {
            &self.addr
        }
    }

    async fn start() -> Result<TestServer, Box<dyn std::error::Error>> {
        let (registry, limiter) = state();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown, shutdown_rx) = watch::channel(());
        tokio::spawn(serve(listener, registry, limiter, shutdown_rx));
        Ok(TestServer {
            addr,
            _shutdown: shutdown,
        })
    }

    #[tokio::test]
    async fn serves_both_endpoints_over_http() -> TestResult {
        let server = start().await?;

        let ready = exchange(
            *server,
            "GET /ready HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert!(ready.starts_with("HTTP/1.1 200 OK\r\n"), "{ready}");
        assert!(ready.contains("content-type: application/json"), "{ready}");
        assert!(
            ready.ends_with(r#"{"status":"ok","connections":0,"sessions":0}"#),
            "{ready}"
        );

        let health = exchange(
            *server,
            "GET /health HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n",
        )
        .await?;
        assert!(health.ends_with(r#"{"status":"ok"}"#), "{health}");
        Ok(())
    }

    #[tokio::test]
    async fn probes_beyond_the_cap_are_still_served() -> TestResult {
        let server = start().await?;

        // A burst of probes must not be throttled: hyper keeps the listener
        // responsive, unlike a probe implementation with its own budget.
        for _ in 0..64 {
            let response = exchange(
                *server,
                "GET /health HTTP/1.1\r\nHost: relay\r\nConnection: close\r\n\r\n",
            )
            .await?;
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_stops_the_listener() -> TestResult {
        let (registry, limiter) = state();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(());
        let server = tokio::spawn(serve(listener, registry, limiter, shutdown_rx));

        exchange(addr, "GET /health HTTP/1.1\r\nConnection: close\r\n\r\n").await?;

        shutdown_tx.send(())?;
        let joined = tokio::time::timeout(Duration::from_secs(2), server).await?;
        let served = joined.expect("health server task panicked");
        assert!(served.is_ok(), "health server failed: {served:?}");
        Ok(())
    }
}
