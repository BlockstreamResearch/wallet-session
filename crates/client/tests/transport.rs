use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_tungstenite::{
    accept_async,
    tungstenite::{
        Bytes, Message,
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use wallet_session_client::{
    Client, ClientConfig, ClientError, IdentityKey, Role, Seed, XChaCha20Poly1305Cipher,
};
use wallet_session_core::message::Topic;

const AUDIENCE: &str = "ws://test";

type TestResult = Result<(), Box<dyn std::error::Error>>;
type TestClient = Client<XChaCha20Poly1305Cipher>;

fn config(addr: std::net::SocketAddr) -> ClientConfig {
    ClientConfig::new(format!("ws://{addr}"))
        .with_insecure_ws()
        .with_audience(AUDIENCE)
        .with_connect_timeout(Duration::from_secs(1))
        .with_write_timeout(Duration::from_secs(1))
        .with_close_timeout(Duration::from_secs(1))
        .with_ping_interval(Duration::from_secs(30))
        .with_pong_timeout(Duration::from_secs(5))
}

async fn connect(
    _addr: std::net::SocketAddr,
    config: ClientConfig,
) -> Result<TestClient, Box<dyn std::error::Error>> {
    Ok(Client::connect(
        config,
        IdentityKey::from_seed(&Seed::from_bytes([1u8; 32])),
        Role::Proposer,
        Topic::new([9u8; 32])?,
        XChaCha20Poly1305Cipher::new([7u8; 32])?,
    )
    .await?)
}

async fn accept(listener: &TcpListener) -> std::io::Result<TcpStream> {
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

#[tokio::test]
async fn policy_close_is_terminal_and_surfaced() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let server = {
        let accepts = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok(stream) = accept(&listener).await else {
                    return;
                };
                accepts.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    let _ = socket
                        .close(Some(CloseFrame {
                            code: CloseCode::Policy,
                            reason: "role already taken".into(),
                        }))
                        .await;
                });
            }
        })
    };

    let mut client = connect(addr, config(addr)).await?;
    let error = timeout(Duration::from_secs(2), client.recv())
        .await?
        .expect_err("unexpected message");
    assert!(
        matches!(error, ClientError::Transport("role already taken")),
        "unexpected error: {error:?}"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "a policy rejection must not reconnect"
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn token_expiry_reconnects_without_backoff() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let server = {
        let accepts = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok(stream) = accept(&listener).await else {
                    return;
                };
                let accepted = accepts.fetch_add(1, Ordering::Relaxed) + 1;
                tokio::spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    if accepted == 1 {
                        let _ = socket
                            .close(Some(CloseFrame {
                                code: CloseCode::Policy,
                                reason: "token expired".into(),
                            }))
                            .await;
                    } else {
                        // Keep the reconnected socket open for the assertion.
                        let _ = socket.next().await;
                    }
                });
            }
        })
    };

    let _client = connect(
        addr,
        config(addr).with_reconnect_initial_delay(Duration::from_secs(5)),
    )
    .await?;

    let started = Instant::now();
    timeout(Duration::from_secs(1), async {
        while accepts.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("token expiry did not reconnect immediately");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "token expiry must bypass the reconnect backoff"
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn reconnect_attempts_are_exactly_bounded() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let server = {
        let accepts = Arc::clone(&accepts);
        tokio::spawn(async move {
            loop {
                let Ok(stream) = accept(&listener).await else {
                    return;
                };
                accepts.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    let _ = socket
                        .close(Some(CloseFrame {
                            code: CloseCode::Policy,
                            reason: "token expired".into(),
                        }))
                        .await;
                });
            }
        })
    };

    let mut client = connect(addr, config(addr).with_reconnect_max_attempts(2)).await?;
    let error = timeout(Duration::from_secs(1), client.recv())
        .await?
        .expect_err("unexpected message");
    assert!(
        matches!(error, ClientError::Transport("token expired")),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        3,
        "one initial connection plus exactly two retries"
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn shutdown_sends_a_normal_close_frame() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (connected_tx, connected_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");
        socket
            .send(Message::Ping(Bytes::new()))
            .await
            .expect("ping");
        let mut connected_tx = Some(connected_tx);
        while let Some(Ok(message)) = socket.next().await {
            match message {
                Message::Pong(_) => {
                    if let Some(tx) = connected_tx.take() {
                        let _ = tx.send(());
                    }
                }
                Message::Close(Some(frame)) => {
                    let _ = close_tx.send(frame);
                    return;
                }
                _ => {}
            }
        }
    });

    let client = connect(addr, config(addr)).await?;
    timeout(Duration::from_secs(1), connected_rx).await??;
    drop(client);

    let close = timeout(Duration::from_secs(1), close_rx).await??;
    assert_eq!(close.code, CloseCode::Normal);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn connect_timeout_is_surfaced_and_stops() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let _stream = stream;
        std::future::pending::<()>().await;
    });

    let mut client = connect(
        addr,
        config(addr)
            .with_connect_timeout(Duration::from_millis(100))
            .with_reconnect_max_attempts(0),
    )
    .await?;
    let error = timeout(Duration::from_secs(2), client.recv())
        .await?
        .expect_err("unexpected message");
    assert!(
        matches!(error, ClientError::Transport("relay connect timed out")),
        "unexpected error: {error:?}"
    );
    server.abort();
    Ok(())
}
