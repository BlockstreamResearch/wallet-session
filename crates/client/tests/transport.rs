use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
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
use wallet_session_core::{
    frame::{RelayFrame, RelayFrameBody},
    message::{MessageId, Topic},
};

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
    let again = timeout(Duration::from_millis(100), client.recv())
        .await?
        .expect_err("the terminal state must not hang");
    assert!(
        matches!(again, ClientError::Transport("role already taken")),
        "unexpected repeated error: {again:?}"
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
async fn stable_connections_reset_the_token_expiry_budget() -> TestResult {
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
                    // Start the stable-connection window only after the client
                    // is demonstrably running its connection loop.
                    while let Some(message) = socket.next().await {
                        if matches!(message, Ok(Message::Ping(_))) {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
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

    let _client = connect(
        addr,
        config(addr)
            .with_ping_interval(Duration::from_millis(10))
            .with_reconnect_max_attempts(1)
            .with_connection_stability(Duration::from_millis(50)),
    )
    .await?;

    timeout(Duration::from_secs(2), async {
        while accepts.load(Ordering::Relaxed) < 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stable token-expiry reconnects must not exhaust the retry budget");
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
async fn sends_before_readiness_are_rejected() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");
        while socket.next().await.is_some() {}
    });

    let mut client = connect(addr, config(addr)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        matches!(
            client.propose(json!({ "test": true })).await,
            Err(ClientError::NotReady)
        ),
        "handshake sends require pairing readiness"
    );
    assert!(matches!(
        client.request(json!({ "method": "too_early" })).await,
        Err(ClientError::SessionNotActive)
    ));

    drop(client);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn inbox_stall_does_not_kill_the_transport() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let accepts = Arc::new(AtomicUsize::new(0));
    let topic = Topic::new([9u8; 32])?;
    let server = {
        let accepts = Arc::clone(&accepts);
        let topic = topic.clone();
        tokio::spawn(async move {
            loop {
                let Ok(stream) = accept(&listener).await else {
                    return;
                };
                let accepted = accepts.fetch_add(1, Ordering::Relaxed) + 1;
                let topic = topic.clone();
                tokio::spawn(async move {
                    let Ok(mut socket) = accept_async(stream).await else {
                        return;
                    };
                    if accepted == 1 {
                        // Fill the client inbox faster than it is drained.
                        for index in 0..100u8 {
                            let frame = RelayFrame {
                                v: 1,
                                id: MessageId::from_bytes([index; MessageId::LEN]),
                                topic: topic.clone(),
                                body: RelayFrameBody::Message {
                                    payload: "not an envelope".to_owned(),
                                },
                            };
                            let text = serde_json::to_string(&frame).expect("json");
                            if socket.send(Message::Text(text.into())).await.is_err() {
                                return;
                            }
                        }
                        // End the connection while the client inbox is full,
                        // so the lifecycle send has to wait.
                        let _ = socket.close(None).await;
                    } else {
                        let frame = RelayFrame {
                            v: 1,
                            id: MessageId::from_bytes([u8::MAX; MessageId::LEN]),
                            topic,
                            body: RelayFrameBody::SessionReady,
                        };
                        let text = serde_json::to_string(&frame).expect("json");
                        let _ = socket.send(Message::Text(text.into())).await;
                        let _ = socket.next().await;
                    }
                });
            }
        })
    };

    let mut client = connect(
        addr,
        config(addr)
            .with_idle_timeout(Duration::from_millis(50))
            .with_reconnect_initial_delay(Duration::from_millis(10)),
    )
    .await?;

    // Let the inbox fill and the transport stall past twice the send timeout.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "the task should be stalled on a lifecycle send"
    );

    // Draining the backlog must let the task finish its lifecycle sends and
    // reconnect instead of exiting silently.
    timeout(Duration::from_secs(2), client.wait_session_ready()).await??;
    assert!(
        accepts.load(Ordering::Relaxed) >= 2,
        "the transport must reconnect after the inbox drains"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn disconnect_closes_locally_when_not_ready() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");
        while socket.next().await.is_some() {}
    });

    let mut client = connect(addr, config(addr)).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = client.disconnect("bye", 1000).await;
    assert!(
        matches!(
            result,
            Err(ClientError::SessionNotActive | ClientError::NotReady)
        ),
        "unexpected disconnect result: {result:?}"
    );
    assert!(matches!(client.recv().await, Err(ClientError::Closed)));

    server.abort();
    Ok(())
}

#[tokio::test]
async fn pings_are_answered_while_the_client_inbox_is_full() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let topic = Topic::new([9u8; 32])?;
    let (pong_tx, pong_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");

        // Fill the client inbox faster than it is drained.
        for index in 0..100u8 {
            let frame = RelayFrame {
                v: 1,
                id: MessageId::from_bytes([index; MessageId::LEN]),
                topic: topic.clone(),
                body: RelayFrameBody::Message {
                    payload: "not an envelope".to_owned(),
                },
            };
            let text = serde_json::to_string(&frame).expect("json");
            socket
                .send(Message::Text(text.into()))
                .await
                .expect("frame");
        }

        socket
            .send(Message::Ping(Bytes::new()))
            .await
            .expect("ping");
        let pong = timeout(Duration::from_secs(1), async {
            while let Some(message) = socket.next().await {
                if matches!(message, Ok(Message::Pong(_))) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap_or(false);
        let _ = pong_tx.send(pong);
        std::future::pending::<()>().await;
    });

    let _client = connect(addr, config(addr)).await?;
    let ponged = timeout(Duration::from_secs(2), pong_rx).await??;
    assert!(
        ponged,
        "the transport must answer pings while the client inbox is full"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn liveness_timeouts_do_not_reset_the_reconnect_budget() -> TestResult {
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
                    let Ok(_socket) = accept_async(stream).await else {
                        return;
                    };
                    // Complete the upgrade, then stop reading so pings are
                    // never answered. This is a black-holed socket.
                    std::future::pending::<()>().await;
                });
            }
        })
    };

    let mut client = connect(
        addr,
        config(addr)
            .with_connection_stability(Duration::from_millis(10))
            .with_ping_interval(Duration::from_millis(100))
            .with_pong_timeout(Duration::from_millis(100))
            .with_reconnect_initial_delay(Duration::from_millis(10))
            .with_reconnect_max_attempts(1),
    )
    .await?;

    let error = timeout(Duration::from_secs(3), client.recv())
        .await?
        .expect_err("the client should become terminal");
    assert!(
        matches!(error, ClientError::Transport("relay pong timed out")),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        2,
        "a liveness timeout must not reset the retry budget"
    );

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
