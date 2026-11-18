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
    Client, ClientConfig, ClientError, ClientEvent, ClientMessage, DisconnectPayload, IdentityKey,
    Opaque, ResponsePayload, Role, Seed, SessionDeletePayload, XChaCha20Poly1305Cipher,
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
        XChaCha20Poly1305Cipher::new(&[7u8; 32])?,
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

    // Wait past the 250ms default reconnect delay, so a retry scheduled
    // alongside the terminal error would have happened.
    tokio::time::sleep(Duration::from_millis(400)).await;
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
    let (closed_tx, closed_rx) = oneshot::channel::<()>();
    let server = {
        let accepts = Arc::clone(&accepts);
        let topic = topic.clone();
        let mut closed_tx = Some(closed_tx);
        tokio::spawn(async move {
            loop {
                let Ok(stream) = accept(&listener).await else {
                    return;
                };
                let accepted = accepts.fetch_add(1, Ordering::Relaxed) + 1;
                let topic = topic.clone();
                let closed = if accepted == 1 {
                    closed_tx.take()
                } else {
                    None
                };
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
                        if let Some(closed) = closed {
                            let _ = closed.send(());
                        }
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

    // Once the server has filled the inbox and closed the socket, the
    // transport has to wait to report `Disconnected`. Wait well past twice the
    // idle timeout, which is when the old code gave up and exited silently.
    timeout(Duration::from_secs(2), closed_rx).await??;
    tokio::time::sleep(Duration::from_millis(250)).await;
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
    // Bounded, so a regression fails instead of hanging the suite.
    assert!(matches!(
        timeout(Duration::from_secs(2), client.recv()).await?,
        Err(ClientError::Closed)
    ));

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
async fn a_stall_after_a_healthy_stretch_resets_the_budget() -> TestResult {
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
                    // Answer pings for well over the stability period, then
                    // stop reading, like a network that drops out.
                    let _ = timeout(Duration::from_millis(500), async {
                        while socket.next().await.is_some() {}
                    })
                    .await;
                    std::future::pending::<()>().await;
                });
            }
        })
    };

    let mut client = connect(
        addr,
        config(addr)
            .with_connection_stability(Duration::from_millis(200))
            .with_ping_interval(Duration::from_millis(50))
            .with_pong_timeout(Duration::from_millis(100))
            .with_reconnect_initial_delay(Duration::from_millis(10))
            .with_reconnect_max_attempts(1),
    )
    .await?;

    // With one attempt, a second outage would close the client unless the
    // healthy stretch before each one resets the budget.
    assert!(
        timeout(Duration::from_secs(3), client.recv())
            .await
            .is_err(),
        "the client must keep reconnecting"
    );
    assert!(
        accepts.load(Ordering::Relaxed) >= 3,
        "each healthy connection is followed by a reconnect"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn relay_pings_alone_do_not_reset_the_budget() -> TestResult {
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
                    // Keep sending our own pings, but never read, so the
                    // client's pings go unanswered.
                    loop {
                        if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                });
            }
        })
    };

    let mut client = connect(
        addr,
        config(addr)
            .with_connection_stability(Duration::from_millis(100))
            .with_ping_interval(Duration::from_millis(50))
            .with_pong_timeout(Duration::from_millis(200))
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
        "pings from the relay must not count as it answering ours"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn ready_then_stalled_connections_do_not_reset_the_budget() -> TestResult {
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
                    // Say the session is ready, then stop answering pings.
                    let frame = RelayFrame {
                        v: 1,
                        id: MessageId::from_bytes([u8::MAX; MessageId::LEN]),
                        topic: Topic::new([9u8; 32]).expect("topic"),
                        body: RelayFrameBody::SessionReady,
                    };
                    let text = serde_json::to_string(&frame).expect("json");
                    let _ = socket.send(Message::Text(text.into())).await;
                    std::future::pending::<()>().await;
                });
            }
        })
    };

    let mut client = connect(
        addr,
        config(addr)
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
        "a stalled connection must not reset the retry budget, even after session_ready"
    );

    server.abort();
    Ok(())
}

#[tokio::test]
async fn foreign_relay_frames_do_not_signal_readiness() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (release, released) = oneshot::channel::<()>();
    let (processed, foreign_processed) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("upgraded");
        let ready = |v: u8, topic: [u8; 32]| {
            let frame = RelayFrame {
                v,
                id: MessageId::from_bytes([u8::MAX; MessageId::LEN]),
                topic: Topic::new(topic).expect("topic"),
                body: RelayFrameBody::SessionReady,
            };
            Message::Text(serde_json::to_string(&frame).expect("json").into())
        };
        // Another topic, then an unknown version of ours.
        socket.send(ready(1, [8u8; 32])).await.expect("sent");
        socket.send(ready(2, [9u8; 32])).await.expect("sent");
        // The client handles frames in order, so its pong to this ping means
        // it has processed both frames above.
        socket
            .send(Message::Ping(Bytes::from_static(b"barrier")))
            .await
            .expect("sent");
        while let Some(Ok(message)) = socket.next().await {
            if matches!(&message, Message::Pong(payload) if payload.as_ref() == b"barrier") {
                break;
            }
        }
        let _ = processed.send(());
        let _ = released.await;
        socket.send(ready(1, [9u8; 32])).await.expect("sent");
        std::future::pending::<()>().await;
    });

    let mut client = connect(addr, config(addr)).await?;
    timeout(Duration::from_secs(2), foreign_processed).await??;
    assert!(
        !client.is_ready(),
        "a foreign session_ready must not make the client ready"
    );

    release.send(()).expect("server waiting");
    timeout(Duration::from_secs(2), client.wait_session_ready()).await??;
    assert!(client.is_ready());

    server.abort();
    Ok(())
}

#[tokio::test]
async fn send_refuses_messages_it_cannot_deliver() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");
        while socket.next().await.is_some() {}
    });
    let mut client = connect(addr, config(addr)).await?;

    // A response the receiver would drop unacknowledged.
    for (response, error) in [(None, None), (Some(vec![1]), Some(vec![2]))] {
        let result = client
            .send(&ClientMessage::Response(ResponsePayload {
                request_id: "r".into(),
                response: response.map(Opaque),
                error: error.map(Opaque),
            }))
            .await;
        assert!(
            matches!(result, Err(ClientError::ProtocolViolation(_))),
            "unexpected result: {result:?}"
        );
    }

    // Ending the session must go through the methods that also close locally.
    for message in [
        ClientMessage::Disconnect(DisconnectPayload {
            reason: "bye".into(),
            code: 1000,
            message: String::new(),
        }),
        ClientMessage::SessionDelete(SessionDeletePayload {
            code: 1000,
            message: String::new(),
        }),
    ] {
        let result = client.send(&message).await;
        assert!(
            matches!(result, Err(ClientError::ProtocolViolation(_))),
            "unexpected result: {result:?}"
        );
    }

    server.abort();
    Ok(())
}

#[tokio::test]
async fn ready_then_expired_connections_exhaust_the_budget() -> TestResult {
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
                    // Say the session is ready, then close at once as if the
                    // token had expired.
                    let frame = RelayFrame {
                        v: 1,
                        id: MessageId::from_bytes([u8::MAX; MessageId::LEN]),
                        topic: Topic::new([9u8; 32]).expect("topic"),
                        body: RelayFrameBody::SessionReady,
                    };
                    let text = serde_json::to_string(&frame).expect("json");
                    let _ = socket.send(Message::Text(text.into())).await;
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
    let error = timeout(Duration::from_secs(3), async {
        loop {
            if let Err(error) = client.recv().await {
                return error;
            }
        }
    })
    .await?;
    assert!(
        matches!(error, ClientError::Transport("token expired")),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        3,
        "session_ready on a connection that closes at once must not reset the budget"
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

#[tokio::test]
async fn outcomes_come_before_the_error_that_closes_the_client() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let stream = accept(&listener).await.expect("accepted");
        let mut socket = accept_async(stream).await.expect("websocket");
        let frame = RelayFrame {
            v: 1,
            id: MessageId::from_bytes([u8::MAX; MessageId::LEN]),
            topic: Topic::new([9u8; 32]).expect("topic"),
            body: RelayFrameBody::SessionReady,
        };
        let text = serde_json::to_string(&frame).expect("json");
        socket
            .send(Message::Text(text.into()))
            .await
            .expect("ready");
        // Take the proposal without acknowledging it, then refuse the
        // connection for good.
        while let Some(Ok(message)) = socket.next().await {
            if message.is_text() {
                break;
            }
        }
        let _ = socket
            .close(Some(CloseFrame {
                code: CloseCode::Policy,
                reason: "role already taken".into(),
            }))
            .await;
    });

    let mut client = connect(addr, config(addr)).await?;
    client.wait_session_ready().await?;
    let proposal = client.propose(json!({ "test": true })).await?;

    let mut failed = false;
    let error = timeout(Duration::from_secs(3), async {
        loop {
            match client.next_event().await {
                Ok(ClientEvent::Failed { id, .. }) if id == proposal => failed = true,
                Ok(_) => {}
                Err(error) => return error,
            }
        }
    })
    .await?;
    assert!(
        matches!(error, ClientError::Transport("role already taken")),
        "unexpected error: {error:?}"
    );
    assert!(failed, "the proposal's outcome must come before the error");

    server.abort();
    Ok(())
}
