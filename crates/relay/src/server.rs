use std::{io, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::sleep,
};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};

use crate::{
    config::NativeRelayTransportConfig,
    connection::{Connection, ConnectionError, RELAY_FRAME_VERSION, RelayStream, random_id},
    limits::Limiter,
    registry::{Registry, RegistryError},
    session::{PeerHandle, Registration},
};
use wallet_session_core::frame::{RelayFrame, RelayFrameBody};

/// Serve relay connections until the listener fails.
pub async fn serve(
    listener: TcpListener,
    registry: Arc<Registry>,
    limiter: Arc<Limiter>,
    config: NativeRelayTransportConfig,
) -> io::Result<()> {
    match listener.local_addr() {
        Ok(addr) => log::info!("relay listening on {addr}"),
        Err(error) => log::warn!("relay listening address unavailable: {error}"),
    }

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                log::debug!("accepted connection from {addr}");

                let registry = Arc::clone(&registry);
                let limiter = Arc::clone(&limiter);
                let config = config.clone();

                tokio::spawn(async move {
                    if let Err(error) = handle(stream, registry, limiter, config).await {
                        log::debug!("relay connection ended with error: {error}");
                    }
                });
            }
            Err(error) => {
                log::error!("relay accept failed: {error}");
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Handle one accepted connection, enforcing connection and session limits.
pub async fn handle(
    stream: TcpStream,
    registry: Arc<Registry>,
    limiter: Arc<Limiter>,
    config: NativeRelayTransportConfig,
) -> Result<(), ServerError> {
    let Some(_total) = limiter.acquire_total() else {
        log::warn!("relay connection limit reached; dropping new connection");
        return Err(ServerError::ConnectionLimit);
    };

    let grace = config.session_grace;
    let (query, identity, mut websocket) = Connection::handshake(stream, config.clone()).await?;

    if !limiter.allow_connect(&identity.did) {
        log::warn!("connect rate limit exceeded for {}", identity.did);
        close_with(&mut websocket, "connection rate limit").await;

        return Err(ServerError::RateLimited);
    }

    let Some(_identity_slot) = limiter.acquire_identity(&identity.did) else {
        log::warn!("connection limit reached for {}", identity.did);
        close_with(&mut websocket, "connection limit").await;

        return Err(ServerError::ConnectionLimit);
    };

    let topic = query.topic.clone();
    let role = query.role;

    let (tx, rx) = mpsc::channel(config.outbound_queue_capacity);
    let weak_tx = tx.downgrade();
    let peer = PeerHandle {
        identity: identity.did.clone(),
        tx: tx.clone(),
    };

    let ready = RelayFrame {
        v: RELAY_FRAME_VERSION,
        id: random_id()?,
        topic: topic.clone(),
        body: RelayFrameBody::SessionReady,
    };
    let (session, registration) =
        match registry.register(&topic, role, peer, &ready, limiter.max_sessions()) {
            Ok(registered) => registered,
            Err(error) => {
                close_with(&mut websocket, "session limit").await;
                return Err(error.into());
            }
        };

    let holds_slot = !matches!(registration, Registration::RoleTaken(_));
    let result = Connection::new(
        query,
        identity,
        session,
        rx,
        tx,
        config,
        Arc::clone(&limiter),
    )
    .run(websocket, registration)
    .await;

    if holds_slot
        && registry
            .disconnect(&topic, role, &weak_tx, grace)
            .unwrap_or(false)
    {
        // After the grace window, expire the reservation and tell the
        // counterpart its peer is gone.
        let registry = Arc::clone(&registry);
        let notify_topic = topic.clone();
        tokio::spawn(async move {
            sleep(grace).await;
            if let Ok(Some(counterpart)) = registry.expire(&notify_topic, role) {
                let Ok(id) = random_id() else {
                    return;
                };
                let frame = RelayFrame {
                    v: RELAY_FRAME_VERSION,
                    id,
                    topic: notify_topic,
                    body: RelayFrameBody::PeerDisconnected,
                };
                if counterpart.tx.try_send(frame).is_err() {
                    log::warn!("dropping peer_disconnected: outbound queue unavailable");
                }
            }
        });
    }

    Ok(result?)
}

/// Close the WebSocket with a policy close frame.
async fn close_with(websocket: &mut RelayStream, reason: &str) {
    let frame = CloseFrame {
        code: CloseCode::Policy,
        reason: reason.into(),
    };
    let _ = websocket.close(Some(frame)).await;
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),

    #[error(transparent)]
    Registry(#[from] RegistryError),

    #[error("relay connection limit reached")]
    ConnectionLimit,

    #[error("relay connection rate limit exceeded")]
    RateLimited,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_utils::{self, signing_key};
    use crate::limits::{Limiter, RateLimit, RelayLimitsConfig};
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use tokio::time::timeout;
    use tokio_tungstenite::{
        MaybeTlsStream, WebSocketStream, connect_async,
        tungstenite::{Bytes, Message},
    };
    use wallet_session_core::frame::{RelayFrame, RelayFrameBody};
    use wallet_session_core::message::Topic;

    const AUDIENCE: &str = "wss://relay.example.com";

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

    fn limiter() -> Arc<Limiter> {
        Arc::new(Limiter::new(RelayLimitsConfig::default()))
    }

    fn token_with(seed: u8) -> String {
        let now = crate::auth::unix_now();
        test_utils::token(&signing_key(seed), AUDIENCE, now, now + 300)
    }

    fn token() -> String {
        token_with(7)
    }

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([9u8; 32])
    }

    async fn connect(
        addr: SocketAddr,
        role: &str,
        topic: &Topic,
        registration_id: Option<&str>,
    ) -> Result<Client, Box<dyn std::error::Error>> {
        connect_auth(addr, &token(), role, topic, registration_id).await
    }

    async fn connect_auth(
        addr: SocketAddr,
        auth: &str,
        role: &str,
        topic: &Topic,
        registration_id: Option<&str>,
    ) -> Result<Client, Box<dyn std::error::Error>> {
        let mut query = format!("auth={auth}&role={role}&topic={topic}");
        if let Some(registration_id) = registration_id {
            query.push_str(&format!("&registrationId={registration_id}"));
        }
        let (client, _response) = connect_async(format!("ws://{addr}/?{query}")).await?;
        Ok(client)
    }

    async fn read_frame(client: &mut Client) -> Result<RelayFrame, Box<dyn std::error::Error>> {
        loop {
            let message = timeout(Duration::from_secs(5), client.next())
                .await?
                .ok_or("websocket closed")??;

            match message {
                Message::Text(text) => return Ok(serde_json::from_str(&text)?),
                Message::Ping(payload) => {
                    client.send(Message::Pong(payload)).await?;
                }
                Message::Close(_) => return Err("websocket closed".into()),
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    #[tokio::test]
    async fn two_peers_get_session_ready_and_route() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve(
            listener,
            Arc::new(Registry::new()),
            limiter(),
            NativeRelayTransportConfig::new(AUDIENCE),
        ));

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;

        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let message = RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "m1".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: "hello".to_owned(),
            },
        };
        proposer
            .send(Message::text(serde_json::to_string(&message)?))
            .await?;

        let delivered = read_frame(&mut responder).await?;
        assert!(matches!(
            delivered.body,
            RelayFrameBody::Message { payload } if payload == "hello"
        ));
        Ok(())
    }

    async fn try_responder(addr: SocketAddr, topic: &Topic) -> bool {
        let Ok(mut client) = connect(addr, "responder", topic, None).await else {
            return false;
        };
        let Ok(Ok(frame)) = timeout(Duration::from_secs(1), read_frame(&mut client)).await else {
            return false;
        };
        matches!(frame.body, RelayFrameBody::SessionReady)
    }

    #[tokio::test]
    async fn responder_slot_is_released_after_disconnect() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve(
            listener,
            Arc::new(Registry::new()),
            limiter(),
            NativeRelayTransportConfig::new(AUDIENCE),
        ));

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;

        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // Disconnect the responder; the relay must free its role slot.
        drop(responder);

        // fresh connection for the same role/topic must eventually be accepted
        // and receive session_ready. Retry to allow the relay to observe the
        // disconnect.
        let mut reconnected = false;
        for _ in 0..100 {
            if try_responder(addr, &topic).await {
                reconnected = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(
            reconnected,
            "responder role slot was not released after disconnect"
        );
        Ok(())
    }

    #[tokio::test]
    async fn invalid_params_are_rejected() -> TestResult {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve(
            listener,
            Arc::new(Registry::new()),
            limiter(),
            NativeRelayTransportConfig::new(AUDIENCE),
        ));

        // No auth/role/topic query parameters.
        let outcome = connect_async(format!("ws://{addr}/")).await;
        assert!(outcome.is_err());
        Ok(())
    }

    async fn serve_with(
        config: NativeRelayTransportConfig,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        serve_with_limits(config, RelayLimitsConfig::default()).await
    }

    async fn serve_with_limits(
        config: NativeRelayTransportConfig,
        limits: RelayLimitsConfig,
    ) -> Result<SocketAddr, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve(
            listener,
            Arc::new(Registry::new()),
            Arc::new(Limiter::new(limits)),
            config,
        ));
        Ok(addr)
    }

    #[tokio::test]
    async fn counterpart_is_notified_after_grace_expires() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_millis(200)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);

        let notified = read_frame(&mut proposer).await?;
        assert!(
            matches!(notified.body, RelayFrameBody::PeerDisconnected),
            "expected PeerDisconnected, got {:?}",
            notified.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn buffered_frames_redelivered_on_reconnect() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(1)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        // Give the relay a moment to observe the disconnect and reserve the slot.
        sleep(Duration::from_millis(100)).await;

        let message = RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "buffered".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: "queued".to_owned(),
            },
        };
        proposer
            .send(Message::text(serde_json::to_string(&message)?))
            .await?;

        // same identity reconnects within grace and receives the buffer after session_ready.
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));
        let redelivered = read_frame(&mut responder).await?;
        assert!(
            matches!(redelivered.body, RelayFrameBody::Message { ref payload } if payload == "queued"),
            "expected buffered message, got {:?}",
            redelivered.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn idle_peer_is_dropped_and_counterpart_notified() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_ping_interval(Duration::from_millis(100))
                .with_idle_timeout(Duration::from_millis(300))
                .with_session_grace(Duration::from_millis(100)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        // keep the responder object alive but never poll it, so it stops answering keepalive pings
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // proposer keeps answering pings while awaiting the notification.
        let notified = read_frame(&mut proposer).await?;
        assert!(
            matches!(notified.body, RelayFrameBody::PeerDisconnected),
            "expected PeerDisconnected after idle timeout, got {:?}",
            notified.body
        );
        Ok(())
    }

    /// Connect and report whether the relay completes registration with
    /// `session_ready` within a short window. Rejected connections (role taken,
    /// reserved slot) close instead, yielding `false`.
    async fn try_connect(
        addr: SocketAddr,
        auth: &str,
        role: &str,
        topic: &Topic,
        registration_id: Option<&str>,
    ) -> bool {
        let Ok(mut client) = connect_auth(addr, auth, role, topic, registration_id).await else {
            return false;
        };
        matches!(
            timeout(Duration::from_secs(1), read_frame(&mut client)).await,
            Ok(Ok(RelayFrame {
                body: RelayFrameBody::SessionReady,
                ..
            }))
        )
    }

    /// Drain a client until the relay closes it (or the connection errors).
    async fn expect_closed(client: &mut Client) -> bool {
        loop {
            match timeout(Duration::from_secs(2), client.next()).await {
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => return true,
                Ok(Some(Ok(_))) => {}
                Err(_) => return false,
            }
        }
    }

    fn message(topic: &Topic, id: &str, payload: &str) -> RelayFrame {
        RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: id.to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: payload.to_owned(),
            },
        }
    }

    async fn send(client: &mut Client, frame: &RelayFrame) -> TestResult {
        client
            .send(Message::text(serde_json::to_string(frame)?))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn buffered_frames_are_capped_dropping_oldest() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_secs(2))
                .with_session_buffer_max_messages(2),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;

        // Three frames while the responder is gone, but only two may be kept.
        for (id, payload) in [("m1", "one"), ("m2", "two"), ("m3", "three")] {
            send(&mut proposer, &message(&topic, id, payload)).await?;
        }

        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let mut delivered = Vec::new();
        for _ in 0..2 {
            let frame = read_frame(&mut responder).await?;
            assert!(
                matches!(frame.body, RelayFrameBody::Message { .. }),
                "expected buffered message, got {:?}",
                frame.body
            );
            if let RelayFrameBody::Message { payload } = frame.body {
                delivered.push(payload);
            }
        }
        assert_eq!(delivered, vec!["two".to_owned(), "three".to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn buffering_disabled_drops_frames_while_disconnected() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_secs(2))
                .with_session_buffer_max_messages(0),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;
        send(&mut proposer, &message(&topic, "lost", "dropped")).await?;

        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // Nothing is buffered, so no message follows session_ready.
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut responder))
                .await
                .is_err(),
            "no frame should be buffered when buffering is disabled"
        );
        Ok(())
    }

    #[tokio::test]
    async fn frames_sent_before_counterpart_arrives_are_dropped() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(2)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        // No counterpart yet: this frame has nowhere to go and is dropped, not
        // buffered for a peer that has never connected.
        send(&mut proposer, &message(&topic, "early", "too-soon")).await?;

        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut responder))
                .await
                .is_err(),
            "a frame sent before the peer connected must not be delivered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reconnect_ack_burst_survives_the_inbound_rate_limit() -> TestResult {
        const BACKLOG: usize = 45;
        const BURST: usize = 8;

        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(5)),
            RelayLimitsConfig {
                inbound_message_rate: RateLimit {
                    burst: BURST as u32,
                    interval: Duration::from_millis(200),
                },
                ..RelayLimitsConfig::default()
            },
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;
        for i in 0..BACKLOG {
            if i >= BURST {
                sleep(Duration::from_millis(35)).await;
            }
            send(&mut proposer, &message(&topic, &format!("m{i}"), "queued")).await?;
        }

        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));
        for i in 0..BACKLOG {
            let frame = timeout(Duration::from_millis(500), read_frame(&mut responder)).await??;
            assert!(
                matches!(frame.body, RelayFrameBody::Message { .. }),
                "expected redelivered frame {i}, got {:?}",
                frame.body
            );
        }

        for i in 0..BACKLOG {
            send(&mut responder, &message(&topic, &format!("ack{i}"), "ack")).await?;
        }

        let mut delivered = 0;
        while delivered < BACKLOG {
            match timeout(Duration::from_millis(500), read_frame(&mut proposer)).await {
                Ok(Ok(frame)) => {
                    if matches!(frame.body, RelayFrameBody::Message { .. }) {
                        delivered += 1;
                    }
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => break,
            }
        }
        assert_eq!(
            delivered, BACKLOG,
            "the relay dropped acknowledgements from a reconnect burst"
        );

        assert!(
            timeout(Duration::from_millis(500), expect_closed(&mut responder))
                .await
                .is_err(),
            "the relay disconnected a peer for acknowledging its own redelivery"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reconnect_within_grace_suppresses_peer_disconnected() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(2)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;

        // Reconnect as the same identity well inside the grace window.
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // The proposer sees the peer come back, not a spurious disconnect.
        let observed = read_frame(&mut proposer).await?;
        assert!(
            matches!(observed.body, RelayFrameBody::SessionReady),
            "expected a fresh session_ready, got {:?}",
            observed.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn same_identity_reconnects_while_old_connection_is_still_open() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_millis(300)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        // The old responder stays open and unpolled, like a half-open socket
        // the relay has not yet noticed is dead.
        let mut old = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut old).await?.body,
            RelayFrameBody::SessionReady
        ));

        let mut new = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut new).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));

        // The replaced connection is closed by the relay.
        assert!(
            expect_closed(&mut old).await,
            "the replaced connection should be closed"
        );

        // Wait past the grace window: the old connection's teardown must not
        // have reserved or expired the new connection's slot.
        sleep(Duration::from_millis(600)).await;

        send(&mut proposer, &message(&topic, "after", "to-new")).await?;
        let routed = read_frame(&mut new).await?;
        assert!(
            matches!(routed.body, RelayFrameBody::Message { ref payload } if payload == "to-new"),
            "expected routing to the new connection, got {:?}",
            routed.body
        );

        send(&mut new, &message(&topic, "back", "to-proposer")).await?;
        let routed = read_frame(&mut proposer).await?;
        assert!(
            matches!(
                routed.body,
                RelayFrameBody::Message { ref payload } if payload == "to-proposer"
            ),
            "expected no peer_disconnected, got {:?}",
            routed.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn different_identity_cannot_replace_live_connection() -> TestResult {
        let addr = serve_with(NativeRelayTransportConfig::new(AUDIENCE)).await?;

        let topic = topic()?;
        let mut proposer =
            connect_auth(addr, &token_with(1), "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect_auth(addr, &token_with(2), "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let mut impostor = connect_auth(addr, &token_with(3), "responder", &topic, None).await?;
        assert!(
            expect_closed(&mut impostor).await,
            "a different identity must not take over a live slot"
        );

        // The owner is unaffected.
        send(&mut proposer, &message(&topic, "keep", "alive")).await?;
        let routed = read_frame(&mut responder).await?;
        assert!(
            matches!(routed.body, RelayFrameBody::Message { ref payload } if payload == "alive"),
            "expected the owner to keep receiving, got {:?}",
            routed.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_role_connection_is_closed() -> TestResult {
        let addr = serve_with(NativeRelayTransportConfig::new(AUDIENCE)).await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // A second proposer with a different identity must be refused.
        let mut second =
            connect_auth(addr, &token_with(8), "proposer", &topic, Some("reg-2")).await?;
        assert!(
            expect_closed(&mut second).await,
            "second connection for an occupied role should be closed"
        );

        // The original proposer is unaffected and still routes.
        send(&mut proposer, &message(&topic, "keep", "alive")).await?;
        let routed = read_frame(&mut responder).await?;
        assert!(
            matches!(routed.body, RelayFrameBody::Message { ref payload } if payload == "alive"),
            "expected the original session to keep routing, got {:?}",
            routed.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn client_sent_session_ready_is_rejected() -> TestResult {
        let addr = serve_with(NativeRelayTransportConfig::new(AUDIENCE)).await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // Clients must not forge the relay-only session_ready frame.
        let rogue = RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "rogue".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::SessionReady,
        };
        send(&mut proposer, &rogue).await?;
        assert!(
            expect_closed(&mut proposer).await,
            "a client sending session_ready should be disconnected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn different_identity_cannot_reclaim_slot_within_grace() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_millis(500)),
        )
        .await?;

        let topic = topic()?;
        let proposer_auth = token_with(1);
        let responder_auth = token_with(2);
        let other_auth = token_with(3);

        let mut proposer =
            connect_auth(addr, &proposer_auth, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect_auth(addr, &responder_auth, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;

        // A different identity cannot hijack the reserved slot.
        assert!(
            !try_connect(addr, &other_auth, "responder", &topic, None).await,
            "a different identity must not reclaim a reserved slot within grace"
        );

        // Once grace expires the slot frees up for anyone.
        sleep(Duration::from_millis(700)).await;
        assert!(
            try_connect(addr, &other_auth, "responder", &topic, None).await,
            "slot should be claimable after the grace window expires"
        );
        Ok(())
    }

    #[tokio::test]
    async fn client_sent_peer_disconnected_is_rejected() -> TestResult {
        let addr = serve_with(NativeRelayTransportConfig::new(AUDIENCE)).await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let forged = RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "forged".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::PeerDisconnected,
        };
        send(&mut responder, &forged).await?;
        assert!(
            expect_closed(&mut responder).await,
            "clients may not send peer_disconnected"
        );

        // The counterpart must not be told its peer is gone, and the session
        // keeps running for whoever is left.
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut proposer))
                .await
                .is_err(),
            "a forged peer_disconnected must not reach the counterpart"
        );
        Ok(())
    }

    #[tokio::test]
    async fn binary_frame_closes_connection() -> TestResult {
        let addr = serve_with(NativeRelayTransportConfig::new(AUDIENCE)).await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        proposer.send(Message::Binary(vec![0u8; 8].into())).await?;
        assert!(
            expect_closed(&mut proposer).await,
            "binary frames are not part of the relay protocol"
        );
        Ok(())
    }

    #[tokio::test]
    async fn frame_topic_mismatch_closes_connection() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(2)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let other = Topic::new([8u8; 32])?;
        send(&mut proposer, &message(&other, "rogue", "cross-topic")).await?;
        assert!(
            expect_closed(&mut proposer).await,
            "a frame stamped with another topic should close the connection"
        );
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut responder))
                .await
                .is_err(),
            "the mismatched frame must not be delivered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_frame_version_closes_connection() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_session_grace(Duration::from_secs(2)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        let rogue = RelayFrame {
            v: 2,
            id: "rogue".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: "future".to_owned(),
            },
        };
        send(&mut proposer, &rogue).await?;
        assert!(
            expect_closed(&mut proposer).await,
            "an unsupported frame version should close the connection"
        );
        Ok(())
    }

    #[tokio::test]
    async fn per_identity_connection_limit_is_enforced() -> TestResult {
        let limits = RelayLimitsConfig {
            max_connections_per_identity: 1,
            ..RelayLimitsConfig::default()
        };
        let addr = serve_with_limits(NativeRelayTransportConfig::new(AUDIENCE), limits).await?;

        let topic = topic()?;
        let mut first = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut first))
                .await
                .is_err(),
            "first connection should stay open while waiting for a counterpart"
        );

        let mut second = connect(addr, "responder", &topic, None).await?;
        assert!(
            expect_closed(&mut second).await,
            "a second connection for the same identity should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn connect_rate_limit_is_enforced() -> TestResult {
        let limits = RelayLimitsConfig {
            connect_rate: RateLimit {
                burst: 1,
                interval: Duration::from_secs(60),
            },
            max_connections_per_identity: 100,
            ..RelayLimitsConfig::default()
        };
        let addr = serve_with_limits(NativeRelayTransportConfig::new(AUDIENCE), limits).await?;

        let topic = topic()?;
        let mut first = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut first))
                .await
                .is_err(),
            "first connection should stay open while waiting for a counterpart"
        );

        let mut second = connect(addr, "responder", &topic, None).await?;
        assert!(
            expect_closed(&mut second).await,
            "a connection above the connect rate should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn session_limit_is_enforced() -> TestResult {
        let limits = RelayLimitsConfig {
            max_sessions: 1,
            ..RelayLimitsConfig::default()
        };
        let addr = serve_with_limits(NativeRelayTransportConfig::new(AUDIENCE), limits).await?;

        let first_topic = Topic::new([6u8; 32])?;
        let mut first = connect(addr, "proposer", &first_topic, Some("reg-1")).await?;
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut first))
                .await
                .is_err(),
            "first session should stay open while waiting for a counterpart"
        );

        let second_topic = Topic::new([7u8; 32])?;
        let mut second = connect(addr, "responder", &second_topic, None).await?;
        assert!(
            expect_closed(&mut second).await,
            "a session above the session cap should be rejected"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pong_timeout_drops_peer_and_allows_reconnect() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_ping_interval(Duration::from_millis(100))
                .with_pong_timeout(Duration::from_millis(200))
                .with_idle_timeout(Duration::from_secs(30))
                .with_session_grace(Duration::from_millis(100)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        // Keep the responder object alive but never poll it, so it never answers pings.
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        // The proposer keeps answering pings while waiting for the liveness verdict.
        let notified = read_frame(&mut proposer).await?;
        assert!(
            matches!(notified.body, RelayFrameBody::PeerDisconnected),
            "expected PeerDisconnected after pong timeout, got {:?}",
            notified.body
        );

        // The reserved slot is released, so the same identity can reconnect.
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));
        Ok(())
    }

    #[tokio::test]
    async fn buffered_frames_expire_after_ttl() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_secs(5))
                .with_session_buffer_ttl(Duration::from_millis(200)),
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, Some("reg-1")).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut proposer).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));

        drop(responder);
        sleep(Duration::from_millis(100)).await;
        send(&mut proposer, &message(&topic, "stale", "old")).await?;
        // Wait past the per-frame TTL but still inside the grace window.
        sleep(Duration::from_millis(300)).await;

        let mut responder = connect(addr, "responder", &topic, None).await?;
        assert!(matches!(
            read_frame(&mut responder).await?.body,
            RelayFrameBody::SessionReady
        ));
        assert!(
            timeout(Duration::from_millis(300), read_frame(&mut responder))
                .await
                .is_err(),
            "expired buffered frame must not be redelivered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stalled_reader_is_dropped_by_write_deadline() -> TestResult {
        // Inbound limits would stop the flood needed to fill the socket buffers.
        let unlimited = RateLimit {
            burst: u32::MAX,
            interval: Duration::from_secs(1),
        };
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_max_incoming_frame_bytes(1024 * 1024)
                .with_write_timeout(Duration::from_millis(300))
                .with_session_grace(Duration::from_millis(300)),
            RelayLimitsConfig {
                inbound_message_rate: unlimited,
                inbound_byte_rate: unlimited,
                global_inbound_byte_rate: unlimited,
                ..RelayLimitsConfig::default()
            },
        )
        .await?;

        let topic = topic()?;
        let mut proposer = connect(addr, "proposer", &topic, None).await?;
        let mut responder = connect(addr, "responder", &topic, None).await?;
        read_frame(&mut proposer).await?;
        read_frame(&mut responder).await?;

        let payload = "a".repeat(900 * 1024);
        let flood_until = tokio::time::Instant::now() + Duration::from_secs(4);
        let mut sent = 0;
        while tokio::time::Instant::now() < flood_until {
            let frame = message(&topic, &format!("m{sent}"), &payload);
            let send = proposer.send(Message::text(serde_json::to_string(&frame)?));
            if let Ok(Ok(())) = timeout(Duration::from_millis(500), send).await {
                sent += 1;
            }
        }

        let mut released = false;
        for _ in 0..20 {
            if let Ok(mut client) = connect(addr, "responder", &topic, None).await
                && !matches!(
                    timeout(Duration::from_secs(1), client.next()).await,
                    Ok(Some(Ok(Message::Close(_))))
                )
            {
                released = true;
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }
        drop(responder);
        assert!(released, "stalled responder kept its slot");
        Ok(())
    }

    fn tight_inbound_limits() -> RelayLimitsConfig {
        RelayLimitsConfig {
            inbound_message_rate: RateLimit {
                burst: 3,
                interval: Duration::from_secs(3600),
            },
            ..RelayLimitsConfig::default()
        }
    }

    async fn ready_pair(
        addr: SocketAddr,
        topic: &Topic,
    ) -> Result<(Client, Client), Box<dyn std::error::Error>> {
        let mut proposer = connect(addr, "proposer", topic, None).await?;
        let mut responder = connect(addr, "responder", topic, None).await?;
        read_frame(&mut proposer).await?;
        read_frame(&mut responder).await?;
        Ok((proposer, responder))
    }

    #[tokio::test]
    async fn inbound_message_rate_limit_drops_excess_frames() -> TestResult {
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE),
            tight_inbound_limits(),
        )
        .await?;
        let topic = topic()?;
        let (mut proposer, mut responder) = ready_pair(addr, &topic).await?;

        for i in 0..6 {
            send(&mut proposer, &message(&topic, &format!("m{i}"), "x")).await?;
        }

        let mut delivered = Vec::new();
        while let Ok(Ok(frame)) =
            timeout(Duration::from_millis(500), read_frame(&mut responder)).await
        {
            delivered.push(frame.id);
        }
        assert_eq!(delivered, ["m0", "m1", "m2"]);
        Ok(())
    }

    #[tokio::test]
    async fn inbound_byte_rate_limit_drops_oversized_burst() -> TestResult {
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE),
            RelayLimitsConfig {
                inbound_byte_rate: RateLimit {
                    burst: 4096,
                    interval: Duration::from_secs(3600),
                },
                ..RelayLimitsConfig::default()
            },
        )
        .await?;
        let topic = topic()?;
        let (mut proposer, mut responder) = ready_pair(addr, &topic).await?;

        let payload = "a".repeat(1500);
        for i in 0..4 {
            send(&mut proposer, &message(&topic, &format!("m{i}"), &payload)).await?;
        }

        let mut delivered = 0;
        while let Ok(Ok(_)) = timeout(Duration::from_millis(500), read_frame(&mut responder)).await
        {
            delivered += 1;
        }
        assert_eq!(delivered, 2, "4096 byte burst fits two ~1.6 KB frames");
        Ok(())
    }

    #[tokio::test]
    async fn global_inbound_byte_budget_is_shared_across_sessions() -> TestResult {
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE),
            RelayLimitsConfig {
                global_inbound_byte_rate: RateLimit {
                    burst: 1200,
                    interval: Duration::from_secs(3600),
                },
                ..RelayLimitsConfig::default()
            },
        )
        .await?;

        let payload = "a".repeat(300);
        let mut delivered = 0;
        // Each session stays well inside its own per-connection limits.
        for n in 0..4u8 {
            let topic = Topic::new([40 + n; 32])?;
            let (mut proposer, mut responder) = ready_pair(addr, &topic).await?;
            send(&mut proposer, &message(&topic, "m", &payload)).await?;
            if timeout(Duration::from_millis(500), read_frame(&mut responder))
                .await
                .is_ok_and(|frame| frame.is_ok())
            {
                delivered += 1;
            }
        }
        assert!(
            (1..4).contains(&delivered),
            "shared budget should admit some but not all, got {delivered}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sustained_rate_limit_violations_disconnect_peer() -> TestResult {
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE),
            tight_inbound_limits(),
        )
        .await?;
        let topic = topic()?;
        let (mut proposer, _responder) = ready_pair(addr, &topic).await?;

        for i in 0..64 {
            if send(&mut proposer, &message(&topic, &format!("m{i}"), "x"))
                .await
                .is_err()
            {
                break;
            }
        }
        assert!(expect_closed(&mut proposer).await);
        Ok(())
    }

    #[tokio::test]
    async fn control_frame_flood_is_charged_and_disconnects_peer() -> TestResult {
        let addr = serve_with_limits(
            NativeRelayTransportConfig::new(AUDIENCE)
                .with_session_grace(Duration::from_millis(300)),
            tight_inbound_limits(),
        )
        .await?;
        let topic = topic()?;
        let (mut proposer, mut responder) = ready_pair(addr, &topic).await?;

        // Pings are not data, but they are charged to the same budget, so a
        // peer cannot use them as unlimited keepalive traffic.
        for _ in 0..64 {
            if proposer.send(Message::Ping(Bytes::new())).await.is_err() {
                break;
            }
        }

        // The verdict is observed on the quiet counterpart: the relay drops the
        // flooder, and tells its peer once the grace window has passed.
        let notified = read_frame(&mut responder).await?;
        assert!(
            matches!(notified.body, RelayFrameBody::PeerDisconnected),
            "expected PeerDisconnected after a control-frame flood, got {:?}",
            notified.body
        );
        Ok(())
    }

    #[tokio::test]
    async fn frame_over_incoming_size_cap_closes_connection() -> TestResult {
        let addr = serve_with(
            NativeRelayTransportConfig::new(AUDIENCE).with_max_incoming_frame_bytes(2048),
        )
        .await?;
        let topic = topic()?;
        let (mut proposer, _responder) = ready_pair(addr, &topic).await?;

        let _ = send(&mut proposer, &message(&topic, "big", &"a".repeat(4096))).await;
        assert!(expect_closed(&mut proposer).await);
        Ok(())
    }
}
