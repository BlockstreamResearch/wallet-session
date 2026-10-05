use std::{io, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::sleep,
};

use crate::{
    connection::{Connection, ConnectionError, NativeRelayTransportConfig, random_id},
    registry::{Registry, RegistryError},
    session::{PeerHandle, Registration},
};
use wallet_session_core::frame::{RelayFrame, RelayFrameBody};

pub async fn serve(
    listener: TcpListener,
    registry: Arc<Registry>,
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
                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle(stream, registry, config).await {
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

pub async fn handle(
    stream: TcpStream,
    registry: Arc<Registry>,
    config: NativeRelayTransportConfig,
) -> Result<(), ServerError> {
    let grace = config.session_grace;
    let (query, identity, websocket) = Connection::handshake(stream, config.clone()).await?;

    let topic = query.topic.clone();
    let role = query.role;
    let (tx, rx) = mpsc::unbounded_channel();
    let peer = PeerHandle {
        identity: identity.did.clone(),
        tx: tx.clone(),
    };

    let (session, registration, buffered) = registry.register(&topic, role, peer)?;

    // `RoleTaken` leaves the existing peer's slot intact, so only reserve/release
    // the slot when this connection actually took it.
    let holds_slot = !matches!(registration, Registration::RoleTaken(_));
    let result = Connection::new(query, identity, session, rx, tx, config)
        .run(websocket, registration, buffered)
        .await;

    if holds_slot {
        let _ = registry.disconnect(&topic, role, grace);

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
                    v: 1,
                    id,
                    topic: notify_topic,
                    body: RelayFrameBody::PeerDisconnected,
                };
                let _ = counterpart.tx.send(frame);
            }
        });
    }

    Ok(result?)
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),

    #[error(transparent)]
    Registry(#[from] RegistryError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::test_utils::{self, signing_key};
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use tokio::time::timeout;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
    use wallet_session_core::frame::{RelayFrame, RelayFrameBody};
    use wallet_session_core::message::Topic;

    const AUDIENCE: &str = "wss://relay.example.com";

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    type Client = WebSocketStream<MaybeTlsStream<TcpStream>>;

    fn token() -> String {
        let now = crate::auth::unix_now();
        test_utils::token(&signing_key(7), AUDIENCE, now, now + 3600)
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
        let mut query = format!("auth={}&role={role}&topic={topic}", token());
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
            v: 1,
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
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(serve(listener, Arc::new(Registry::new()), config));
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
            v: 1,
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
}
