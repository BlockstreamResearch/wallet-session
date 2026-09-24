use std::{io, sync::Arc, time::Duration};

use thiserror::Error;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::sleep,
};

use crate::{
    connection::{Connection, ConnectionError, NativeRelayTransportConfig},
    registry::{Registry, RegistryError},
    session::{PeerHandle, Registration},
};

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
    let (params, websocket) = Connection::handshake(stream, config).await?;

    let topic = params.topic.clone();
    let role = params.role;
    let (tx, rx) = mpsc::unbounded_channel();
    let peer = PeerHandle {
        identity: params.identity.did.clone(),
        tx: tx.clone(),
    };

    let (session, registration) = registry.register(&topic, role, peer)?;

    // `RoleTaken` leaves the existing peer's slot intact, so only release the
    // slot when this connection actually took it.
    let holds_slot = !matches!(registration, Registration::RoleTaken(_));
    let result = Connection::new(params, session, rx, tx)
        .run(websocket, registration)
        .await;

    if holds_slot {
        let _ = registry.release(&topic, role);
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
    use crate::frame::{RelayFrame, RelayFrameBody};
    use futures_util::{SinkExt, StreamExt};
    use std::net::SocketAddr;
    use tokio::time::timeout;
    use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
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
        let message = timeout(Duration::from_secs(5), client.next())
            .await?
            .ok_or("websocket closed")??;

        match message {
            Message::Text(text) => Ok(serde_json::from_str(&text)?),
            other => Err(format!("unexpected message: {other:?}").into()),
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
}
