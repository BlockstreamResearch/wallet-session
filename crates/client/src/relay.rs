use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use wallet_session_core::{
    connection::{ConnectionQuery, Role},
    frame::RelayFrame,
    message::Topic,
};

use crate::{
    config::ClientConfig,
    error::{ClientError, Result},
    identity::IdentityKey,
    random,
};

/// Client-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A single relay connection for one topic and role.
pub(crate) struct RelayClient {
    stream: RelayStream,
    topic: Topic,
}

impl RelayClient {
    /// Connect and authenticate to the relay for `topic` as `role`.
    pub(crate) async fn connect(
        config: &ClientConfig,
        identity: &IdentityKey,
        role: Role,
        topic: &Topic,
    ) -> Result<Self> {
        let session_id = random::id()?;
        let token = identity.connection_token(&session_id, &config.audience, config.token_ttl)?;

        let registration_id = if role == Role::Proposer {
            Some(
                config
                    .registration_id
                    .clone()
                    .ok_or(ClientError::MissingRegistrationId)?,
            )
        } else {
            None
        };
        let query = ConnectionQuery {
            auth: token,
            role,
            topic: topic.clone(),
            registration_id,
        };
        let query = serde_urlencoded::to_string(&query)?;

        let mut url = url::Url::parse(&config.relay_url)?;
        url.set_query(Some(&query));

        log::debug!("connecting to relay {url}");
        let (stream, _response) = connect_async(url.as_str()).await?;

        Ok(Self {
            stream,
            topic: topic.clone(),
        })
    }

    /// Topic of this connection.
    pub(crate) fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Send a frame to the relay
    pub(crate) async fn send(&mut self, frame: RelayFrame) -> Result<()> {
        let text = serde_json::to_string(&frame)?;
        log::trace!("client -> topic={} frame={text}", frame.topic);
        self.stream.send(Message::text(text)).await?;
        Ok(())
    }

    /// Await the next relay frame
    pub(crate) async fn recv(&mut self) -> Result<RelayFrame> {
        loop {
            let message = self.stream.next().await.ok_or(ClientError::Closed)??;
            match message {
                Message::Text(text) => {
                    log::trace!("client <- topic={} frame={}", self.topic, text);
                    return Ok(serde_json::from_str(&text)?);
                }
                Message::Close(_) => return Err(ClientError::Closed),
                Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                    continue;
                }
            }
        }
    }
}
