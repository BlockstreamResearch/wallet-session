use std::time::Duration;

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use tokio::{net::TcpStream, sync::mpsc, task::JoinHandle};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Bytes, Message},
};
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

/// Everything the writer task can put on the wire.
pub(crate) enum Outbound {
    /// A relay frame to serialize and send.
    Frame(RelayFrame),

    /// A WebSocket keepalive reply to a relay ping.
    Pong(Bytes),
}

/// A single relay connection for one topic and role.
///
/// Reads happen through `recv`; writes go through the `outbox` channel drained
/// by a writer task, so several producers (app, acks, retries) can send
/// concurrently with the read loop.
pub(crate) struct RelayClient {
    topic: Topic,
    idle_timeout: Duration,
    outbox: mpsc::UnboundedSender<Outbound>,
    source: SplitStream<RelayStream>,
    _writer: JoinHandle<()>,
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

        let (sink, source) = stream.split();
        let (outbox, outbound) = mpsc::unbounded_channel();
        let _writer = tokio::spawn(write_loop(sink, outbound));

        Ok(Self {
            topic: topic.clone(),
            idle_timeout: config.idle_timeout,
            outbox,
            source,
            _writer,
        })
    }

    /// Topic of this connection.
    pub(crate) fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Cloneable handle to the outbound writer.
    pub(crate) fn outbox(&self) -> mpsc::UnboundedSender<Outbound> {
        self.outbox.clone()
    }

    /// Await the next relay frame.
    pub(crate) async fn recv(&mut self) -> Result<RelayFrame> {
        loop {
            let message = match tokio::time::timeout(self.idle_timeout, self.source.next()).await {
                Ok(Some(message)) => message?,
                Ok(None) => return Err(ClientError::Closed),
                Err(_) => return Err(ClientError::Timeout),
            };

            match message {
                Message::Text(text) => {
                    log::trace!("client <- topic={} frame={}", self.topic, text);
                    return Ok(serde_json::from_str(&text)?);
                }
                Message::Close(_) => return Err(ClientError::Closed),
                Message::Ping(payload) => {
                    let _ = self.outbox.send(Outbound::Pong(payload));
                }
                Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }
}

async fn write_loop(mut sink: SplitSink<RelayStream, Message>, mut rx: mpsc::UnboundedReceiver<Outbound>) {
    while let Some(outbound) = rx.recv().await {
        let message = match outbound {
            Outbound::Frame(frame) => {
                let text = match serde_json::to_string(&frame) {
                    Ok(text) => text,
                    Err(_) => break,
                };
                log::trace!("client -> topic={} frame={text}", frame.topic);
                Message::text(text)
            }
            Outbound::Pong(payload) => Message::Pong(payload),
        };

        if sink.send(message).await.is_err() {
            break;
        }
    }
    let _ = sink.close().await;
}
