use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval_at, sleep_until},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Bytes, Message, protocol::WebSocketConfig},
};
use wallet_session_core::{
    connection::{ConnectionQuery, Role},
    frame::RelayFrame,
    message::Topic,
};

use crate::{config::ClientConfig, error::Result, identity::IdentityKey, random};

/// Client-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Frames buffered between the transport task and the client.
pub(crate) const INBOX_CAPACITY: usize = 64;

/// Frames buffered between the client and the transport task.
pub(crate) const OUTBOUND_CAPACITY: usize = 64;

/// Maximum relay frame accepted from the relay, matching the relay default.
const MAX_RELAY_FRAME_BYTES: usize = 256 * 1024;

/// Maximum buffered WebSocket write bytes.
const MAX_WRITE_BUFFER_BYTES: usize = 2 * MAX_RELAY_FRAME_BYTES;

/// Everything the connection task can put on the wire.
pub(crate) enum Outbound {
    /// A relay frame to serialize and send.
    Frame(RelayFrame),
}

/// Everything a connection task reports to the client.
pub(crate) enum Inbox {
    /// A relay frame received from the relay.
    Frame(RelayFrame),

    /// The connection for `topic` is established (initial or after reconnect).
    Connected(Topic),

    /// The connection for `topic` was lost; a reconnect is starting.
    Disconnected(Topic),

    /// Reconnect attempts for `topic` were exhausted.
    Closed(Topic),

    /// The client no longer needs the pairing connection for `topic`.
    Retire(Topic),
}

/// A reconnecting relay connection for one topic and role.
///
/// A background task owns the WebSocket lifecycle and exposes a stable
/// outbound channel, so the client and reliability layer never observe a
/// socket swap. Inbound events go to the shared channel owned by the client.
pub(crate) struct Transport {
    outbound: mpsc::Sender<Outbound>,
    _task: JoinHandle<()>,
}

impl Transport {
    /// Start (asynchronously) a connection to the relay for `topic` as `role`.
    pub(crate) fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
        inbox: mpsc::Sender<Inbox>,
    ) -> Self {
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let _task = tokio::spawn(connection_task(
            config,
            identity,
            role,
            topic.clone(),
            outbound_rx,
            inbox,
        ));

        Self { outbound, _task }
    }

    /// Cloneable handle to the outbound writer.
    pub(crate) fn outbound(&self) -> mpsc::Sender<Outbound> {
        self.outbound.clone()
    }
}

async fn connection_task(
    config: ClientConfig,
    identity: IdentityKey,
    role: Role,
    topic: Topic,
    mut outbound: mpsc::Receiver<Outbound>,
    inbox: mpsc::Sender<Inbox>,
) {
    let mut delay = config.reconnect_initial_delay;
    let mut attempt = 0usize;

    loop {
        match connect_once(&config, &identity, role, &topic).await {
            Ok(stream) => {
                attempt = 0;
                delay = config.reconnect_initial_delay;
                let _ = inbox.send(Inbox::Connected(topic.clone())).await;

                if !run_connection(stream, &mut outbound, &inbox, &config).await {
                    return; // all senders dropped: shutting down
                }
                let _ = inbox.send(Inbox::Disconnected(topic.clone())).await;
            }
            Err(error) => {
                log::debug!("relay connect failed: {error}");
                let _ = inbox.send(Inbox::Disconnected(topic.clone())).await;
            }
        }

        attempt += 1;
        if attempt >= config.reconnect_max_attempts {
            log::warn!("relay reconnect attempts exhausted");
            let _ = inbox.send(Inbox::Closed(topic.clone())).await;
            return;
        }

        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(config.reconnect_max_delay);
    }
}

async fn connect_once(
    config: &ClientConfig,
    identity: &IdentityKey,
    role: Role,
    topic: &Topic,
) -> Result<RelayStream> {
    crate::tls::ensure_crypto_provider();

    let session_id = random::id()?.to_string();
    let token = identity.connection_token(&session_id, &config.audience, config.token_ttl)?;

    let query = ConnectionQuery {
        auth: token,
        role,
        topic: topic.clone(),
        registration_id: config.registration_id.clone(),
    };
    let query = serde_urlencoded::to_string(&query)?;

    let mut url = url::Url::parse(&config.relay_url)?;
    url.set_query(Some(&query));

    log::debug!("connecting to relay {url}");
    let (stream, _response) =
        connect_async_with_config(url.as_str(), Some(websocket_config()), false).await?;
    Ok(stream)
}

/// WebSocket limits that bound what a relay can make the client buffer.
fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_RELAY_FRAME_BYTES))
        .max_frame_size(Some(MAX_RELAY_FRAME_BYTES))
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
}

/// Drive one WebSocket session. Returns `true` to reconnect, `false` to stop.
async fn run_connection(
    stream: RelayStream,
    outbound: &mut mpsc::Receiver<Outbound>,
    inbox: &mpsc::Sender<Inbox>,
    config: &ClientConfig,
) -> bool {
    let (mut sink, mut source) = stream.split();

    let mut ping = interval_at(Instant::now() + config.ping_interval, config.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut awaiting_pong = false;
    let mut pong_deadline = Instant::now();

    loop {
        tokio::select! {
            outbound_item = outbound.recv() => match outbound_item {
                Some(Outbound::Frame(frame)) => {
                    let Ok(text) = serde_json::to_string(&frame) else {
                        return true;
                    };
                    log::trace!("client -> topic={} frame={text}", frame.topic);
                    if sink.send(Message::text(text)).await.is_err() {
                        return true;
                    }
                }
                None => return false,
            },
            message = source.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    match serde_json::from_str::<RelayFrame>(&text) {
                        Ok(frame) => {
                            log::trace!("client <- topic={} frame={text}", frame.topic);
                            if inbox.send(Inbox::Frame(frame)).await.is_err() {
                                return false;
                            }
                        }
                        Err(error) => log::warn!("invalid relay frame: {error}"),
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    let _ = sink.send(Message::Pong(payload)).await;
                }
                Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                Some(Ok(Message::Close(_))) => return true,
                Some(Ok(Message::Binary(_) | Message::Frame(_))) => {}
                Some(Err(error)) => {
                    log::debug!("relay read error: {error}");
                    return true;
                }
                None => return true,
            },
            _ = ping.tick(), if !awaiting_pong => {
                awaiting_pong = true;
                pong_deadline = Instant::now() + config.pong_timeout;
                if sink.send(Message::Ping(Bytes::new())).await.is_err() {
                    return true;
                }
            }
            _ = sleep_until(pong_deadline), if awaiting_pong => {
                log::debug!("relay pong timed out");
                return true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_limits_match_the_relay_default() {
        let config = websocket_config();
        assert_eq!(config.max_message_size, Some(MAX_RELAY_FRAME_BYTES));
        assert_eq!(config.max_frame_size, Some(MAX_RELAY_FRAME_BYTES));
        assert_eq!(config.max_write_buffer_size, MAX_WRITE_BUFFER_BYTES);
    }
}
