use futures_util::{SinkExt, StreamExt};
use tokio::{
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval_at, sleep_until},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Bytes, Message},
};
use wallet_session_core::{
    connection::{ConnectionQuery, Role},
    frame::RelayFrame,
    message::Topic,
};

use crate::{config::ClientConfig, error::Result, identity::IdentityKey, random};

/// Client-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Everything the connection task can put on the wire.
pub(crate) enum Outbound {
    /// A relay frame to serialize and send.
    Frame(RelayFrame),
}

/// Everything the connection task reports to the client.
pub(crate) enum Inbox {
    /// A relay frame received from the relay.
    Frame(RelayFrame),

    /// The connection is established (initial or after reconnect).
    Connected,

    /// The connection was lost; a reconnect is starting.
    Disconnected,

    /// Reconnect attempts were exhausted.
    Closed,
}

/// A reconnecting relay connection for one topic and role.
///
/// A background task owns the WebSocket lifecycle and exposes stable inbound
/// and outbound channels, so the client and reliability layer never observe a
/// socket swap.
pub(crate) struct Transport {
    topic: Topic,
    outbound: mpsc::UnboundedSender<Outbound>,
    inbox: mpsc::UnboundedReceiver<Inbox>,
    _task: JoinHandle<()>,
}

impl Transport {
    /// Start (asynchronously) a connection to the relay for `topic` as `role`.
    pub(crate) fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
    ) -> Self {
        let (outbound, outbound_rx) = mpsc::unbounded_channel();
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let _task = tokio::spawn(connection_task(
            config,
            identity,
            role,
            topic.clone(),
            outbound_rx,
            inbox_tx,
        ));

        Self {
            topic,
            outbound,
            inbox,
            _task,
        }
    }

    /// Topic of this connection.
    pub(crate) fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Cloneable handle to the outbound writer.
    pub(crate) fn outbound(&self) -> mpsc::UnboundedSender<Outbound> {
        self.outbound.clone()
    }

    /// Await the next inbox item, or `None` once the connection task exits.
    pub(crate) async fn recv(&mut self) -> Option<Inbox> {
        self.inbox.recv().await
    }
}

async fn connection_task(
    config: ClientConfig,
    identity: IdentityKey,
    role: Role,
    topic: Topic,
    mut outbound: mpsc::UnboundedReceiver<Outbound>,
    inbox: mpsc::UnboundedSender<Inbox>,
) {
    let mut delay = config.reconnect_initial_delay;
    let mut attempt = 0usize;

    loop {
        match connect_once(&config, &identity, role, &topic).await {
            Ok(stream) => {
                attempt = 0;
                delay = config.reconnect_initial_delay;
                let _ = inbox.send(Inbox::Connected);

                if !run_connection(stream, &mut outbound, &inbox, &config).await {
                    return; // all senders dropped: shutting down
                }
                let _ = inbox.send(Inbox::Disconnected);
            }
            Err(error) => {
                log::debug!("relay connect failed: {error}");
                let _ = inbox.send(Inbox::Disconnected);
            }
        }

        attempt += 1;
        if attempt >= config.reconnect_max_attempts {
            log::warn!("relay reconnect attempts exhausted");
            let _ = inbox.send(Inbox::Closed);
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
    let session_id = random::id()?;
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
    let (stream, _response) = connect_async(url.as_str()).await?;
    Ok(stream)
}

/// Drive one WebSocket session. Returns `true` to reconnect, `false` to stop.
async fn run_connection(
    stream: RelayStream,
    outbound: &mut mpsc::UnboundedReceiver<Outbound>,
    inbox: &mpsc::UnboundedSender<Inbox>,
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
                            let _ = inbox.send(Inbox::Frame(frame));
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
