use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::{Sink, SinkExt, StreamExt};
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval_at, sleep_until},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{
        Bytes, Error as TungsteniteError, Message,
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
    },
};
use wallet_session_core::{
    connection::{ConnectionQuery, Role},
    frame::{RelayFrame, RelayFrameBody},
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

    /// The socket for `topic` is established (initial or after reconnect).
    Connected(Topic),

    /// The connection for `topic` was lost; a reconnect is starting.
    Disconnected(Topic),

    /// Reconnect attempts for `topic` were exhausted or permanently rejected.
    Closed { topic: Topic, reason: &'static str },

    /// The client no longer needs the pairing connection for `topic`.
    Retire(Topic),

    /// The session-join window for `topic` after a failed `approve` ended.
    SessionTimeout(Topic),
}

/// Why one connection attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionEnd {
    /// The client is shutting down.
    Shutdown,

    /// Retry after the configured backoff.
    Reconnect { reason: &'static str },

    /// Retry immediately, for example after a token-expiry close.
    ReconnectNow { reason: &'static str },

    /// Do not retry.
    Fatal { reason: &'static str },
}

struct ConnectionResult {
    end: ConnectionEnd,
    saw_session_ready: bool,
    uptime: Duration,
    timed_out: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboxTry {
    Sent,
    Full,
    Closed,
}

/// Try to hand a frame or control event to the client without blocking the
/// connection loop. A full inbox is backpressure: the peer retransmits any
/// frame whose ack was not sent.
fn try_send_inbox(inbox: &mpsc::Sender<Inbox>, item: Inbox) -> InboxTry {
    match inbox.try_send(item) {
        Ok(()) => InboxTry::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => InboxTry::Full,
        Err(mpsc::error::TrySendError::Closed(_)) => InboxTry::Closed,
    }
}

/// Send a lifecycle item, waiting for the client to make room.
///
/// Returns `false` only when the transport shuts down or the client drops the
/// inbox. A full inbox is not terminal: the application may drain it later,
/// so the task must stay alive to deliver the lifecycle item.
async fn send_inbox_wait(
    inbox: &mpsc::Sender<Inbox>,
    item: Inbox,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        result = inbox.send(item) => result.is_ok(),
        _ = shutdown.changed() => false,
    }
}

/// A reconnecting relay connection for one topic and role.
///
/// A background task owns the WebSocket lifecycle and exposes a stable
/// outbound channel, so the client and reliability layer never observe a
/// socket swap. Inbound events go to the shared channel owned by the client.
pub(crate) struct Transport {
    outbound: mpsc::Sender<Outbound>,
    shutdown: watch::Sender<bool>,
    _task: JoinHandle<()>,
}

impl Drop for Transport {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

impl Transport {
    /// Start (asynchronously) a connection to the relay for `topic` as `role`.
    ///
    /// `ready` follows the relay's current view of the counterpart. `joined`
    /// latches the first `session_ready` and is never cleared.
    pub(crate) fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
        ready: Arc<AtomicBool>,
        joined: Arc<AtomicBool>,
        inbox: mpsc::Sender<Inbox>,
    ) -> Self {
        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let _task = tokio::spawn(connection_task(
            config,
            identity,
            role,
            topic.clone(),
            outbound_rx,
            ready,
            joined,
            inbox,
            shutdown_rx,
        ));

        Self {
            outbound,
            shutdown,
            _task,
        }
    }

    /// Cloneable handle to the outbound writer.
    pub(crate) fn outbound(&self) -> mpsc::Sender<Outbound> {
        self.outbound.clone()
    }
}

#[allow(clippy::too_many_arguments)]
async fn connection_task(
    config: ClientConfig,
    identity: IdentityKey,
    role: Role,
    topic: Topic,
    mut outbound: mpsc::Receiver<Outbound>,
    ready: Arc<AtomicBool>,
    joined: Arc<AtomicBool>,
    inbox: mpsc::Sender<Inbox>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut retries = 0usize;
    let mut delay = config.reconnect_initial_delay;

    loop {
        ready.store(false, Ordering::Relaxed);
        let connected = tokio::select! {
            biased;
            result = connect_with_timeout(&config, &identity, role, &topic) => result,
            _ = shutdown.changed() => return,
        };

        let end = match connected {
            Ok(stream) => {
                if !send_inbox_wait(&inbox, Inbox::Connected(topic.clone()), &mut shutdown).await {
                    return;
                }
                let result = run_connection(
                    stream,
                    &mut outbound,
                    &ready,
                    &joined,
                    &inbox,
                    &mut shutdown,
                    &config,
                )
                .await;
                ready.store(false, Ordering::Relaxed);
                if !matches!(result.end, ConnectionEnd::Shutdown) {
                    // Reliability re-flushes unacked tracked frames on the next
                    // ready edge. Do not let copies queued on the old socket
                    // bypass that gating and pacing.
                    while outbound.try_recv().is_ok() {}
                }
                if result.saw_session_ready
                    || (!result.timed_out && result.uptime >= config.connection_stability)
                {
                    retries = 0;
                    delay = config.reconnect_initial_delay;
                }
                result.end
            }
            Err(error) => {
                let end = classify_connect_error(&error);
                if let ConnectionEnd::Reconnect { reason } | ConnectionEnd::Fatal { reason } = end {
                    log::debug!("relay connect failed: {reason}");
                }
                end
            }
        };

        match end {
            ConnectionEnd::Shutdown => return,
            ConnectionEnd::Fatal { reason } => {
                let _ =
                    send_inbox_wait(&inbox, Inbox::Closed { topic, reason }, &mut shutdown).await;
                return;
            }
            ConnectionEnd::ReconnectNow { reason } => {
                if retries >= config.reconnect_max_attempts {
                    let _ = send_inbox_wait(&inbox, Inbox::Closed { topic, reason }, &mut shutdown)
                        .await;
                    return;
                }
                retries += 1;
                if !send_inbox_wait(&inbox, Inbox::Disconnected(topic.clone()), &mut shutdown).await
                {
                    return;
                }
            }
            ConnectionEnd::Reconnect { reason } => {
                if !send_inbox_wait(&inbox, Inbox::Disconnected(topic.clone()), &mut shutdown).await
                {
                    return;
                }
                if retries >= config.reconnect_max_attempts {
                    let _ = send_inbox_wait(&inbox, Inbox::Closed { topic, reason }, &mut shutdown)
                        .await;
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown.changed() => return,
                }
                retries += 1;
                delay = delay.saturating_mul(2).min(config.reconnect_max_delay);
            }
        }
    }
}

async fn connect_with_timeout(
    config: &ClientConfig,
    identity: &IdentityKey,
    role: Role,
    topic: &Topic,
) -> Result<RelayStream> {
    tokio::time::timeout(
        config.connect_timeout,
        connect_once(config, identity, role, topic),
    )
    .await
    .map_err(|_| crate::error::ClientError::Timeout)?
}

fn classify_connect_error(error: &crate::error::ClientError) -> ConnectionEnd {
    use crate::error::ClientError;

    match error {
        ClientError::InvalidConfig(_) => ConnectionEnd::Fatal {
            reason: "invalid client configuration",
        },
        ClientError::Url(_) => ConnectionEnd::Fatal {
            reason: "invalid relay URL",
        },
        ClientError::Query(_) => ConnectionEnd::Fatal {
            reason: "invalid connection parameters",
        },
        ClientError::Random(_) => ConnectionEnd::Fatal {
            reason: "random source failure",
        },
        ClientError::WebSocket(TungsteniteError::Http(response))
            if response.status().is_client_error() =>
        {
            ConnectionEnd::Fatal {
                reason: "relay rejected connection",
            }
        }
        ClientError::Timeout => ConnectionEnd::Reconnect {
            reason: "relay connect timed out",
        },
        _ => ConnectionEnd::Reconnect {
            reason: "relay connection failed",
        },
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

    log::debug!(
        "connecting to relay host={} topic={}",
        url.host_str().unwrap_or("?"),
        topic.log_tag()
    );
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

/// Drive one WebSocket session.
async fn run_connection(
    stream: RelayStream,
    outbound: &mut mpsc::Receiver<Outbound>,
    ready: &AtomicBool,
    joined: &AtomicBool,
    inbox: &mpsc::Sender<Inbox>,
    shutdown: &mut watch::Receiver<bool>,
    config: &ClientConfig,
) -> ConnectionResult {
    let (mut sink, mut source) = stream.split();
    let started_at = Instant::now();

    let mut ping = interval_at(Instant::now() + config.ping_interval, config.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut awaiting_pong = false;
    let mut pong_deadline = Instant::now();
    let mut idle_deadline = Instant::now() + config.idle_timeout;
    let mut saw_session_ready = false;
    let mut session_writable = false;
    let mut timed_out = false;

    let end = loop {
        tokio::select! {
            biased;
            outbound_item = outbound.recv() => match outbound_item {
                Some(Outbound::Frame(frame)) => {
                    // A frame queued before the relay made this session
                    // writable must not cross the new connection. Tracked
                    // frames are re-dispatched by reliability on the ready
                    // edge; stale untracked acks are dropped and the peer
                    // retransmits the envelopes.
                    if !session_writable {
                        log::debug!(
                            "dropping outbound frame before session_ready on topic {}",
                            frame.topic.log_tag()
                        );
                        continue;
                    }
                    let Ok(text) = serde_json::to_string(&frame) else {
                        break ConnectionEnd::Reconnect { reason: "invalid outbound frame" };
                    };
                    log::trace!(
                        "client -> topic={} bytes={}",
                        frame.topic.log_tag(),
                        text.len()
                    );
                    if !send_with_timeout(&mut sink, Message::text(text), config.write_timeout).await {
                        break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                    }
                }
                None => break ConnectionEnd::Shutdown,
            },
            message = source.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    match serde_json::from_str::<RelayFrame>(&text) {
                        Ok(frame) => {
                            log::trace!(
                                "client <- topic={} bytes={}",
                                frame.topic.log_tag(),
                                text.len()
                            );
                            if matches!(&frame.body, RelayFrameBody::SessionReady) {
                                // A peer can return after its grace window and
                                // the relay sends another `session_ready` on
                                // the same socket. The shared flag must follow
                                // every one of them, not just the first.
                                saw_session_ready = true;
                                session_writable = true;
                                ready.store(true, Ordering::Relaxed);
                                joined.store(true, Ordering::Relaxed);
                            }
                            if matches!(&frame.body, RelayFrameBody::PeerDisconnected) {
                                session_writable = false;
                                ready.store(false, Ordering::Relaxed);
                            }
                            match try_send_inbox(inbox, Inbox::Frame(frame)) {
                                InboxTry::Sent => {}
                                InboxTry::Full => {
                                    log::debug!("dropping inbound frame: client inbox full");
                                }
                                InboxTry::Closed => break ConnectionEnd::Shutdown,
                            }
                        }
                        Err(error) => log::warn!("invalid relay frame: {error}"),
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    if !send_with_timeout(
                        &mut sink,
                        Message::Pong(payload),
                        config.write_timeout,
                    )
                    .await
                    {
                        break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    awaiting_pong = false;
                }
                Some(Ok(Message::Close(frame))) => break classify_close(frame),
                Some(Ok(Message::Binary(_) | Message::Frame(_))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                }
                Some(Err(error)) => {
                    log::debug!("relay read error: {error}");
                    break ConnectionEnd::Reconnect { reason: "relay connection lost" };
                }
                None => break ConnectionEnd::Reconnect { reason: "relay connection closed" },
            },
            _ = ping.tick(), if !awaiting_pong => {
                awaiting_pong = true;
                pong_deadline = Instant::now() + config.pong_timeout;
                if !send_with_timeout(&mut sink, Message::Ping(Bytes::new()), config.write_timeout).await {
                    break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                }
            }
            _ = sleep_until(pong_deadline), if awaiting_pong => {
                log::debug!("relay pong timed out");
                timed_out = true;
                break ConnectionEnd::Reconnect { reason: "relay pong timed out" };
            }
            _ = sleep_until(idle_deadline) => {
                log::debug!("relay idle timeout");
                timed_out = true;
                break ConnectionEnd::Reconnect { reason: "relay idle timeout" };
            }
            _ = shutdown.changed() => break ConnectionEnd::Shutdown,
        }
    };

    if matches!(end, ConnectionEnd::Shutdown) {
        close_socket(&mut sink, config.close_timeout).await;
    }

    ConnectionResult {
        end,
        saw_session_ready,
        uptime: started_at.elapsed(),
        timed_out,
    }
}

fn classify_close(frame: Option<CloseFrame>) -> ConnectionEnd {
    match frame {
        Some(frame) if frame.code == CloseCode::Policy => match frame.reason.as_str() {
            "token expired" => ConnectionEnd::ReconnectNow {
                reason: "token expired",
            },
            "role already taken" => ConnectionEnd::Fatal {
                reason: "role already taken",
            },
            _ => ConnectionEnd::Fatal {
                reason: "relay policy rejection",
            },
        },
        _ => ConnectionEnd::Reconnect {
            reason: "relay closed connection",
        },
    }
}

async fn send_with_timeout<S>(sink: &mut S, message: Message, timeout: Duration) -> bool
where
    S: Sink<Message> + Unpin,
{
    matches!(
        tokio::time::timeout(timeout, sink.send(message)).await,
        Ok(Ok(()))
    )
}

async fn close_socket<S>(sink: &mut S, timeout: Duration)
where
    S: Sink<Message> + Unpin,
{
    let close = async {
        let frame = CloseFrame {
            code: CloseCode::Normal,
            reason: "client shutdown".into(),
        };
        let _ = sink.send(Message::Close(Some(frame))).await;
        let _ = sink.close().await;
    };
    let _ = tokio::time::timeout(timeout, close).await;
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

    struct PendingSink;

    impl Sink<Message> for PendingSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn start_send(
            self: std::pin::Pin<&mut Self>,
            _: Message,
        ) -> std::result::Result<(), Self::Error> {
            unreachable!()
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn write_timeout_fails_a_stalled_sink() {
        let mut sink = PendingSink;
        assert!(
            !send_with_timeout(&mut sink, Message::text("frame"), Duration::from_secs(1)).await
        );
    }

    #[test]
    fn inbox_try_send_is_non_blocking() {
        let topic = Topic::new([9u8; 32]).expect("topic");
        let (inbox, receiver) = mpsc::channel(1);
        inbox
            .try_send(Inbox::Connected(topic.clone()))
            .expect("first item");

        assert_eq!(
            try_send_inbox(&inbox, Inbox::Disconnected(topic.clone())),
            InboxTry::Full
        );
        drop(receiver);
        assert_eq!(
            try_send_inbox(&inbox, Inbox::Disconnected(topic)),
            InboxTry::Closed
        );
    }

    #[test]
    fn classifies_policy_closes() {
        let close = |code: CloseCode, reason: &str| {
            Some(CloseFrame {
                code,
                reason: reason.into(),
            })
        };

        assert_eq!(
            classify_close(close(CloseCode::Policy, "token expired")),
            ConnectionEnd::ReconnectNow {
                reason: "token expired"
            }
        );
        assert_eq!(
            classify_close(close(CloseCode::Policy, "role already taken")),
            ConnectionEnd::Fatal {
                reason: "role already taken"
            }
        );
        assert_eq!(
            classify_close(close(CloseCode::Policy, "something else")),
            ConnectionEnd::Fatal {
                reason: "relay policy rejection"
            }
        );
        assert_eq!(
            classify_close(close(CloseCode::Normal, "")),
            ConnectionEnd::Reconnect {
                reason: "relay closed connection"
            }
        );
        assert_eq!(
            classify_close(None),
            ConnectionEnd::Reconnect {
                reason: "relay closed connection"
            }
        );
    }
}
