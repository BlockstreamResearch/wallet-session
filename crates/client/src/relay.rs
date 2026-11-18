use std::{
    collections::VecDeque,
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
    message::{MessageType, Topic},
};

use crate::{
    config::ClientConfig,
    error::{JsonErrorSummary, Result},
    identity::IdentityKey,
    random,
};

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
    /// How long the relay kept responding: the whole connection, or, if it
    /// ended because the relay stopped responding (a pong, idle or write
    /// deadline passed), until it last answered one of our pings.
    healthy_for: Duration,
    /// Lifecycle and control items the client had no room for yet.
    undelivered: Vec<Inbox>,
}

/// Hand a message frame to the client without blocking the connection loop.
///
/// A full inbox is backpressure: the frame is dropped and the peer
/// retransmits the envelope, since we never acked it. While control items
/// are queued, message frames are dropped the same way, so the client never
/// sees an envelope ahead of the lifecycle item that preceded it.
///
/// A `disconnect` or `session_delete` is the exception. Its sender closes
/// straight after sending it and never retransmits it, so one that finds no
/// room waits at the back of the control queue instead. Only the first one
/// waits and later ones are dropped, which keeps the queue bounded: one that
/// replaced it at the back would split repeated control frames that
/// `queue_control` otherwise merges. The kind is read before the envelope is
/// authenticated; the client drops a forged one like any other.
///
/// Returns `false` once the client has dropped the inbox.
fn deliver_message(
    control: &mut VecDeque<Inbox>,
    inbox: &mpsc::Sender<Inbox>,
    frame: RelayFrame,
) -> bool {
    let frame = if control.is_empty() {
        match inbox.try_send(Inbox::Frame(frame)) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
            Err(mpsc::error::TrySendError::Full(Inbox::Frame(frame))) => frame,
            Err(mpsc::error::TrySendError::Full(_)) => unreachable!("sent a frame"),
        }
    } else {
        frame
    };
    let waiting = control.iter().any(|item| {
        matches!(item, Inbox::Frame(queued) if matches!(queued.body, RelayFrameBody::Message { .. }))
    });
    if is_one_shot(&frame) && !waiting {
        control.push_back(Inbox::Frame(frame));
    } else {
        log::debug!("dropping inbound frame: client inbox full or control items pending");
    }
    true
}

/// Whether a message frame carries a `disconnect` or `session_delete`.
fn is_one_shot(frame: &RelayFrame) -> bool {
    #[derive(serde::Deserialize)]
    struct Kind {
        kind: MessageType,
    }

    let RelayFrameBody::Message { payload } = &frame.body else {
        return false;
    };
    serde_json::from_str::<Kind>(payload).is_ok_and(|envelope| {
        matches!(
            envelope.kind,
            MessageType::Disconnect | MessageType::SessionDelete
        )
    })
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
                let result = run_connection(
                    stream,
                    &topic,
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
                    // bypass that gating and pacing. Do this before waiting
                    // for inbox room below: the retry task may be waiting for
                    // outbound room, and it must not be held up until the
                    // application drains its inbox.
                    while outbound.try_recv().is_ok() {}

                    // The socket is gone, so there is nothing left to service
                    // while we wait for room.
                    for item in result.undelivered {
                        if !send_inbox_wait(&inbox, item, &mut shutdown).await {
                            return;
                        }
                    }
                }
                // Only a connection on which the relay kept responding for a
                // while shows the relay is healthy. `session_ready` alone
                // does not: a relay that says ready and then closes, or stops
                // responding, would otherwise keep us reconnecting forever,
                // and on a token-expiry close without even a backoff. A
                // connection that was healthy that long and only then
                // stalled still counts.
                if result.healthy_for >= config.connection_stability {
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
#[allow(clippy::too_many_arguments)]
async fn run_connection(
    stream: RelayStream,
    topic: &Topic,
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
    let mut session_writable = false;
    let mut stalled = false;
    // Only a pong shows the relay is reading what we send. Frames it sends
    // on its own, pings included, do not.
    let mut last_pong = started_at;

    // `Connected` and relay control frames must reach the client even while
    // its inbox is full, but waiting for room must not stop us answering
    // pings or reading the socket. Queue them here and hand them over as soon
    // as there is capacity. While anything is queued, message frames are
    // dropped (the peer retransmits them) so the client never sees a frame
    // ahead of the lifecycle item that precedes it. A teardown, which is not
    // retransmitted, joins the queue instead (see `deliver_message`).
    //
    // Outbound frames come first in the `select!` below, so a final message
    // the client queued just before going away is still written even when
    // the closed inbox ends the loop on the next turn.
    let mut control = VecDeque::from([Inbox::Connected(topic.clone())]);

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
                    match send_with_timeout(&mut sink, Message::text(text), config.write_timeout).await {
                        Write::Sent => {}
                        Write::TimedOut => {
                            stalled = true;
                            break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                        }
                        Write::Failed => break ConnectionEnd::Reconnect { reason: "relay connection lost" },
                    }
                }
                None => break ConnectionEnd::Shutdown,
            },
            permit = inbox.reserve(), if !control.is_empty() => match permit {
                Ok(permit) => {
                    if let Some(item) = control.pop_front() {
                        permit.send(item);
                    }
                }
                Err(_) => break ConnectionEnd::Shutdown,
            },
            message = source.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    match serde_json::from_str::<RelayFrame>(&text) {
                        // The relay binds this socket to one topic. A frame for
                        // another topic or version must not move our
                        // readiness or reach the client.
                        Ok(frame) if frame.v != RelayFrame::VERSION || frame.topic != *topic => {
                            log::warn!(
                                "dropping relay frame with version {} for topic {}",
                                frame.v,
                                frame.topic.log_tag()
                            );
                        }
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
                                session_writable = true;
                                ready.store(true, Ordering::Relaxed);
                                joined.store(true, Ordering::Relaxed);
                            }
                            if matches!(&frame.body, RelayFrameBody::PeerDisconnected) {
                                session_writable = false;
                                ready.store(false, Ordering::Relaxed);
                            }
                            if !matches!(&frame.body, RelayFrameBody::Message { .. }) {
                                queue_control(&mut control, frame);
                            } else if !deliver_message(&mut control, inbox, frame) {
                                break ConnectionEnd::Shutdown;
                            }
                        }
                        Err(error) => {
                            log::warn!("invalid relay frame: {}", JsonErrorSummary(&error));
                        }
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    match send_with_timeout(
                        &mut sink,
                        Message::Pong(payload),
                        config.write_timeout,
                    )
                    .await
                    {
                        Write::Sent => {}
                        Write::TimedOut => {
                            stalled = true;
                            break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                        }
                        Write::Failed => break ConnectionEnd::Reconnect { reason: "relay connection lost" },
                    }
                }
                Some(Ok(Message::Pong(_))) => {
                    idle_deadline = Instant::now() + config.idle_timeout;
                    last_pong = Instant::now();
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
                match send_with_timeout(&mut sink, Message::Ping(Bytes::new()), config.write_timeout).await {
                    Write::Sent => {}
                    Write::TimedOut => {
                        stalled = true;
                        break ConnectionEnd::Reconnect { reason: "relay write timed out" };
                    }
                    Write::Failed => break ConnectionEnd::Reconnect { reason: "relay connection lost" },
                }
            }
            _ = sleep_until(pong_deadline), if awaiting_pong => {
                log::debug!("relay pong timed out");
                stalled = true;
                break ConnectionEnd::Reconnect { reason: "relay pong timed out" };
            }
            _ = sleep_until(idle_deadline) => {
                log::debug!("relay idle timeout");
                stalled = true;
                break ConnectionEnd::Reconnect { reason: "relay idle timeout" };
            }
            _ = shutdown.changed() => break ConnectionEnd::Shutdown,
        }
    };

    if matches!(end, ConnectionEnd::Shutdown) {
        close_socket(&mut sink, config.close_timeout).await;
    }

    let healthy_for = if stalled {
        last_pong.saturating_duration_since(started_at)
    } else {
        started_at.elapsed()
    };
    ConnectionResult {
        end,
        healthy_for,
        undelivered: control.into(),
    }
}

/// Queue a relay control frame for the client.
///
/// An undelivered `session_ready` is stale once anything newer arrives, so it
/// is replaced. A `peer_disconnected` is kept even if the peer has returned
/// since: the application must still learn that the peer was gone and its
/// grace window ran out. A repeated one collapses into the first. So besides
/// `Connected` the queue never holds more than one `peer_disconnected`
/// followed by one `session_ready`, and at most one teardown that
/// `deliver_message` queued among them.
fn queue_control(control: &mut VecDeque<Inbox>, frame: RelayFrame) {
    let is = |item: Option<&Inbox>, wanted: fn(&RelayFrameBody) -> bool| matches!(item, Some(Inbox::Frame(queued)) if wanted(&queued.body));
    let ready = |body: &RelayFrameBody| matches!(body, RelayFrameBody::SessionReady);
    let gone = |body: &RelayFrameBody| matches!(body, RelayFrameBody::PeerDisconnected);

    if is(control.back(), ready) {
        control.pop_back();
    }
    if gone(&frame.body) && is(control.back(), gone) {
        return;
    }
    control.push_back(Inbox::Frame(frame));
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

/// How a bounded write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Write {
    Sent,
    /// The write deadline passed: the relay stopped reading.
    TimedOut,
    /// The socket failed the write, for example because it was reset.
    Failed,
}

async fn send_with_timeout<S>(sink: &mut S, message: Message, timeout: Duration) -> Write
where
    S: Sink<Message> + Unpin,
{
    match tokio::time::timeout(timeout, sink.send(message)).await {
        Ok(Ok(())) => Write::Sent,
        Ok(Err(_)) => Write::Failed,
        Err(_) => Write::TimedOut,
    }
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

    fn control(body: RelayFrameBody) -> RelayFrame {
        RelayFrame {
            v: RelayFrame::VERSION,
            id: wallet_session_core::message::MessageId::from_bytes([0u8; 16]),
            topic: Topic::new([9u8; 32]).expect("topic"),
            body,
        }
    }

    fn kinds(control: &VecDeque<Inbox>) -> Vec<&'static str> {
        control
            .iter()
            .map(|item| match item {
                Inbox::Connected(_) => "connected",
                Inbox::Frame(frame) => match frame.body {
                    RelayFrameBody::SessionReady => "ready",
                    RelayFrameBody::PeerDisconnected => "gone",
                    RelayFrameBody::Message { .. } => "message",
                },
                _ => "other",
            })
            .collect()
    }

    #[test]
    fn queued_peer_disconnect_survives_the_peer_returning() {
        let topic = Topic::new([9u8; 32]).expect("topic");
        let mut queue = VecDeque::from([Inbox::Connected(topic)]);

        queue_control(&mut queue, control(RelayFrameBody::SessionReady));
        // A stale ready is replaced; a disconnect is kept when the peer returns.
        queue_control(&mut queue, control(RelayFrameBody::PeerDisconnected));
        queue_control(&mut queue, control(RelayFrameBody::SessionReady));
        assert_eq!(kinds(&queue), ["connected", "gone", "ready"]);

        // Leaving and returning again collapses into the same shape.
        queue_control(&mut queue, control(RelayFrameBody::PeerDisconnected));
        queue_control(&mut queue, control(RelayFrameBody::PeerDisconnected));
        assert_eq!(kinds(&queue), ["connected", "gone"]);
        queue_control(&mut queue, control(RelayFrameBody::SessionReady));
        assert_eq!(kinds(&queue), ["connected", "gone", "ready"]);
    }

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
        assert_eq!(
            send_with_timeout(&mut sink, Message::text("frame"), Duration::from_secs(1)).await,
            Write::TimedOut
        );
    }

    struct BrokenSink;

    impl Sink<Message> for BrokenSink {
        type Error = std::io::Error;

        fn poll_ready(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }

        fn start_send(
            self: std::pin::Pin<&mut Self>,
            _: Message,
        ) -> std::result::Result<(), Self::Error> {
            Err(std::io::ErrorKind::ConnectionReset.into())
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_failed_write_is_not_a_stall() {
        let mut sink = BrokenSink;
        assert_eq!(
            send_with_timeout(&mut sink, Message::text("frame"), Duration::from_secs(1)).await,
            Write::Failed
        );
    }

    /// A lifecycle item waits as long as it takes for room in the inbox. It
    /// must never give up, which is what left the client with no transport
    /// and no error before.
    #[tokio::test(start_paused = true)]
    async fn lifecycle_sends_wait_for_room_instead_of_giving_up() {
        let topic = Topic::new([9u8; 32]).expect("topic");
        let (inbox, mut receiver) = mpsc::channel(1);
        inbox
            .try_send(Inbox::Connected(topic.clone()))
            .expect("first item");
        let (_shutdown_tx, mut shutdown) = watch::channel(false);
        let send = tokio::spawn(async move {
            send_inbox_wait(&inbox, Inbox::Disconnected(topic), &mut shutdown).await
        });

        // Far longer than any timeout the transport uses.
        tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
        assert!(!send.is_finished(), "the send must still be waiting");

        assert!(matches!(receiver.recv().await, Some(Inbox::Connected(_))));
        assert!(
            send.await.expect("task"),
            "the send completes once there is room"
        );
        assert!(matches!(
            receiver.recv().await,
            Some(Inbox::Disconnected(_))
        ));
    }

    fn message(kind: &str) -> RelayFrame {
        control(RelayFrameBody::Message {
            payload: format!(r#"{{"kind":"{kind}"}}"#),
        })
    }

    #[test]
    fn message_delivery_is_non_blocking() {
        let (inbox, receiver) = mpsc::channel(1);
        let mut queue = VecDeque::new();
        assert!(deliver_message(&mut queue, &inbox, message("request")));
        assert!(deliver_message(&mut queue, &inbox, message("request")));
        assert!(
            queue.is_empty(),
            "a message the inbox has no room for is dropped"
        );

        drop(receiver);
        assert!(!deliver_message(&mut queue, &inbox, message("request")));
    }

    #[test]
    fn a_teardown_waits_when_the_inbox_is_full() {
        let (inbox, _receiver) = mpsc::channel(1);
        let mut queue = VecDeque::new();
        assert!(deliver_message(&mut queue, &inbox, message("request")));

        assert!(deliver_message(&mut queue, &inbox, message("disconnect")));
        assert_eq!(kinds(&queue), ["message"]);
        // Later messages, and later teardowns, are dropped behind it.
        assert!(deliver_message(&mut queue, &inbox, message("request")));
        assert!(deliver_message(
            &mut queue,
            &inbox,
            message("session_delete")
        ));
        assert_eq!(kinds(&queue), ["message"]);
        assert!(matches!(
            queue.front(),
            Some(Inbox::Frame(RelayFrame { body: RelayFrameBody::Message { payload }, .. }))
                if payload.contains("disconnect")
        ));
    }

    #[test]
    fn teardowns_and_control_frames_keep_the_queue_bounded() {
        // Whoever sends these, relay or peer, must not be able to grow the
        // queue: a teardown waiting at the back must not stop repeated
        // control frames from merging.
        let topic = Topic::new([9u8; 32]).expect("topic");
        let (inbox, _receiver) = mpsc::channel(1);
        inbox
            .try_send(Inbox::Connected(topic.clone()))
            .expect("fill the inbox");
        for first in [
            RelayFrameBody::PeerDisconnected,
            RelayFrameBody::SessionReady,
        ] {
            let mut queue = VecDeque::from([Inbox::Connected(topic.clone())]);
            for _ in 0..1000 {
                queue_control(&mut queue, control(first.clone()));
                assert!(deliver_message(&mut queue, &inbox, message("disconnect")));
                let second = match first {
                    RelayFrameBody::PeerDisconnected => RelayFrameBody::SessionReady,
                    _ => RelayFrameBody::PeerDisconnected,
                };
                queue_control(&mut queue, control(second));
            }
            assert!(queue.len() <= 5, "{:?}", kinds(&queue));
        }
    }

    #[test]
    fn a_teardown_waits_behind_queued_control_items() {
        let topic = Topic::new([9u8; 32]).expect("topic");
        let (inbox, _receiver) = mpsc::channel(8);
        let mut queue = VecDeque::from([Inbox::Connected(topic)]);
        assert!(deliver_message(&mut queue, &inbox, message("request")));
        assert!(deliver_message(&mut queue, &inbox, message("disconnect")));
        assert_eq!(kinds(&queue), ["connected", "message"]);
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
