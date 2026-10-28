use std::{sync::Arc, time::Duration};

use futures_util::{Sink, SinkExt, StreamExt, stream::SplitStream};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{Notify, mpsc, oneshot, watch},
    task::JoinHandle,
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Bytes, Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::{StatusCode, Uri},
        protocol::{CloseFrame, frame::coding::CloseCode},
    },
};
use wallet_session_core::{codec, connection::ConnectionQuery};

use crate::{
    auth::{Identity, IdentityError, unix_now},
    config::NativeRelayTransportConfig,
    limits::{Bucket, InboundBytes, Limiter},
    session::{Outbound, Registration, Role, Session, SessionError},
};
use wallet_session_core::{
    did::DidKey,
    frame::{RelayFrame, RelayFrameBody},
    message::Topic,
};

/// Server-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<TcpStream>;

/// Relay frame protocol version accepted from clients.
pub(crate) const RELAY_FRAME_VERSION: u8 = 1;

/// Time to let the writer flush before aborting it on connection teardown.
const WRITER_SHUTDOWN_GRACE: Duration = Duration::from_millis(100);

/// Consecutive frames a connection may have rejected by its own inbound rate
/// limits before it is disconnected.
pub(crate) const MAX_CONSECUTIVE_RATE_DROPS: u32 = 32;

/// Maximum accepted query-string length before parsing.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;

/// Maximum number of characters of a client-supplied `registrationId` echoed
/// into logs.
const MAX_LOGGED_REGISTRATION_ID: usize = 64;

/// Truncate a client-supplied registration id for logging.
// TODO: remove once `registration_id` is properly integrated.
fn described_registration_id(registration_id: &str) -> String {
    registration_id
        .chars()
        .take(MAX_LOGGED_REGISTRATION_ID)
        .collect()
}

/// Parse and verify the handshake query, returning the params and peer identity.
fn parse_connection(
    uri: &Uri,
    audience: &str,
    now: u64,
    max_token_lifetime: Duration,
) -> Result<(ConnectionQuery, Identity), ConnectionError> {
    let query = uri
        .query()
        .ok_or(ConnectionError::MissingParameter("query"))?;
    if query.len() > MAX_QUERY_BYTES {
        return Err(ConnectionError::QueryTooLarge);
    }
    let query: ConnectionQuery = serde_urlencoded::from_str(query)?;

    let identity =
        Identity::verify_token_with_lifetime(&query.auth, audience, now, max_token_lifetime)?;

    // TODO: `registrationId` is client-asserted and not covered by the token
    // signature, so it is an attribution label only
    if let Some(registration_id) = &query.registration_id {
        log::debug!(
            "connection from {} carries registrationId {:?}",
            identity.did,
            described_registration_id(registration_id)
        );
    }

    Ok((query, identity))
}

fn reject_response() -> ErrorResponse {
    let mut response = ErrorResponse::default();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

pub(crate) fn random_id() -> Result<String, ConnectionError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(codec::encode(&bytes))
}

/// A single peer connection bound to one topic slot.
///
/// A connection only depends on its [`Session`]; peer registration and
/// teardown are the caller's responsibility.
pub struct Connection {
    query: ConnectionQuery,
    identity: Identity,
    session: Arc<Session>,
    outbound: mpsc::Receiver<Outbound>,
    self_tx: mpsc::Sender<Outbound>,
    config: NativeRelayTransportConfig,
    limiter: Arc<Limiter>,
}

impl Connection {
    /// Perform the WebSocket handshake and parse the connection parameters.
    #[allow(clippy::result_large_err)]
    pub async fn handshake(
        stream: TcpStream,
        config: NativeRelayTransportConfig,
    ) -> Result<(ConnectionQuery, Identity, RelayStream), ConnectionError> {
        let audience = config.audience.as_str();
        let now = unix_now();
        let mut parsed: Option<Result<(ConnectionQuery, Identity), ConnectionError>> = None;
        let request = accept_hdr_async_with_config(
            stream,
            |request: &Request, response: Response| {
                let params =
                    parse_connection(request.uri(), audience, now, config.max_token_lifetime);
                let accepted = params.is_ok();
                parsed = Some(params);
                if accepted {
                    Ok(response)
                } else {
                    Err(reject_response())
                }
            },
            Some(config.websocket_config()),
        );
        let handshake = match tokio::time::timeout(config.handshake_timeout, request).await {
            Ok(handshake) => handshake,
            Err(_) => {
                log::debug!("websocket handshake timed out");
                return Err(ConnectionError::HandshakeTimeout);
            }
        };

        let (query, identity) = match parsed {
            Some(Ok(parsed)) => parsed,
            Some(Err(error)) => return Err(error),
            None => match handshake.err() {
                Some(error) => return Err(ConnectionError::from(error)),
                None => return Err(ConnectionError::HandshakeFailed),
            },
        };

        let websocket = handshake.map_err(ConnectionError::from)?;
        log::debug!(
            "handshake accepted for topic {} as {:?} ({})",
            query.topic,
            query.role,
            identity.did
        );

        Ok((query, identity, websocket))
    }

    /// Build a connection for a peer that has been registered on `session`.
    pub fn new(
        query: ConnectionQuery,
        identity: Identity,
        session: Arc<Session>,
        outbound: mpsc::Receiver<Outbound>,
        self_tx: mpsc::Sender<Outbound>,
        config: NativeRelayTransportConfig,
        limiter: Arc<Limiter>,
    ) -> Self {
        Self {
            query,
            identity,
            session,
            outbound,
            self_tx,
            config,
            limiter,
        }
    }

    /// Serve the peer until it disconnects.
    pub async fn run(
        self,
        websocket: RelayStream,
        registration: Registration,
    ) -> Result<(), ConnectionError> {
        let mut websocket = websocket;
        log::debug!(
            "serving peer {} on topic {} as {:?}",
            self.identity.did,
            self.query.topic,
            self.query.role
        );
        let both_ready = match registration {
            Registration::BothReady => true,
            Registration::Waiting => false,
            Registration::RoleTaken(role) => {
                log::warn!(
                    "rejecting connection for topic {}: {role:?} role already taken",
                    self.query.topic
                );
                let frame = CloseFrame {
                    code: CloseCode::Policy,
                    reason: "role already taken".into(),
                };
                let _ = websocket.close(Some(frame)).await;
                return Err(ConnectionError::RoleTaken(role));
            }
        };

        let (sink, source) = websocket.split();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<Option<CloseFrame>>();

        let backlog = BacklogDelivery {
            ready: Arc::new(Notify::new()),
            tx: self.self_tx.downgrade(),
        };

        // Deadline by which an outstanding keepalive ping must be answered.
        let (ping_deadline, mut ping_deadline_rx) = watch::channel(None);
        let mut writer = tokio::spawn(write_loop(
            sink,
            self.outbound,
            shutdown_rx,
            self.config.clone(),
            ping_deadline.clone(),
            Arc::clone(&backlog.ready),
        ));

        let config = &self.config;
        if both_ready {
            log::info!(
                "session ready for topic {}, role {:?}",
                self.query.topic,
                self.query.role
            );
        }

        // The slot's handle must be the only strong sender left: when a
        // same-identity reconnect replaces this connection, dropping that
        // handle closes the outbound queue, which stops the writer and ends
        // this connection. The read loop upgrades it again to drain a backlog.
        drop(self.self_tx);

        let expires_at = tokio::time::Instant::now()
            + Duration::from_secs(self.identity.exp.saturating_sub(unix_now()));
        let context = ReadContext {
            query: &self.query,
            session: &self.session,
            config,
            limiter: &self.limiter,
            identity: &self.identity.did,
            expires_at,
        };
        let result = read_loop(
            source,
            &mut writer,
            &context,
            &ping_deadline,
            &mut ping_deadline_rx,
            backlog,
        )
        .await;

        let close_frame = match &result {
            Err(ConnectionError::TokenExpired) => Some(CloseFrame {
                code: CloseCode::Policy,
                reason: "token expired".into(),
            }),
            _ => None,
        };
        let _ = shutdown_tx.send(close_frame);
        stop_writer(&mut writer).await;

        result
    }
}

async fn stop_writer(writer: &mut JoinHandle<()>) {
    if writer.is_finished() {
        return;
    }
    if tokio::time::timeout(WRITER_SHUTDOWN_GRACE, &mut *writer)
        .await
        .is_err()
    {
        log::debug!("connection writer did not stop promptly; aborting");
        writer.abort();
    }
}

/// Write queued frames and keepalive pings until the queue closes, the
/// connection shuts down, or a write misses its deadline.
///
/// Besides the per-write timeout, a frame must be written within the queue
/// timeout of entering the queue, so a reader that takes each write just in
/// time but never catches up is dropped as well. The frames behind the one
/// being written are checked when the writer reaches them, so a keepalive
/// ping written in between can delay that by up to one write timeout. A frame
/// holds its bytes in the peer's budget until it has been written.
async fn write_loop<S>(
    mut sink: S,
    mut rx: mpsc::Receiver<Outbound>,
    mut shutdown: oneshot::Receiver<Option<CloseFrame>>,
    config: NativeRelayTransportConfig,
    ping_deadline: watch::Sender<Option<tokio::time::Instant>>,
    backlog_ready: Arc<Notify>,
) where
    S: Sink<Message> + Unpin,
{
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + config.ping_interval,
        config.ping_interval,
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut close_frame = None;
    let mut session_ready_sent = false;
    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(queued) => {
                    let frame = &queued.frame;
                    let session_ready = matches!(&frame.body, RelayFrameBody::SessionReady);
                    let Ok(text) = serde_json::to_string(frame) else {
                        break;
                    };
                    log::trace!("relay -> topic={} frame={text}", frame.topic);
                    let message = Message::text(text);
                    if !send_queued(&mut sink, message, queued.queued_at, &config).await {
                        break;
                    }
                    // Written: its bytes go back to the peer's budget.
                    drop(queued);
                    // Once the peer has been told it is ready, the backlog
                    // held for it may follow, and every later write makes room
                    // in the queue for more of it.
                    session_ready_sent |= session_ready;
                    if session_ready_sent {
                        backlog_ready.notify_one();
                    }
                }
                None => break,
            },
            _ = ping.tick() => {
                if !send_with_timeout(&mut sink, Message::Ping(Bytes::new()), config.write_timeout).await {
                    break;
                }
                // A live peer answers with a pong (or other traffic) before this deadline.
                // Arm only if no deadline is outstanding so repeated pings cannot
                // indefinitely extend the window when pong_timeout > ping_interval.
                let deadline = tokio::time::Instant::now() + config.pong_timeout;
                let _ = ping_deadline.send_if_modified(|current| {
                    if current.is_none() {
                        *current = Some(deadline);
                        true
                    } else {
                        false
                    }
                });
            }
            reason = &mut shutdown => {
                close_frame = reason.ok().flatten();
                break;
            }
        }
    }
    if let Some(frame) = close_frame {
        send_with_timeout(&mut sink, Message::Close(Some(frame)), config.write_timeout).await;
    }
    if tokio::time::timeout(WRITER_SHUTDOWN_GRACE, sink.close())
        .await
        .is_err()
    {
        log::debug!("outbound websocket close timed out");
    }
}

/// Spend one redelivery credit, if any is left.
///
/// Credits are the inbound budget for the acknowledgements of frames the relay
/// redelivered; they are spent only once the steady-state bucket is empty, so
/// live traffic keeps using the configured rate.
fn spend_redelivery_credit(credit: &mut u32) -> bool {
    let Some(left) = credit.checked_sub(1) else {
        return false;
    };
    *credit = left;
    true
}

/// Charge an inbound control frame like a text frame: to the connection's
/// inbound budget, then to the identity's share of the relay-wide budget and
/// to the budget itself.
///
/// The frame is dropped when a budget is exhausted, and a peer that keeps
/// exceeding its own or its identity's budget is disconnected like any other
/// flooder. An exhausted relay-wide budget alone drops the frame without
/// counting towards that, so other identities cannot get this peer
/// disconnected. Returns `Err` only to disconnect the peer.
fn charge_control_frame(
    bytes: usize,
    message_bucket: &mut Bucket,
    byte_bucket: &mut Bucket,
    limiter: &Limiter,
    identity: &DidKey,
    consecutive_drops: &mut u32,
    topic: &Topic,
) -> Result<(), ConnectionError> {
    let limits = limiter.limits();
    let now = tokio::time::Instant::now();
    let within_connection_limits = message_bucket.allow_n(1, limits.inbound_message_rate, now)
        && byte_bucket.allow_n(
            u32::try_from(bytes).unwrap_or(u32::MAX),
            limits.inbound_byte_rate,
            now,
        );
    if !within_connection_limits {
        *consecutive_drops += 1;
        log::debug!("dropping control frame on topic {topic}: inbound rate limit exceeded");
        if *consecutive_drops > MAX_CONSECUTIVE_RATE_DROPS {
            log::warn!("peer on topic {topic} keeps exceeding its inbound rate limit; dropping");
            return Err(ConnectionError::RateLimited);
        }
        return Ok(());
    }

    match limiter.allow_inbound_bytes(identity, bytes) {
        InboundBytes::Allowed => *consecutive_drops = 0,
        InboundBytes::ShareExhausted => {
            *consecutive_drops += 1;
            log::debug!(
                "dropping control frame on topic {topic}: identity share of the relay budget exhausted"
            );
            if *consecutive_drops > MAX_CONSECUTIVE_RATE_DROPS {
                log::warn!(
                    "peer on topic {topic} keeps exceeding its share of the relay budget; dropping"
                );
                return Err(ConnectionError::RateLimited);
            }
        }
        InboundBytes::GlobalExhausted => {
            log::debug!(
                "dropping control frame on topic {topic}: relay inbound byte budget exhausted"
            );
        }
    }
    Ok(())
}

/// Send one message, returning whether the socket is still usable.
async fn send_with_timeout<S>(sink: &mut S, message: Message, write_timeout: Duration) -> bool
where
    S: Sink<Message> + Unpin,
{
    match tokio::time::timeout(write_timeout, sink.send(message)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            log::warn!("outbound websocket write timed out; closing connection");
            false
        }
    }
}

/// Send a frame that entered the queue at `queued_at`, returning whether the
/// socket is still usable.
///
/// The write gets the write timeout, cut short so that the frame is written
/// within the queue timeout of entering the queue or not at all. A frame
/// already past it is not attempted, even if the socket would take it now.
async fn send_queued<S>(
    sink: &mut S,
    message: Message,
    queued_at: tokio::time::Instant,
    config: &NativeRelayTransportConfig,
) -> bool
where
    S: Sink<Message> + Unpin,
{
    let left = config
        .outbound_queue_timeout
        .saturating_sub(queued_at.elapsed());
    if left >= config.write_timeout {
        return send_with_timeout(sink, message, config.write_timeout).await;
    }
    let sent = if left.is_zero() {
        None
    } else {
        tokio::time::timeout(left, sink.send(message)).await.ok()
    };
    match sent {
        Some(Ok(())) => true,
        Some(Err(_)) => false,
        None => {
            log::warn!("outbound queue is not draining; closing connection");
            false
        }
    }
}

/// Shared, read-only state a connection's read loop works against.
struct ReadContext<'a> {
    query: &'a ConnectionQuery,
    session: &'a Session,
    config: &'a NativeRelayTransportConfig,
    limiter: &'a Limiter,
    identity: &'a DidKey,
    expires_at: tokio::time::Instant,
}

/// Everything a read loop needs to deliver a peer's backlog.
struct BacklogDelivery {
    /// Armed by the writer after `session_ready` has been written, and after
    /// every write from then on.
    ready: Arc<Notify>,

    /// The slot's channel. It is weak because the slot's handle must stay the
    /// only strong sender, so a replaced connection closes its queue
    tx: mpsc::WeakSender<Outbound>,
}

async fn read_loop(
    mut source: SplitStream<RelayStream>,
    writer: &mut JoinHandle<()>,
    context: &ReadContext<'_>,
    ping_deadline: &watch::Sender<Option<tokio::time::Instant>>,
    ping_deadline_rx: &mut watch::Receiver<Option<tokio::time::Instant>>,
    backlog: BacklogDelivery,
) -> Result<(), ConnectionError> {
    let ReadContext {
        query,
        session,
        config,
        limiter,
        identity,
        expires_at,
    } = *context;

    let limits = limiter.limits();
    let now = tokio::time::Instant::now();
    let mut message_bucket = Bucket::full(limits.inbound_message_rate.burst, now);
    let mut byte_bucket = Bucket::full(limits.inbound_byte_rate.burst, now);
    let mut consecutive_drops = 0u32;

    let mut redelivery_credit = 0u32;
    let mut backlog_pending = true;
    let mut idle_deadline = now + config.idle_timeout;

    // Every deadline is absolute and polled on each iteration, and no arm
    // awaits anything, so neither a slow writer nor a backlog its counterpart
    // keeps refilling can hold the connection past them.
    loop {
        let message = tokio::select! {
            biased;

            _ = &mut *writer => {
                log::debug!("connection writer stopped for topic {}; closing", query.topic);
                break;
            }
            _ = wait_pong_deadline(ping_deadline_rx) => {
                log::debug!("peer on topic {} missed a keepalive pong; dropping", query.topic);
                return Err(ConnectionError::PongTimeout);
            }
            _ = tokio::time::sleep_until(expires_at) => {
                log::debug!(
                    "peer on topic {} has an expired token; closing",
                    query.topic
                );
                return Err(ConnectionError::TokenExpired);
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                log::debug!(
                    "peer on topic {} idle for {:?}; dropping",
                    query.topic,
                    config.idle_timeout
                );
                return Err(ConnectionError::IdleTimeout);
            }
            () = backlog.ready.notified(), if backlog_pending => {
                // One step: what fits in the queue now. The writer wakes this
                // arm again once it has made room.
                backlog_pending = match backlog.tx.upgrade() {
                    Some(tx) => {
                        let drain = session.drain_backlog(query.role, &tx)?;
                        redelivery_credit = redelivery_credit
                            .saturating_add(u32::try_from(drain.delivered).unwrap_or(u32::MAX));
                        !drain.finished
                    }
                    // The slot let go of the queue: this connection was replaced.
                    None => false,
                };
                continue;
            }
            incoming = source.next() => match incoming {
                Some(Ok(message)) => message,
                Some(Err(error)) => return Err(error.into()),
                None => break,
            },
        };

        idle_deadline = tokio::time::Instant::now() + config.idle_timeout;
        let _ = ping_deadline.send(None);

        let frame = match message {
            Message::Text(text) => {
                // Charged before parsing so a flood cannot force JSON work or
                // grow the counterpart's queue and buffer faster than the limits.
                let now = tokio::time::Instant::now();
                let within_message_budget =
                    message_bucket.allow_n(1, limits.inbound_message_rate, now)
                        || spend_redelivery_credit(&mut redelivery_credit);
                let within_connection_limits = within_message_budget
                    && byte_bucket.allow_n(
                        u32::try_from(text.len()).unwrap_or(u32::MAX),
                        limits.inbound_byte_rate,
                        now,
                    );
                if !within_connection_limits {
                    consecutive_drops += 1;
                    log::debug!(
                        "dropping frame on topic {}: inbound rate limit exceeded",
                        query.topic
                    );
                    if consecutive_drops > MAX_CONSECUTIVE_RATE_DROPS {
                        log::warn!(
                            "peer on topic {} keeps exceeding its inbound rate limit; dropping",
                            query.topic
                        );
                        return Err(ConnectionError::RateLimited);
                    }
                    continue;
                }

                match limiter.allow_inbound_bytes(identity, text.len()) {
                    InboundBytes::Allowed => consecutive_drops = 0,
                    InboundBytes::ShareExhausted => {
                        consecutive_drops += 1;
                        log::debug!(
                            "dropping frame on topic {}: identity share of the relay budget exhausted",
                            query.topic
                        );
                        if consecutive_drops > MAX_CONSECUTIVE_RATE_DROPS {
                            log::warn!(
                                "peer on topic {} keeps exceeding its share of the relay budget; dropping",
                                query.topic
                            );
                            return Err(ConnectionError::RateLimited);
                        }
                        continue;
                    }
                    InboundBytes::GlobalExhausted => {
                        log::debug!(
                            "dropping frame on topic {}: relay inbound byte budget exhausted",
                            query.topic
                        );
                        continue;
                    }
                }

                log::trace!("relay <- topic={} frame={text}", query.topic);
                serde_json::from_str::<RelayFrame>(&text).inspect_err(|error| {
                    log::warn!("invalid relay frame on topic {}: {error}", query.topic);
                })?
            }
            Message::Close(_) => break,
            // The relay protocol is JSON text only.
            Message::Binary(_) => {
                log::warn!(
                    "binary frame on topic {} is not part of the relay protocol",
                    query.topic
                );
                return Err(ConnectionError::UnexpectedBinary);
            }
            // Keepalive pongs and other control frames count as activity, but
            // they are charged to the same budgets as data frames, the shared
            // ones included, so a peer cannot hold the connection open with
            // unmetered traffic and identities cannot exceed the relay-wide
            // budget with it.
            Message::Ping(payload) | Message::Pong(payload) => {
                charge_control_frame(
                    payload.len(),
                    &mut message_bucket,
                    &mut byte_bucket,
                    limiter,
                    identity,
                    &mut consecutive_drops,
                    &query.topic,
                )?;
                continue;
            }
            Message::Frame(frame) => {
                charge_control_frame(
                    frame.payload().len(),
                    &mut message_bucket,
                    &mut byte_bucket,
                    limiter,
                    identity,
                    &mut consecutive_drops,
                    &query.topic,
                )?;
                continue;
            }
        };

        if frame.v != RELAY_FRAME_VERSION {
            log::warn!(
                "unsupported relay frame version {} on topic {}",
                frame.v,
                query.topic
            );
            return Err(ConnectionError::InvalidVersion(frame.v));
        }
        if frame.topic != query.topic {
            log::warn!(
                "frame topic {} does not match subscription {}",
                frame.topic,
                query.topic
            );
            return Err(ConnectionError::TopicMismatch);
        }
        if let Some(kind) = frame.body.relay_only_body() {
            log::warn!(
                "client sent relay-only {kind} frame on topic {}",
                query.topic
            );
            return Err(ConnectionError::ClientControlFrame(kind));
        }

        match session.route(
            query.role,
            frame,
            config.session_buffer_max_messages,
            config.session_buffer_ttl,
        ) {
            Ok(()) => {}
            Err(SessionError::NoCounterpart) => {
                log::trace!(
                    "dropping frame on topic {}: counterpart not connected",
                    query.topic
                );
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Resolves when an outstanding keepalive ping is not answered in time.
async fn wait_pong_deadline(rx: &mut watch::Receiver<Option<tokio::time::Instant>>) {
    loop {
        let deadline = *rx.borrow_and_update();
        match deadline {
            Some(deadline) => {
                tokio::time::sleep_until(deadline).await;
                if *rx.borrow_and_update() == Some(deadline) {
                    return;
                }
            }
            None => {
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        }
    }
}

/// Connection handler failures.
#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("missing query parameter: {0}")]
    MissingParameter(&'static str),

    #[error("invalid query parameters: {0}")]
    Query(#[from] serde_urlencoded::de::Error),

    #[error("invalid auth token: {0}")]
    Identity(#[from] IdentityError),

    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("malformed relay frame: {0}")]
    Frame(#[from] serde_json::Error),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("role already taken: {0:?}")]
    RoleTaken(Role),

    #[error("clients may not send {0} frames")]
    ClientControlFrame(&'static str),

    #[error("binary frames are not part of the relay protocol")]
    UnexpectedBinary,

    #[error("inbound rate limit exceeded")]
    RateLimited,

    #[error("websocket handshake failed")]
    HandshakeFailed,

    #[error("websocket handshake timed out")]
    HandshakeTimeout,

    #[error("handshake query is too large")]
    QueryTooLarge,

    #[error("unsupported relay frame version: {0}")]
    InvalidVersion(u8),

    #[error("frame topic does not match the subscription")]
    TopicMismatch,

    #[error("peer idle timeout")]
    IdleTimeout,

    #[error("peer missed a keepalive pong")]
    PongTimeout,

    #[error("connection token expired")]
    TokenExpired,

    #[error("random source failure: {0}")]
    Random(#[from] getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::test_utils::{self, signing_key};
    use crate::limits::OutboundBudget;
    use tokio::time::timeout;
    use wallet_session_core::message::Topic;

    const AUDIENCE: &str = "wss://relay.example.com";
    const NOW: u64 = 1_700_000_000;
    const MAX_LIFETIME: Duration = Duration::from_secs(3600);

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn token() -> String {
        test_utils::token(&signing_key(1), AUDIENCE, NOW, NOW + 3600)
    }

    fn uri(query: &str) -> Result<Uri, Box<dyn std::error::Error>> {
        Ok(format!("/?{query}").parse()?)
    }

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([1u8; 32])
    }

    fn parse(query: &str) -> Result<(ConnectionQuery, Identity), ConnectionError> {
        parse_connection(
            &uri(query).map_err(|_| ConnectionError::HandshakeFailed)?,
            AUDIENCE,
            NOW,
            MAX_LIFETIME,
        )
    }

    #[test]
    fn registration_id_is_truncated_and_quoted_for_logs() {
        let long = "a".repeat(MAX_LOGGED_REGISTRATION_ID + 10);
        assert_eq!(
            described_registration_id(&long).chars().count(),
            MAX_LOGGED_REGISTRATION_ID
        );

        // Control characters are escaped, so they cannot forge log lines.
        assert_eq!(
            format!("{:?}", described_registration_id("a\nb")),
            r#""a\nb""#
        );
    }

    #[test]
    fn proposer_params_parse() -> TestResult {
        let topic = topic()?;
        let query = format!(
            "auth={}&role=proposer&topic={}&registrationId=reg-1",
            token(),
            topic
        );
        let (query, identity) = parse(&query)?;

        assert_eq!(query.role, Role::Proposer);
        assert_eq!(query.topic, topic);
        assert_eq!(identity.did, test_utils::did_key(&signing_key(1)));
        assert_eq!(identity.session, "session");
        assert_eq!(query.registration_id.as_deref(), Some("reg-1"));
        Ok(())
    }

    #[test]
    fn responder_params_parse_without_registration_id() -> TestResult {
        let query = format!("auth={}&role=responder&topic={}", token(), topic()?);
        let (query, _identity) = parse(&query)?;

        assert_eq!(query.role, Role::Responder);
        assert_eq!(query.registration_id, None);
        Ok(())
    }

    #[test]
    fn proposer_registration_id_is_optional() -> TestResult {
        let query = format!("auth={}&role=proposer&topic={}", token(), topic()?);
        let (query, _identity) = parse(&query)?;

        assert_eq!(query.role, Role::Proposer);
        assert_eq!(query.registration_id, None);
        Ok(())
    }

    #[test]
    fn invalid_role_is_rejected() -> TestResult {
        let query = format!("auth={}&role=observer&topic={}", token(), topic()?);
        assert!(matches!(parse(&query), Err(ConnectionError::Query(_))));
        Ok(())
    }

    #[test]
    fn invalid_topic_is_rejected() -> TestResult {
        let query = format!("auth={}&role=responder&topic=not-a-topic", token());
        assert!(matches!(parse(&query), Err(ConnectionError::Query(_))));
        Ok(())
    }

    #[test]
    fn missing_auth_is_rejected() -> TestResult {
        let query = format!("role=responder&topic={}", topic()?);
        assert!(matches!(parse(&query), Err(ConnectionError::Query(_))));
        Ok(())
    }

    #[test]
    fn malformed_auth_token_is_rejected() -> TestResult {
        let query = format!("auth=no-dots&role=responder&topic={}", topic()?);
        assert!(matches!(
            parse(&query),
            Err(ConnectionError::Identity(IdentityError::MalformedToken))
        ));
        Ok(())
    }

    #[test]
    fn wrong_audience_is_rejected() -> TestResult {
        let token = test_utils::token(&signing_key(1), "wss://other", NOW, NOW + 3600);
        let query = format!("auth={}&role=responder&topic={}", token, topic()?);
        assert!(matches!(
            parse(&query),
            Err(ConnectionError::Identity(IdentityError::Audience))
        ));
        Ok(())
    }

    #[test]
    fn oversized_query_is_rejected() -> TestResult {
        let query = "a".repeat(MAX_QUERY_BYTES + 1);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW, MAX_LIFETIME),
            Err(ConnectionError::QueryTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn oversized_auth_token_is_rejected() -> TestResult {
        let query = format!(
            "auth={}&role=responder&topic={}",
            "a".repeat(crate::auth::MAX_TOKEN_BYTES + 1),
            topic()?
        );
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW, MAX_LIFETIME),
            Err(ConnectionError::Identity(IdentityError::TooLong))
        ));
        Ok(())
    }

    #[test]
    fn token_lifetime_over_cap_is_rejected() -> TestResult {
        let token = test_utils::token(&signing_key(1), AUDIENCE, NOW, NOW + 7200);
        let query = format!("auth={token}&role=responder&topic={}", topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW, Duration::from_secs(3600)),
            Err(ConnectionError::Identity(IdentityError::ExpiryTooLong))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn slow_handshake_times_out() -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        // keep the client socket open but never send the HTTP upgrade request.
        let _client = TcpStream::connect(addr).await?;
        let (server, _) = listener.accept().await?;

        let config = NativeRelayTransportConfig::new(AUDIENCE)
            .with_handshake_timeout(Duration::from_millis(100));
        let outcome = Connection::handshake(server, config).await;
        assert!(matches!(outcome, Err(ConnectionError::HandshakeTimeout)));
        Ok(())
    }

    #[tokio::test]
    async fn stop_writer_tolerates_an_already_joined_writer() -> TestResult {
        let mut writer = tokio::spawn(async {});
        // mirrors `read_loop` observing the writer finish.
        (&mut writer).await?;
        stop_writer(&mut writer).await;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn stop_writer_aborts_a_stalled_writer() {
        let mut writer = tokio::spawn(std::future::pending::<()>());
        stop_writer(&mut writer).await;
        assert!(writer.await.is_err_and(|error| error.is_cancelled()));
    }

    /// Ids of the frames a test reader accepted.
    type Accepted = Arc<std::sync::Mutex<Vec<String>>>;

    /// A reader that takes `per_message` to accept each message, and the ids
    /// of the frames it accepted.
    fn slow_reader(per_message: Duration) -> (Accepted, impl Sink<Message> + Unpin) {
        let accepted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = futures_util::sink::unfold(
            Arc::clone(&accepted),
            move |accepted, message: Message| async move {
                tokio::time::sleep(per_message).await;
                if let Message::Text(text) = &message
                    && let Ok(frame) = serde_json::from_str::<RelayFrame>(text)
                {
                    accepted.lock().expect("accepted ids").push(frame.id);
                }
                Ok::<_, std::convert::Infallible>(accepted)
            },
        );
        (accepted, Box::pin(sink))
    }

    /// Run a writer over `sink` as a connection does. It runs until the
    /// returned sender shuts it down or is dropped.
    fn spawn_writer<S>(
        sink: S,
        rx: mpsc::Receiver<Outbound>,
        config: NativeRelayTransportConfig,
    ) -> (oneshot::Sender<Option<CloseFrame>>, JoinHandle<()>)
    where
        S: Sink<Message> + Unpin + Send + 'static,
    {
        let (shutdown, shutdown_rx) = oneshot::channel();
        let (ping_deadline, _) = watch::channel(None);
        let writer = tokio::spawn(write_loop(
            sink,
            rx,
            shutdown_rx,
            config,
            ping_deadline,
            Arc::new(Notify::new()),
        ));
        (shutdown, writer)
    }

    /// Writer settings for these tests, with no keepalive ping in the way.
    fn writer_config() -> NativeRelayTransportConfig {
        NativeRelayTransportConfig::new(AUDIENCE)
            .with_ping_interval(Duration::from_secs(3600))
            .with_write_timeout(Duration::from_secs(10))
            .with_outbound_queue_timeout(Duration::from_secs(15))
    }

    /// A message frame entering the queue now, holding 100 bytes of `budget`.
    fn queued(
        budget: &Arc<OutboundBudget>,
        id: &str,
    ) -> Result<Outbound, Box<dyn std::error::Error>> {
        let frame = RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: id.to_owned(),
            topic: topic()?,
            body: RelayFrameBody::Message {
                payload: "ciphertext".to_owned(),
            },
        };
        Ok(Outbound::new(frame, budget.try_charge(100)))
    }

    #[tokio::test(start_paused = true)]
    async fn writer_drops_a_reader_that_never_catches_up_with_its_queue() -> TestResult {
        let budget = Arc::new(OutboundBudget::new(1024));
        let (tx, rx) = mpsc::channel(8);
        for i in 0..6 {
            tx.try_send(queued(&budget, &format!("m{i}"))?)?;
        }

        // Every write takes 4s, well inside the 10s write timeout, but the
        // six frames take 24s to get through and none may wait over 15s. The
        // fourth is still being written at 15s: that write is cut short.
        let (accepted, sink) = slow_reader(Duration::from_secs(4));
        let start = tokio::time::Instant::now();
        let (_shutdown, writer) = spawn_writer(sink, rx, writer_config());
        timeout(Duration::from_secs(60), writer).await??;

        let queue_timeout = Duration::from_secs(15);
        let window = queue_timeout..=queue_timeout + WRITER_SHUTDOWN_GRACE;
        let elapsed = start.elapsed();
        assert!(
            window.contains(&elapsed),
            "the writer must stop once a frame has waited the queue timeout, not {elapsed:?}"
        );
        assert_eq!(*accepted.lock().expect("accepted ids"), ["m0", "m1", "m2"]);

        drop(tx);
        assert_eq!(budget.held(), 0, "frames left behind give their bytes back");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn writer_keeps_a_slow_reader_that_keeps_up() -> TestResult {
        let budget = Arc::new(OutboundBudget::new(1024));
        let (tx, rx) = mpsc::channel(8);
        let (accepted, sink) = slow_reader(Duration::from_secs(4));
        let (shutdown, writer) = spawn_writer(sink, rx, writer_config());

        // The last of these waits 8s and is written by 12s.
        for i in 0..3 {
            tx.try_send(queued(&budget, &format!("m{i}"))?)?;
        }
        // A frame queued long after the queue emptied waits only from then.
        tokio::time::sleep(Duration::from_secs(30)).await;
        tx.try_send(queued(&budget, "m3")?)?;
        tokio::time::sleep(Duration::from_secs(10)).await;

        assert!(
            !writer.is_finished(),
            "a reader that keeps up must not be dropped"
        );
        assert_eq!(
            *accepted.lock().expect("accepted ids"),
            ["m0", "m1", "m2", "m3"]
        );
        assert_eq!(budget.held(), 0, "written frames give their bytes back");

        let _ = shutdown.send(None);
        timeout(Duration::from_secs(1), writer).await??;
        Ok(())
    }
}
