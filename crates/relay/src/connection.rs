use std::{sync::Arc, time::Duration};

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot, watch},
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
    limits::{Bucket, Limiter, RelayLimitsConfig},
    session::{Registration, Role, Session, SessionError},
};
use wallet_session_core::{frame::RelayFrame, message::Topic};

/// Server-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<TcpStream>;

/// Relay frame protocol version accepted from clients.
pub(crate) const RELAY_FRAME_VERSION: u8 = 1;

/// Time to let the writer flush before aborting it on connection teardown.
const WRITER_SHUTDOWN_GRACE: Duration = Duration::from_millis(100);

/// Consecutive frames a connection may have rejected by its own inbound rate
/// limits before it is disconnected.
const MAX_CONSECUTIVE_RATE_DROPS: u32 = 32;

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
    outbound: mpsc::Receiver<RelayFrame>,
    self_tx: mpsc::Sender<RelayFrame>,
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
        outbound: mpsc::Receiver<RelayFrame>,
        self_tx: mpsc::Sender<RelayFrame>,
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        // Deadline by which an outstanding keepalive ping must be answered.
        let (ping_deadline, mut ping_deadline_rx) = watch::channel(None);
        let mut writer = tokio::spawn(write_loop(
            sink,
            self.outbound,
            shutdown_rx,
            self.config.ping_interval,
            self.config.pong_timeout,
            self.config.write_timeout,
            ping_deadline.clone(),
        ));

        let config = &self.config;
        if both_ready {
            log::info!(
                "session ready for topic {}, role {:?}",
                self.query.topic,
                self.query.role
            );
        }

        let redelivered = self
            .session
            .drain_backlog(self.query.role, &self.self_tx)
            .await;

        // The slot's handle must be the only sender left: when a same-identity
        // reconnect replaces this connection, dropping that handle closes the
        // outbound queue, which stops the writer and ends this connection.
        drop(self.self_tx);
        let redelivered = match redelivered {
            Ok(redelivered) => redelivered,
            Err(error) => {
                let _ = shutdown_tx.send(());
                stop_writer(&mut writer).await;
                return Err(error.into());
            }
        };

        let context = ReadContext {
            query: &self.query,
            session: &self.session,
            config,
            limiter: &self.limiter,
        };
        let result = read_loop(
            source,
            &mut writer,
            &context,
            &ping_deadline,
            &mut ping_deadline_rx,
            redelivered,
        )
        .await;

        let _ = shutdown_tx.send(());
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

async fn write_loop(
    mut sink: SplitSink<RelayStream, Message>,
    mut rx: mpsc::Receiver<RelayFrame>,
    mut shutdown: oneshot::Receiver<()>,
    ping_interval: Duration,
    pong_timeout: Duration,
    write_timeout: Duration,
    ping_deadline: watch::Sender<Option<tokio::time::Instant>>,
) {
    let mut ping =
        tokio::time::interval_at(tokio::time::Instant::now() + ping_interval, ping_interval);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(frame) => {
                    let Ok(text) = serde_json::to_string(&frame) else {
                        break;
                    };
                    log::trace!("relay -> topic={} frame={text}", frame.topic);
                    if !send_with_timeout(&mut sink, Message::text(text), write_timeout).await {
                        break;
                    }
                }
                None => break,
            },
            _ = ping.tick() => {
                if !send_with_timeout(&mut sink, Message::Ping(Bytes::new()), write_timeout).await {
                    break;
                }
                // A live peer answers with a pong (or other traffic) before this deadline.
                // Arm only if no deadline is outstanding so repeated pings cannot
                // indefinitely extend the window when pong_timeout > ping_interval.
                let deadline = tokio::time::Instant::now() + pong_timeout;
                let _ = ping_deadline.send_if_modified(|current| {
                    if current.is_none() {
                        *current = Some(deadline);
                        true
                    } else {
                        false
                    }
                });
            }
            _ = &mut shutdown => break,
        }
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

/// Charge an inbound control frame to the connection's inbound budget.
///
/// The frame is dropped when the budget is exhausted, and a peer that keeps
/// exceeding it is disconnected like any other flooder. Returns `Err` only to
/// disconnect the peer.
fn charge_control_frame(
    bytes: usize,
    message_bucket: &mut Bucket,
    byte_bucket: &mut Bucket,
    limits: &RelayLimitsConfig,
    consecutive_drops: &mut u32,
    topic: &Topic,
) -> Result<(), ConnectionError> {
    let now = tokio::time::Instant::now();
    let within_limits = message_bucket.allow_n(1, limits.inbound_message_rate, now)
        && byte_bucket.allow_n(
            u32::try_from(bytes).unwrap_or(u32::MAX),
            limits.inbound_byte_rate,
            now,
        );
    if within_limits {
        *consecutive_drops = 0;
        return Ok(());
    }

    *consecutive_drops += 1;
    log::debug!("dropping control frame on topic {topic}: inbound rate limit exceeded");
    if *consecutive_drops > MAX_CONSECUTIVE_RATE_DROPS {
        log::warn!("peer on topic {topic} keeps exceeding its inbound rate limit; dropping");
        return Err(ConnectionError::RateLimited);
    }
    Ok(())
}

/// Send one message, returning whether the socket is still usable.
async fn send_with_timeout(
    sink: &mut SplitSink<RelayStream, Message>,
    message: Message,
    write_timeout: Duration,
) -> bool {
    match tokio::time::timeout(write_timeout, sink.send(message)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            log::warn!("outbound websocket write timed out; closing connection");
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
}

async fn read_loop(
    mut source: SplitStream<RelayStream>,
    writer: &mut JoinHandle<()>,
    context: &ReadContext<'_>,
    ping_deadline: &watch::Sender<Option<tokio::time::Instant>>,
    ping_deadline_rx: &mut watch::Receiver<Option<tokio::time::Instant>>,
    redelivered: usize,
) -> Result<(), ConnectionError> {
    let ReadContext {
        query,
        session,
        config,
        limiter,
    } = *context;

    let limits = limiter.limits();
    let now = tokio::time::Instant::now();
    let mut message_bucket = Bucket::full(limits.inbound_message_rate.burst, now);
    let mut byte_bucket = Bucket::full(limits.inbound_byte_rate.burst, now);
    let mut consecutive_drops = 0u32;

    let mut redelivery_credit = u32::try_from(redelivered).unwrap_or(u32::MAX);

    loop {
        let message = tokio::select! {
            _ = &mut *writer => {
                log::debug!("connection writer stopped for topic {}; closing", query.topic);
                break;
            }
            _ = wait_pong_deadline(ping_deadline_rx) => {
                log::debug!("peer on topic {} missed a keepalive pong; dropping", query.topic);
                return Err(ConnectionError::PongTimeout);
            }
            incoming = tokio::time::timeout(config.idle_timeout, source.next()) => match incoming {
                Ok(Some(Ok(message))) => message,
                Ok(Some(Err(error))) => return Err(error.into()),
                Ok(None) => break,
                Err(_) => {
                    log::debug!(
                        "peer on topic {} idle for {:?}; dropping",
                        query.topic,
                        config.idle_timeout
                    );
                    return Err(ConnectionError::IdleTimeout);
                }
            },
        };

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
                consecutive_drops = 0;

                // Shared budget: a drop here is not this peer's fault, so it
                // does not count toward disconnecting it.
                if !limiter.allow_inbound_bytes(text.len()) {
                    log::debug!(
                        "dropping frame on topic {}: relay inbound byte budget exhausted",
                        query.topic
                    );
                    continue;
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
            // they are charged to the same budget as data frames so a peer
            // cannot hold the connection open with unmetered traffic.
            Message::Ping(payload) | Message::Pong(payload) => {
                charge_control_frame(
                    payload.len(),
                    &mut message_bucket,
                    &mut byte_bucket,
                    &limits,
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
                    &limits,
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

    #[error("random source failure: {0}")]
    Random(#[from] getrandom::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::test_utils::{self, signing_key};
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
}
