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
    session::{Registration, Role, Session, SessionError},
};
use wallet_session_core::frame::{RelayFrame, RelayFrameBody};

/// Server-side relay WebSocket stream.
pub(crate) type RelayStream = WebSocketStream<TcpStream>;

/// Relay frame protocol version accepted from clients.
pub(crate) const RELAY_FRAME_VERSION: u8 = 1;

/// Time to let the writer flush before aborting it on connection teardown.
const WRITER_SHUTDOWN_GRACE: Duration = Duration::from_millis(100);

/// Maximum accepted query-string length before parsing.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;

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
            "connection from {} carries registrationId {registration_id}",
            identity.did
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
    ) -> Self {
        Self {
            query,
            identity,
            session,
            outbound,
            self_tx,
            config,
        }
    }

    /// Serve the peer until it disconnects.
    pub async fn run(
        self,
        websocket: RelayStream,
        registration: Registration,
        buffered: Vec<RelayFrame>,
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
            let ready = RelayFrame {
                v: RELAY_FRAME_VERSION,
                id: random_id()?,
                topic: self.query.topic.clone(),
                body: RelayFrameBody::SessionReady,
            };
            let _ = self.session.route(
                self.query.role,
                ready.clone(),
                config.session_buffer_max_messages,
                config.session_buffer_ttl,
            );
            let _ = self.self_tx.send(ready).await;
        }

        if !buffered.is_empty() {
            log::debug!(
                "redelivering {} buffered frame(s) to {}",
                buffered.len(),
                self.identity.did
            );
            for frame in buffered {
                let _ = self.self_tx.send(frame).await;
            }
        }

        let result = read_loop(
            source,
            &mut writer,
            &self.query,
            &self.session,
            config,
            &ping_deadline,
            &mut ping_deadline_rx,
        )
        .await;

        drop(self.self_tx);
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

async fn read_loop(
    mut source: SplitStream<RelayStream>,
    writer: &mut JoinHandle<()>,
    query: &ConnectionQuery,
    session: &Session,
    config: &NativeRelayTransportConfig,
    ping_deadline: &watch::Sender<Option<tokio::time::Instant>>,
    ping_deadline_rx: &mut watch::Receiver<Option<tokio::time::Instant>>,
) -> Result<(), ConnectionError> {
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

        // Any inbound frame proves the peer is alive; clear the pong deadline.
        let _ = ping_deadline.send(None);

        let frame = match message {
            Message::Text(text) => {
                log::trace!("relay <- topic={} frame={text}", query.topic);
                serde_json::from_str::<RelayFrame>(&text).inspect_err(|error| {
                    log::warn!("invalid relay frame on topic {}: {error}", query.topic);
                })?
            }
            Message::Close(_) => break,
            // Keepalive pongs and other control frames count as activity.
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
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
        if matches!(&frame.body, RelayFrameBody::SessionReady) {
            log::warn!(
                "client sent relay-only session_ready on topic {}",
                query.topic
            );
            return Err(ConnectionError::ClientSessionReady);
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

    #[error("clients may not send session_ready")]
    ClientSessionReady,

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
