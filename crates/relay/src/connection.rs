use std::sync::Arc;

use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
        http::{StatusCode, Uri},
        protocol::{CloseFrame, WebSocketConfig, frame::coding::CloseCode},
    },
};
use wallet_session_core::{codec, connection::ConnectionQuery};

use crate::{
    auth::{Identity, IdentityError, unix_now},
    session::{Registration, Role, Session, SessionError},
};
use wallet_session_core::frame::{RelayFrame, RelayFrameBody};

/// Server-side relay WebSocket stream.
type RelayStream = WebSocketStream<TcpStream>;

/// Default maximum WebSocket text or binary frame size accepted from a client.
pub const DEFAULT_MAX_INCOMING_FRAME_BYTES: usize = 1024 * 1024;

/// Runtime limits for the relay connection handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRelayTransportConfig {
    /// Audience the relay expects in the auth token (`aud` claim).
    pub audience: String,

    /// Maximum incoming text or binary frame size before JSON parsing.
    pub max_incoming_frame_bytes: usize,
}

impl NativeRelayTransportConfig {
    /// Build a config that expects `audience` in the auth token.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            max_incoming_frame_bytes: DEFAULT_MAX_INCOMING_FRAME_BYTES,
        }
    }
}

/// Parse and verify the handshake query, returning the params and peer identity.
fn parse_connection(
    uri: &Uri,
    audience: &str,
    now: u64,
) -> Result<(ConnectionQuery, Identity), ConnectionError> {
    let query = uri
        .query()
        .ok_or(ConnectionError::MissingParameter("query"))?;
    let query: ConnectionQuery = serde_urlencoded::from_str(query)?;

    let identity = Identity::verify_token(&query.auth, audience, now)?;
    if query.role == Role::Proposer && query.registration_id.is_none() {
        return Err(ConnectionError::MissingParameter("registrationId"));
    }

    Ok((query, identity))
}

fn websocket_config(config: &NativeRelayTransportConfig) -> WebSocketConfig {
    WebSocketConfig::default().max_message_size(Some(config.max_incoming_frame_bytes))
}

fn reject_response() -> ErrorResponse {
    let mut response = ErrorResponse::default();
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

fn random_id() -> Result<String, ConnectionError> {
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
    outbound: mpsc::UnboundedReceiver<RelayFrame>,
    self_tx: mpsc::UnboundedSender<RelayFrame>,
}

impl Connection {
    /// Perform the WebSocket handshake and parse the connection parameters.
    pub async fn handshake(
        stream: TcpStream,
        config: NativeRelayTransportConfig,
    ) -> Result<(ConnectionQuery, Identity, RelayStream), ConnectionError> {
        let audience = config.audience.as_str();
        let now = unix_now();
        let mut parsed: Option<Result<(ConnectionQuery, Identity), ConnectionError>> = None;
        let handshake = accept_hdr_async_with_config(
            stream,
            |request: &Request, response: Response| {
                let params = parse_connection(request.uri(), audience, now);
                let accepted = params.is_ok();
                parsed = Some(params);
                if accepted {
                    Ok(response)
                } else {
                    Err(reject_response())
                }
            },
            Some(websocket_config(&config)),
        )
        .await;

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
        outbound: mpsc::UnboundedReceiver<RelayFrame>,
        self_tx: mpsc::UnboundedSender<RelayFrame>,
    ) -> Self {
        Self {
            query,
            identity,
            session,
            outbound,
            self_tx,
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
        let writer = tokio::spawn(write_loop(sink, self.outbound, shutdown_rx));

        if both_ready {
            log::info!(
                "session ready for topic {}, role {:?}",
                self.query.topic,
                self.query.role
            );
            let ready = RelayFrame {
                v: 1,
                id: random_id()?,
                topic: self.query.topic.clone(),
                body: RelayFrameBody::SessionReady,
            };
            let _ = self.session.route(self.query.role, ready.clone());
            let _ = self.self_tx.send(ready);
        }

        let result = read_loop(source, &self.query, &self.session).await;

        drop(self.self_tx);
        let _ = shutdown_tx.send(());
        let _ = writer.await;

        result
    }
}

async fn write_loop(
    mut sink: SplitSink<RelayStream, Message>,
    mut rx: mpsc::UnboundedReceiver<RelayFrame>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            received = rx.recv() => match received {
                Some(frame) => {
                    let text = match serde_json::to_string(&frame) {
                        Ok(text) => text,
                        Err(_) => break,
                    };
                    log::trace!("relay -> topic={} frame={text}", frame.topic);
                    if sink.send(Message::text(text)).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            _ = &mut shutdown => break,
        }
    }
    let _ = sink.close().await;
}

async fn read_loop(
    mut source: SplitStream<RelayStream>,
    query: &ConnectionQuery,
    session: &Session,
) -> Result<(), ConnectionError> {
    while let Some(message) = source.next().await {
        let message = message?;
        let frame = match message {
            Message::Text(text) => {
                log::trace!("relay <- topic={} frame={text}", query.topic);
                serde_json::from_str::<RelayFrame>(&text).inspect_err(|error| {
                    log::warn!("invalid relay frame on topic {}: {error}", query.topic);
                })?
            }
            Message::Close(_) => break,
            Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
                continue;
            }
        };

        if matches!(&frame.body, RelayFrameBody::SessionReady) {
            log::warn!(
                "client sent relay-only session_ready on topic {}",
                query.topic
            );
            return Err(ConnectionError::ClientSessionReady);
        }

        match session.route(query.role, frame) {
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

    #[test]
    fn proposer_params_parse() -> TestResult {
        let topic = topic()?;
        let query = format!(
            "auth={}&role=proposer&topic={}&registrationId=reg-1",
            token(),
            topic
        );
        let (query, identity) = parse_connection(&uri(&query)?, AUDIENCE, NOW)?;

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
        let (query, _identity) = parse_connection(&uri(&query)?, AUDIENCE, NOW)?;

        assert_eq!(query.role, Role::Responder);
        assert_eq!(query.registration_id, None);
        Ok(())
    }

    #[test]
    fn proposer_requires_registration_id() -> TestResult {
        let query = format!("auth={}&role=proposer&topic={}", token(), topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::MissingParameter("registrationId"))
        ));
        Ok(())
    }

    #[test]
    fn invalid_role_is_rejected() -> TestResult {
        let query = format!("auth={}&role=observer&topic={}", token(), topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::Query(_))
        ));
        Ok(())
    }

    #[test]
    fn invalid_topic_is_rejected() -> TestResult {
        let query = format!("auth={}&role=responder&topic=not-a-topic", token());
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::Query(_))
        ));
        Ok(())
    }

    #[test]
    fn missing_auth_is_rejected() -> TestResult {
        let query = format!("role=responder&topic={}", topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::Query(_))
        ));
        Ok(())
    }

    #[test]
    fn malformed_auth_token_is_rejected() -> TestResult {
        let query = format!("auth=no-dots&role=responder&topic={}", topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::Identity(IdentityError::MalformedToken))
        ));
        Ok(())
    }

    #[test]
    fn wrong_audience_is_rejected() -> TestResult {
        let token = test_utils::token(&signing_key(1), "wss://other", NOW, NOW + 3600);
        let query = format!("auth={}&role=responder&topic={}", token, topic()?);
        assert!(matches!(
            parse_connection(&uri(&query)?, AUDIENCE, NOW),
            Err(ConnectionError::Identity(IdentityError::Audience))
        ));
        Ok(())
    }
}
