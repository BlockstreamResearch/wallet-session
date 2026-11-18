use thiserror::Error;

/// Client-side failures.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("encoding error: {0}")]
    Codec(#[from] wallet_session_core::error::Error),

    #[error("cipher error: {0}")]
    Cipher(#[from] crate::crypto::CipherError),

    #[error("handshake error: {0}")]
    Handshake(#[from] crate::handshake::HandshakeError),

    #[error("invalid pairing uri: {0}")]
    PairingUri(String),

    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    #[error("invalid query parameters: {0}")]
    Query(#[from] serde_urlencoded::ser::Error),

    #[error("relay connection closed")]
    Closed,

    #[error("relay transport failed: {0}")]
    Transport(&'static str),

    #[error("invalid client configuration: {0}")]
    InvalidConfig(&'static str),

    /// The outbound queue is full, or the link has too many pending messages
    /// and unconsumed delivery outcomes. Drain `poll_event()`/`next_event()`
    /// and retry later.
    #[error("client is under backpressure")]
    Busy,

    #[error("relay connection timed out")]
    Timeout,

    #[error("peer disconnected")]
    PeerDisconnected,

    #[error("unexpected handshake message")]
    UnexpectedHandshake,

    #[error("protocol violation: {0}")]
    ProtocolViolation(&'static str),

    #[error("random source failure: {0}")]
    Random(#[from] getrandom::Error),

    #[error("session is not active")]
    SessionNotActive,

    #[error("relay session is not ready")]
    NotReady,

    /// The proposer did not join the session topic within the join timeout
    /// after the responder's `approve`. The client is closed.
    #[error("session was not established")]
    SessionNotEstablished,
}

pub type Result<T> = std::result::Result<T, ClientError>;
