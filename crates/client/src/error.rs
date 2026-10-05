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

    #[error("invalid pairing uri: {0}")]
    PairingUri(String),

    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    #[error("invalid query parameters: {0}")]
    Query(#[from] serde_urlencoded::ser::Error),

    #[error("relay connection closed")]
    Closed,

    #[error("relay connection timed out")]
    Timeout,

    #[error("peer disconnected")]
    PeerDisconnected,

    #[error("random source failure: {0}")]
    Random(#[from] getrandom::Error),

    #[error("a registration id is required for the proposer")]
    MissingRegistrationId,

    #[error("session is not active")]
    SessionNotActive,
}

pub type Result<T> = std::result::Result<T, ClientError>;
