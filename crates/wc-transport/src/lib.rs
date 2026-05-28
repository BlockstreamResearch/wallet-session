//! Native relay transport.
//!
//! The relay server RPC contract defines JSON-RPC messages over a WebSocket
//! connection. This crate owns the native WebSocket I/O only; relay methods,
//! topics, auth URL construction, and response DTOs remain in `wc-protocol`.
//!
//! <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
//!
//! > WalletConnect expects an `Authorization: Bearer <signed jwt>` header when establishing the Websocket connection.
//!
//! <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#purpose>
//!
//! > This document aims to create the JsonRpc contract between a client and a server.

mod client;

pub use client::{
    DEFAULT_CONNECT_RETRY_ATTEMPTS, DEFAULT_CONNECT_RETRY_INITIAL_DELAY,
    DEFAULT_CONNECT_RETRY_MAX_DELAY, DEFAULT_MAX_PUSHES_WHILE_WAITING, DEFAULT_MAX_QUEUED_MESSAGES,
    DEFAULT_REQUEST_TIMEOUT, RelayClient, RelayClientConfig, RelayClientError,
    RelayReconnectConfig,
};

use std::{fmt, string::FromUtf8Error};

use futures_util::{SinkExt, StreamExt};
use rustls::crypto::aws_lc_rs;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{Error as TungsteniteError, Message, Utf8Bytes},
};
use wc_protocol::relay::{
    IrnSubscription, RelayJsonRpcRequest, RelayJsonRpcResponse, RelayJsonRpcSuccess, RelayRequest,
    RelayRpcId,
};

type RelayStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Default maximum WebSocket text or binary frame size accepted from the relay.
pub const DEFAULT_MAX_INCOMING_FRAME_BYTES: usize = 1024 * 1024;

/// Runtime limits for the native WebSocket transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRelayTransportConfig {
    /// Maximum incoming text or binary frame size before JSON parsing.
    pub max_incoming_frame_bytes: usize,
}

impl Default for NativeRelayTransportConfig {
    fn default() -> Self {
        Self {
            max_incoming_frame_bytes: DEFAULT_MAX_INCOMING_FRAME_BYTES,
        }
    }
}

/// Native WebSocket transport for the `WalletConnect` relay.
///
/// The transport reads and writes WebSocket frames, parses JSON frames into
/// `serde_json::Value`, and serializes typed relay JSON-RPC requests from
/// `wc-protocol`.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#methods>
///
/// > The following definitions are shared concepts across all JSON-RPC methods for the Relay API
pub struct NativeRelayTransport {
    stream: RelayStream,
    config: NativeRelayTransportConfig,
}

impl NativeRelayTransport {
    /// Opens a native WebSocket connection to an authenticated relay URL.
    ///
    /// Use `wc_protocol::relay::RelayConnectionUrl` to build the URL with
    /// `auth`, `projectId`, and `ua` query parameters.
    ///
    /// Rustls requires a process-wide crypto provider before TLS handshakes.
    /// The native transport installs the `aws-lc-rs` provider if the
    /// application has not installed one already.
    ///
    /// <https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html>
    ///
    /// > They should do this by calling `CryptoProvider::install_default()` early on.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
    ///
    /// > Where websocket headers are not supported i.e. browsers, use the URL query param `?auth=<signed jwt>`.
    pub async fn connect(url: &str) -> Result<RelayConnection, TransportError> {
        Self::connect_with_config(url, NativeRelayTransportConfig::default()).await
    }

    /// Opens a native WebSocket connection with explicit transport limits.
    pub async fn connect_with_config(
        url: &str,
        config: NativeRelayTransportConfig,
    ) -> Result<RelayConnection, TransportError> {
        // Installs Rustls's `aws-lc-rs` provider when no application provider exists.
        //
        // `install_default` returns the provider on failure, which includes the
        // already-installed-provider case. The transport only needs some process-level
        // provider to exist before Tungstenite starts a Rustls handshake.
        let _ = aws_lc_rs::default_provider().install_default();

        let (stream, response) = connect_async(url)
            .await
            .map_err(|source| TransportError::Connect { source })?;

        Ok(RelayConnection {
            transport: Self { stream, config },
            status: response.status().as_u16(),
        })
    }

    /// Sends a typed relay JSON-RPC request.
    ///
    /// `wc-protocol` supplies the method name through `RelayRequest`, so the
    /// transport only serializes and writes the JSON frame.
    pub async fn send_request<T>(
        &mut self,
        request: &RelayJsonRpcRequest<T>,
    ) -> Result<(), TransportError>
    where
        T: Serialize + Sync,
    {
        let value =
            serde_json::to_value(request).map_err(|source| TransportError::Serialize { source })?;
        self.send_json(&value).await
    }

    /// Builds and sends a typed relay JSON-RPC request with `id`.
    ///
    /// This is the transport equivalent of the harness call path: construct the
    /// relay envelope with protocol DTOs, then send it as one WebSocket text
    /// frame.
    pub async fn call<T>(&mut self, id: RelayRpcId, params: T) -> Result<(), TransportError>
    where
        T: RelayRequest + Send + Serialize + Sync,
    {
        self.send_request(&RelayJsonRpcRequest::new(id, params))
            .await
    }

    /// Sends a JSON value as a WebSocket text frame.
    pub async fn send_json(&mut self, value: &Value) -> Result<(), TransportError> {
        self.send_text(value.to_string()).await
    }

    /// Sends a WebSocket text frame.
    pub async fn send_text(&mut self, text: impl Into<String>) -> Result<(), TransportError> {
        self.stream
            .send(Message::Text(Utf8Bytes::from(text.into())))
            .await
            .map_err(|source| TransportError::Send { source })
    }

    /// Reads the next JSON message from the relay.
    ///
    /// Ping frames are answered with Pong frames and are not returned to the
    /// caller. Text frames are parsed directly; binary frames must contain UTF-8
    /// JSON.
    pub async fn next_json(&mut self) -> Result<Option<Value>, TransportError> {
        loop {
            let Some(message) = self.stream.next().await else {
                return Ok(None);
            };
            let message = message.map_err(|source| TransportError::Read { source })?;

            match message {
                Message::Text(text) => {
                    self.ensure_incoming_frame_size(text.len())?;
                    return parse_json(&text).map(Some);
                }
                Message::Binary(bytes) => {
                    self.ensure_incoming_frame_size(bytes.len())?;
                    let text = String::from_utf8(bytes.to_vec())
                        .map_err(|source| TransportError::Utf8 { source })?;
                    return parse_json(&text).map(Some);
                }
                Message::Ping(bytes) => self
                    .stream
                    .send(Message::Pong(bytes))
                    .await
                    .map_err(|source| TransportError::Pong { source })?,
                Message::Pong(_) | Message::Frame(_) => {}
                Message::Close(frame) => {
                    return Err(TransportError::Closed(RelayClose::from(frame)));
                }
            }
        }
    }

    /// Reads the next response matching `expected_id`.
    ///
    /// Other JSON messages are returned to the caller as `UnexpectedMessage` so
    /// higher layers can decide whether to buffer, acknowledge, or inspect them.
    pub async fn next_response<T>(
        &mut self,
        expected_id: RelayRpcId,
    ) -> Result<RelayJsonRpcResponse<T>, TransportError>
    where
        T: DeserializeOwned,
    {
        let Some(value) = self.next_json().await? else {
            return Err(TransportError::StreamEnded);
        };

        if !expected_id.matches_json_value(value.get("id")) {
            return Err(TransportError::UnexpectedMessage { expected_id, value });
        }

        serde_json::from_value(value).map_err(|source| TransportError::Json { source })
    }

    /// Acknowledges an `irn_subscription` push.
    ///
    /// Relay server RPC requires the client to answer a subscription request
    /// with a JSON-RPC `result: true` response.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscription>
    ///
    /// > Response (client->server)
    pub async fn ack_subscription(
        &mut self,
        request: &RelayJsonRpcRequest<IrnSubscription>,
    ) -> Result<(), TransportError> {
        let ack = RelayJsonRpcSuccess::new(request.id(), true);
        let value =
            serde_json::to_value(ack).map_err(|source| TransportError::Serialize { source })?;
        self.send_json(&value).await
    }

    /// Sends a WebSocket close frame.
    pub async fn close(&mut self) -> Result<(), TransportError> {
        self.stream
            .close(None)
            .await
            .map_err(|source| TransportError::Close { source })
    }

    const fn ensure_incoming_frame_size(&self, actual: usize) -> Result<(), TransportError> {
        let limit = self.config.max_incoming_frame_bytes;
        if actual > limit {
            return Err(TransportError::FrameTooLarge { actual, limit });
        }

        Ok(())
    }
}

/// Result of opening a native relay transport.
pub struct RelayConnection {
    transport: NativeRelayTransport,
    status: u16,
}

impl RelayConnection {
    /// HTTP status returned during the WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Moves the connected transport out of the connection metadata wrapper.
    #[must_use]
    pub fn into_transport(self) -> NativeRelayTransport {
        self.transport
    }
}

/// Relay close metadata extracted from a WebSocket close frame.
///
/// <https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.5>
///
/// > If The WebSocket Connection is Closed and no Close control frame was received by the endpoint, The WebSocket Connection Close Code is considered to be 1006.
///
/// <https://datatracker.ietf.org/doc/html/rfc6455#section-7.1.6>
///
/// > the interpretation of said data being left to the endpoints and not defined by this protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayClose {
    /// WebSocket close code when the peer sent one.
    pub code: Option<u16>,
    /// WebSocket close reason when the peer sent one.
    pub reason: String,
}

impl From<Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>> for RelayClose {
    fn from(frame: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>) -> Self {
        frame.map_or_else(
            || Self {
                code: None,
                reason: String::new(),
            },
            |frame| Self {
                code: Some(u16::from(frame.code)),
                reason: frame.reason.to_string(),
            },
        )
    }
}

impl fmt::Display for RelayClose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.code {
            Some(code) if self.reason.is_empty() => write!(formatter, "code={code}"),
            Some(code) => write!(formatter, "code={code} reason={}", self.reason),
            None if self.reason.is_empty() => formatter.write_str("no close frame"),
            None => write!(formatter, "reason={}", self.reason),
        }
    }
}

/// Native transport failure.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// WebSocket handshake failed.
    #[error("relay websocket connect failed")]
    Connect {
        /// Source error from Tungstenite.
        #[source]
        source: TungsteniteError,
    },

    /// WebSocket send failed.
    #[error("relay websocket send failed")]
    Send {
        /// Source error from Tungstenite.
        #[source]
        source: TungsteniteError,
    },

    /// WebSocket read failed.
    #[error("relay websocket read failed")]
    Read {
        /// Source error from Tungstenite.
        #[source]
        source: TungsteniteError,
    },

    /// WebSocket close send failed.
    #[error("relay websocket close failed")]
    Close {
        /// Source error from Tungstenite.
        #[source]
        source: TungsteniteError,
    },

    /// Pong reply to a relay ping failed.
    #[error("relay websocket pong failed")]
    Pong {
        /// Source error from Tungstenite.
        #[source]
        source: TungsteniteError,
    },

    /// JSON serialization failed before writing a frame.
    #[error("relay json serialization failed")]
    Serialize {
        /// Source error from serde JSON.
        #[source]
        source: serde_json::Error,
    },

    /// JSON parsing failed for an incoming text or binary frame.
    #[error("relay json parsing failed")]
    Json {
        /// Source error from serde JSON.
        #[source]
        source: serde_json::Error,
    },

    /// Binary WebSocket frame could not be decoded as UTF-8 JSON text.
    #[error("relay binary frame is not utf-8")]
    Utf8 {
        /// Source UTF-8 conversion error.
        #[source]
        source: FromUtf8Error,
    },

    /// Incoming text or binary frame exceeded the configured size limit.
    #[error("relay websocket frame too large: {actual} bytes exceeds {limit} bytes")]
    FrameTooLarge {
        /// Incoming frame size in bytes.
        actual: usize,
        /// Configured maximum frame size in bytes.
        limit: usize,
    },

    /// The peer ended the WebSocket stream without a close frame.
    #[error("relay websocket stream ended")]
    StreamEnded,

    /// The peer closed the WebSocket stream.
    #[error("relay websocket closed: {0}")]
    Closed(RelayClose),

    /// A response read found a different relay message.
    #[error("unexpected relay message while waiting for response id {}", expected_id.as_u64())]
    UnexpectedMessage {
        /// Response ID the caller was waiting for.
        expected_id: RelayRpcId,
        /// JSON message that arrived instead.
        value: Value,
    },
}

fn parse_json(text: &str) -> Result<Value, TransportError> {
    serde_json::from_str(text).map_err(|source| TransportError::Json { source })
}
