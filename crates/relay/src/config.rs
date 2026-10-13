use std::time::Duration;

use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::auth::DEFAULT_MAX_TOKEN_LIFETIME;

/// Default maximum WebSocket text or binary frame size accepted from a client.
pub const DEFAULT_MAX_INCOMING_FRAME_BYTES: usize = 256 * 1024;

/// Default time a disconnected peer's slot is reserved for reconnection.
pub const DEFAULT_SESSION_GRACE: Duration = Duration::from_secs(10);

/// Default maximum frames buffered per disconnected peer.
pub const DEFAULT_SESSION_BUFFER_MAX_MESSAGES: usize = 256;

/// Default time a buffered frame remains deliverable.
pub const DEFAULT_SESSION_BUFFER_TTL: Duration = Duration::from_secs(60);

/// Default interval between relay keepalive pings.
pub const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(30);

/// Default time to wait for a pong after a keepalive ping.
pub const DEFAULT_PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum time without any inbound traffic before a peer is dropped.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Default maximum time for the WebSocket handshake to complete.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum time for a single outbound WebSocket write.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default number of frames queued for a connected peer.
pub const DEFAULT_OUTBOUND_QUEUE_CAPACITY: usize = 64;

/// Runtime limits for the relay connection handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRelayTransportConfig {
    /// Audience the relay expects in the auth token (`aud` claim).
    pub audience: String,

    /// Maximum incoming text or binary frame size before JSON parsing.
    pub max_incoming_frame_bytes: usize,

    /// Time a disconnected peer's slot is reserved for reconnection.
    pub session_grace: Duration,

    /// Maximum frames buffered per disconnected peer.
    pub session_buffer_max_messages: usize,

    /// How long a buffered frame remains deliverable.
    pub session_buffer_ttl: Duration,

    /// Interval between relay keepalive pings.
    pub ping_interval: Duration,

    /// Time to wait for a pong after a keepalive ping.
    pub pong_timeout: Duration,

    /// Maximum time without any inbound traffic before a peer is dropped.
    pub idle_timeout: Duration,

    /// Maximum time for the WebSocket handshake to complete.
    pub handshake_timeout: Duration,

    /// Maximum time for a single outbound WebSocket write.
    pub write_timeout: Duration,

    /// Maximum frames queued for a connected peer that is not reading.
    pub outbound_queue_capacity: usize,

    /// Maximum accepted lifetime of an auth token.
    pub max_token_lifetime: Duration,
}

impl NativeRelayTransportConfig {
    /// Build a config that expects `audience` in the auth token.
    pub fn new(audience: impl Into<String>) -> Self {
        Self {
            audience: audience.into(),
            max_incoming_frame_bytes: DEFAULT_MAX_INCOMING_FRAME_BYTES,
            session_grace: DEFAULT_SESSION_GRACE,
            session_buffer_max_messages: DEFAULT_SESSION_BUFFER_MAX_MESSAGES,
            session_buffer_ttl: DEFAULT_SESSION_BUFFER_TTL,
            ping_interval: DEFAULT_PING_INTERVAL,
            pong_timeout: DEFAULT_PONG_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            outbound_queue_capacity: DEFAULT_OUTBOUND_QUEUE_CAPACITY,
            max_token_lifetime: DEFAULT_MAX_TOKEN_LIFETIME,
        }
    }

    /// Set the maximum accepted incoming frame size.
    pub fn with_max_incoming_frame_bytes(mut self, max: usize) -> Self {
        self.max_incoming_frame_bytes = max;
        self
    }

    /// Set the reconnection grace window.
    pub fn with_session_grace(mut self, grace: Duration) -> Self {
        self.session_grace = grace;
        self
    }

    /// Set the per-peer buffer limit.
    pub fn with_session_buffer_max_messages(mut self, max: usize) -> Self {
        self.session_buffer_max_messages = max;
        self
    }

    /// Set the per-frame buffer TTL.
    pub fn with_session_buffer_ttl(mut self, ttl: Duration) -> Self {
        self.session_buffer_ttl = ttl;
        self
    }

    /// Set the keepalive ping interval.
    pub fn with_ping_interval(mut self, interval: Duration) -> Self {
        self.ping_interval = interval;
        self
    }

    /// Set the pong deadline after a keepalive ping.
    pub fn with_pong_timeout(mut self, timeout: Duration) -> Self {
        self.pong_timeout = timeout;
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set the WebSocket handshake timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Set the outbound write timeout.
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Set the per-connection outbound queue capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero: the connection handler builds its outbound
    /// channel from this value, and a zero-capacity channel cannot be created.
    pub fn with_outbound_queue_capacity(mut self, capacity: usize) -> Self {
        assert!(
            capacity > 0,
            "outbound queue capacity must be greater than zero"
        );
        self.outbound_queue_capacity = capacity;
        self
    }

    /// Set the maximum accepted auth-token lifetime.
    pub fn with_max_token_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_token_lifetime = lifetime;
        self
    }

    /// Get WebSocketConfig from this config.
    pub fn websocket_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .max_message_size(Some(self.max_incoming_frame_bytes))
            .max_frame_size(Some(self.max_incoming_frame_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "outbound queue capacity")]
    fn zero_outbound_queue_capacity_is_rejected() {
        let _ = NativeRelayTransportConfig::new("wss://relay.example.com")
            .with_outbound_queue_capacity(0);
    }
}
