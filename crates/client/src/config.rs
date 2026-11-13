use std::time::Duration;

use url::Url;

use crate::error::ClientError;

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relay WebSocket endpoint used to connect and advertised in pairing URIs.
    pub relay_url: String,

    /// Audience (`aud`) expected by the relay in the connection token.
    pub audience: String,

    /// Optional registration id sent to the relay as an attribution label.
    pub registration_id: Option<String>,

    /// Allow `ws://` relay URLs. Without this, only `wss://` is accepted.
    pub allow_insecure_ws: bool,

    /// Lifetime of the signed connection token.
    pub token_ttl: Duration,

    /// Maximum time without an inbound frame before the relay is considered dead.
    pub idle_timeout: Duration,

    /// Maximum time to establish the WebSocket connection.
    pub connect_timeout: Duration,

    /// Maximum time for a single WebSocket write.
    pub write_timeout: Duration,

    /// Maximum time to send a close frame and close the socket.
    pub close_timeout: Duration,

    /// Base delay before the first retransmission of an un-ACKed message.
    pub ack_base_delay: Duration,

    /// Maximum retransmissions before a message is reported failed.
    pub ack_max_attempts: usize,

    /// Interval between client keepalive pings.
    pub ping_interval: Duration,

    /// How long to wait for a pong before treating the connection as dead.
    pub pong_timeout: Duration,

    /// Initial delay before the first reconnect attempt.
    pub reconnect_initial_delay: Duration,

    /// Maximum reconnect backoff delay.
    pub reconnect_max_delay: Duration,

    /// Maximum reconnect attempts before giving up.
    pub reconnect_max_attempts: usize,
}

impl ClientConfig {
    /// Build a config whose token audience is the same as the relay URL.
    pub fn new(relay_url: impl Into<String>) -> Self {
        let relay_url = relay_url.into();
        Self {
            audience: relay_url.clone(),
            relay_url,
            registration_id: None,
            allow_insecure_ws: false,
            token_ttl: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            close_timeout: Duration::from_secs(2),
            ack_base_delay: Duration::from_secs(2),
            ack_max_attempts: 5,
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            reconnect_initial_delay: Duration::from_millis(250),
            reconnect_max_delay: Duration::from_secs(5),
            reconnect_max_attempts: 5,
        }
    }

    /// Set the registration id sent to the relay.
    pub fn with_registration_id(mut self, registration_id: impl Into<String>) -> Self {
        self.registration_id = Some(registration_id.into());
        self
    }

    /// Allow an insecure `ws://` relay URL.
    pub fn with_insecure_ws(mut self) -> Self {
        self.allow_insecure_ws = true;
        self
    }

    /// Validate the configuration before starting a client.
    pub fn validate(&self) -> Result<(), ClientError> {
        let url = Url::parse(&self.relay_url)
            .map_err(|_| ClientError::InvalidConfig("invalid relay URL"))?;
        match url.scheme() {
            "wss" => {}
            "ws" if self.allow_insecure_ws => {}
            "ws" => {
                return Err(ClientError::InvalidConfig(
                    "ws:// relay URL requires explicit opt-in",
                ));
            }
            _ => {
                return Err(ClientError::InvalidConfig(
                    "relay URL must use ws:// or wss://",
                ));
            }
        }

        for (timeout, name) in [
            (self.idle_timeout, "idle_timeout"),
            (self.connect_timeout, "connect_timeout"),
            (self.write_timeout, "write_timeout"),
            (self.close_timeout, "close_timeout"),
            (self.ping_interval, "ping_interval"),
            (self.pong_timeout, "pong_timeout"),
        ] {
            if timeout.is_zero() {
                return Err(ClientError::InvalidConfig(name));
            }
        }

        Ok(())
    }

    /// Set the audience expected by the relay, when it differs from `relay_url`.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Set the connection token lifetime.
    pub fn with_token_ttl(mut self, token_ttl: Duration) -> Self {
        self.token_ttl = token_ttl;
        self
    }

    /// Set the inbound idle timeout.
    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = idle_timeout;
        self
    }

    /// Set the WebSocket connect timeout.
    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    /// Set the WebSocket write timeout.
    pub fn with_write_timeout(mut self, write_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self
    }

    /// Set the WebSocket close timeout.
    pub fn with_close_timeout(mut self, close_timeout: Duration) -> Self {
        self.close_timeout = close_timeout;
        self
    }

    /// Set the base retransmission delay.
    pub fn with_ack_base_delay(mut self, ack_base_delay: Duration) -> Self {
        self.ack_base_delay = ack_base_delay;
        self
    }

    /// Set the maximum retransmission attempts.
    pub fn with_ack_max_attempts(mut self, ack_max_attempts: usize) -> Self {
        self.ack_max_attempts = ack_max_attempts;
        self
    }

    /// Set the keepalive ping interval.
    pub fn with_ping_interval(mut self, ping_interval: Duration) -> Self {
        self.ping_interval = ping_interval;
        self
    }

    /// Set the pong deadline.
    pub fn with_pong_timeout(mut self, pong_timeout: Duration) -> Self {
        self.pong_timeout = pong_timeout;
        self
    }

    /// Set the initial reconnect delay.
    pub fn with_reconnect_initial_delay(mut self, delay: Duration) -> Self {
        self.reconnect_initial_delay = delay;
        self
    }

    /// Set the maximum reconnect backoff delay.
    pub fn with_reconnect_max_delay(mut self, delay: Duration) -> Self {
        self.reconnect_max_delay = delay;
        self
    }

    /// Set the maximum reconnect attempts.
    pub fn with_reconnect_max_attempts(mut self, attempts: usize) -> Self {
        self.reconnect_max_attempts = attempts;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_insecure_ws_without_opt_in() {
        let config = ClientConfig::new("ws://127.0.0.1:8080");
        assert!(matches!(
            config.validate(),
            Err(ClientError::InvalidConfig(
                "ws:// relay URL requires explicit opt-in"
            ))
        ));
        assert!(config.with_insecure_ws().validate().is_ok());
    }

    #[test]
    fn requires_websocket_urls() {
        assert!(matches!(
            ClientConfig::new("https://relay.example.com").validate(),
            Err(ClientError::InvalidConfig(
                "relay URL must use ws:// or wss://"
            ))
        ));
        assert!(
            ClientConfig::new("wss://relay.example.com")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn rejects_zero_transport_timeouts() {
        for config in [
            ClientConfig::new("wss://relay.example.com").with_idle_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_connect_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_write_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_close_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_ping_interval(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_pong_timeout(Duration::ZERO),
        ] {
            assert!(matches!(
                config.validate(),
                Err(ClientError::InvalidConfig(_))
            ));
        }
    }
}
