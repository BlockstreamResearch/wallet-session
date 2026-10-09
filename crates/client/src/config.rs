use std::time::Duration;

/// Client configuration.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Relay WebSocket endpoint used to connect and advertised in pairing URIs.
    pub relay_url: String,

    /// Audience (`aud`) expected by the relay in the connection token.
    pub audience: String,

    /// Registration id; required when connecting as the proposer.
    pub registration_id: Option<String>,

    /// Lifetime of the signed connection token.
    pub token_ttl: Duration,

    /// Maximum time without an inbound frame before the relay is considered dead.
    pub idle_timeout: Duration,

    /// Base delay before the first retransmission of an un-ACKed message.
    pub ack_base_delay: Duration,

    /// Maximum retransmissions before a message is reported failed.
    pub ack_max_attempts: usize,

    /// How long an inbound envelope id is remembered for duplicate suppression.
    pub seen_ttl: Duration,

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
            token_ttl: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(60),
            ack_base_delay: Duration::from_secs(2),
            ack_max_attempts: 5,
            seen_ttl: Duration::from_secs(300),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            reconnect_initial_delay: Duration::from_millis(250),
            reconnect_max_delay: Duration::from_secs(5),
            reconnect_max_attempts: 5,
        }
    }

    /// Set the registration id used when connecting as the proposer.
    pub fn with_registration_id(mut self, registration_id: impl Into<String>) -> Self {
        self.registration_id = Some(registration_id.into());
        self
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

    /// Set the duplicate-suppression TTL.
    pub fn with_seen_ttl(mut self, seen_ttl: Duration) -> Self {
        self.seen_ttl = seen_ttl;
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
