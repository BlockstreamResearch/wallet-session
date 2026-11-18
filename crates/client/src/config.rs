use std::time::Duration;

use url::Url;

use crate::error::ClientError;

/// Longest accepted retransmission delay.
///
/// Receivers reject envelopes once their `ts` is more than 300 seconds old, so
/// a longer delay cannot produce a useful retry. The cap also keeps retry
/// arithmetic away from `Duration` and `Instant` overflow.
pub(crate) const MAX_RETRY_DELAY: Duration = Duration::from_secs(300);

/// Longest accepted transport timeout or interval.
///
/// Deadlines are computed as `Instant::now() + duration`, which panics on
/// overflow. A day is far longer than any of these needs to be.
const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

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

    /// Lifetime of the signed connection token. Must be at least one second,
    /// and leave room for `connection_stability` (see there).
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
    /// Must be non-zero and no longer than the 300-second envelope lifetime.
    pub ack_base_delay: Duration,

    /// Maximum retransmissions before a message is reported failed.
    pub ack_max_attempts: usize,

    /// Minimum spacing between retransmissions. Must be non-zero and no
    /// longer than the 300-second envelope lifetime.
    pub retransmit_spacing: Duration,

    /// Maximum retransmission bytes per second used to pace reconnects.
    pub retransmit_bytes_per_second: usize,

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

    /// How long a connection must stay up before it resets the reconnect budget.
    ///
    /// A connection waiting for its counterpart may never see `session_ready`,
    /// but it is still healthy and should not exhaust its retries on token
    /// expiry or ordinary network drops.
    ///
    /// Must be non-zero, and together with `connect_timeout` shorter than
    /// the lifetime a token is sure to have: the whole seconds of
    /// `token_ttl`, less one, since tokens carry truncated whole-second `iat`
    /// and `exp`. The token is signed before we connect, so the connect
    /// itself uses up part of that lifetime. Otherwise a token expiry can
    /// arrive before a connection is considered stable, and every routine
    /// token renewal spends a reconnect attempt.
    pub connection_stability: Duration,

    /// How long a responder keeps a session link that the proposer has not
    /// joined, counted from the end of the handshake retry window that starts
    /// when it sends `approve`. When it expires the client closes with
    /// [`ClientError::SessionNotEstablished`].
    pub session_join_timeout: Duration,
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
            retransmit_spacing: Duration::from_millis(100),
            retransmit_bytes_per_second: 256 * 1024,
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
            reconnect_initial_delay: Duration::from_millis(250),
            reconnect_max_delay: Duration::from_secs(5),
            reconnect_max_attempts: 5,
            connection_stability: Duration::from_secs(30),
            session_join_timeout: Duration::from_secs(30),
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
            (self.token_ttl, "token_ttl"),
            (self.idle_timeout, "idle_timeout"),
            (self.connect_timeout, "connect_timeout"),
            (self.write_timeout, "write_timeout"),
            (self.close_timeout, "close_timeout"),
            (self.ack_base_delay, "ack_base_delay"),
            (self.retransmit_spacing, "retransmit_spacing"),
            (self.ping_interval, "ping_interval"),
            (self.pong_timeout, "pong_timeout"),
            (self.connection_stability, "connection_stability"),
            (self.session_join_timeout, "session_join_timeout"),
        ] {
            if timeout.is_zero() {
                return Err(ClientError::InvalidConfig(name));
            }
        }

        for (delay, name) in [
            (self.ack_base_delay, "ack_base_delay"),
            (self.retransmit_spacing, "retransmit_spacing"),
        ] {
            if delay > MAX_RETRY_DELAY {
                return Err(ClientError::InvalidConfig(name));
            }
        }

        for (timeout, name) in [
            (self.token_ttl, "token_ttl"),
            (self.idle_timeout, "idle_timeout"),
            (self.connect_timeout, "connect_timeout"),
            (self.write_timeout, "write_timeout"),
            (self.close_timeout, "close_timeout"),
            (self.ping_interval, "ping_interval"),
            (self.pong_timeout, "pong_timeout"),
            (self.connection_stability, "connection_stability"),
            (self.session_join_timeout, "session_join_timeout"),
            (self.reconnect_initial_delay, "reconnect_initial_delay"),
            (self.reconnect_max_delay, "reconnect_max_delay"),
        ] {
            if timeout > MAX_TIMEOUT {
                return Err(ClientError::InvalidConfig(name));
            }
        }

        // With no attempts, a frame dispatched while offline would be reported
        // failed on the next ready edge without ever being written.
        if self.ack_max_attempts == 0 {
            return Err(ClientError::InvalidConfig("ack_max_attempts"));
        }

        // Tokens carry whole-second `iat`/`exp`, so a shorter lifetime would
        // produce a token that is already expired.
        if self.token_ttl < Duration::from_secs(1) {
            return Err(ClientError::InvalidConfig(
                "token_ttl must be at least one second",
            ));
        }

        if self.reconnect_initial_delay > self.reconnect_max_delay {
            return Err(ClientError::InvalidConfig(
                "reconnect_initial_delay must not exceed reconnect_max_delay",
            ));
        }

        // `iat` is truncated to a whole second, so a token may already be up
        // to a second old when the relay accepts it, and it was signed before
        // the connect began. Both durations were bounded above.
        let token_lifetime = Duration::from_secs(self.token_ttl.as_secs() - 1);
        if self.connect_timeout + self.connection_stability >= token_lifetime {
            return Err(ClientError::InvalidConfig(
                "connect_timeout plus connection_stability must be shorter than token_ttl less one second",
            ));
        }

        if self.retransmit_bytes_per_second == 0 {
            return Err(ClientError::InvalidConfig("retransmit_bytes_per_second"));
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

    /// Set the minimum spacing between retransmissions.
    pub fn with_retransmit_spacing(mut self, retransmit_spacing: Duration) -> Self {
        self.retransmit_spacing = retransmit_spacing;
        self
    }

    /// Set the maximum retransmission byte rate.
    pub fn with_retransmit_bytes_per_second(mut self, bytes_per_second: usize) -> Self {
        self.retransmit_bytes_per_second = bytes_per_second;
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

    /// Set how long a connection must stay up to reset the reconnect budget.
    pub fn with_connection_stability(mut self, stability: Duration) -> Self {
        self.connection_stability = stability;
        self
    }

    /// Set how long an unjoined session link survives a failed `approve`.
    pub fn with_session_join_timeout(mut self, timeout: Duration) -> Self {
        self.session_join_timeout = timeout;
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
    fn rejects_timeouts_that_overflow_deadlines() {
        let huge = Duration::MAX;
        for config in [
            ClientConfig::new("wss://relay.example.com").with_idle_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_connect_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_write_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_close_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_ping_interval(huge),
            ClientConfig::new("wss://relay.example.com").with_pong_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_session_join_timeout(huge),
            ClientConfig::new("wss://relay.example.com").with_reconnect_initial_delay(huge),
            ClientConfig::new("wss://relay.example.com").with_reconnect_max_delay(huge),
            ClientConfig::new("wss://relay.example.com")
                .with_token_ttl(huge)
                .with_connection_stability(MAX_TIMEOUT),
        ] {
            assert!(
                matches!(config.validate(), Err(ClientError::InvalidConfig(_))),
                "{config:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_inconsistent_durations() {
        let config = ClientConfig::new("wss://relay.example.com");
        assert!(matches!(
            config
                .clone()
                .with_token_ttl(Duration::from_millis(500))
                .with_connection_stability(Duration::from_millis(100))
                .validate(),
            Err(ClientError::InvalidConfig(
                "token_ttl must be at least one second"
            ))
        ));
        assert!(matches!(
            config
                .with_reconnect_initial_delay(Duration::from_secs(10))
                .with_reconnect_max_delay(Duration::from_secs(5))
                .validate(),
            Err(ClientError::InvalidConfig(
                "reconnect_initial_delay must not exceed reconnect_max_delay"
            ))
        ));
    }

    #[test]
    fn requires_at_least_one_ack_attempt() {
        let config = ClientConfig::new("wss://relay.example.com");
        assert!(matches!(
            config.clone().with_ack_max_attempts(0).validate(),
            Err(ClientError::InvalidConfig("ack_max_attempts"))
        ));
        assert!(config.with_ack_max_attempts(1).validate().is_ok());
    }

    #[test]
    fn rejects_zero_transport_timeouts() {
        for config in [
            ClientConfig::new("wss://relay.example.com").with_token_ttl(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_idle_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_connect_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_write_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_close_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_ack_base_delay(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_ping_interval(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_pong_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_retransmit_spacing(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_connection_stability(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_session_join_timeout(Duration::ZERO),
            ClientConfig::new("wss://relay.example.com").with_retransmit_bytes_per_second(0),
        ] {
            assert!(matches!(
                config.validate(),
                Err(ClientError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn rejects_unbounded_retry_delays() {
        for delay in [MAX_RETRY_DELAY + Duration::from_secs(1), Duration::MAX] {
            assert!(matches!(
                ClientConfig::new("wss://relay.example.com")
                    .with_ack_base_delay(delay)
                    .validate(),
                Err(ClientError::InvalidConfig("ack_base_delay"))
            ));
            assert!(matches!(
                ClientConfig::new("wss://relay.example.com")
                    .with_retransmit_spacing(delay)
                    .validate(),
                Err(ClientError::InvalidConfig("retransmit_spacing"))
            ));
        }

        assert!(
            ClientConfig::new("wss://relay.example.com")
                .with_ack_base_delay(MAX_RETRY_DELAY)
                .with_retransmit_spacing(MAX_RETRY_DELAY)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn requires_stability_shorter_than_token_ttl() {
        // The default connect timeout is 10 s, and a 30 s token is sure of
        // 29 s.
        assert!(
            ClientConfig::new("wss://relay.example.com")
                .with_token_ttl(Duration::from_secs(30))
                .with_connection_stability(Duration::from_millis(18_999))
                .validate()
                .is_ok()
        );
        for stability in [
            Duration::from_secs(19),
            Duration::from_secs(29),
            Duration::from_secs(30),
        ] {
            assert!(matches!(
                ClientConfig::new("wss://relay.example.com")
                    .with_token_ttl(Duration::from_secs(30))
                    .with_connection_stability(stability)
                    .validate(),
                Err(ClientError::InvalidConfig(
                    "connect_timeout plus connection_stability must be shorter than token_ttl less one second"
                ))
            ));
        }
    }

    #[test]
    fn fractional_token_ttl_only_counts_whole_seconds() {
        // A 1.9 s token is issued for one whole second, and is not sure to
        // outlive the truncation of its `iat`, so no stability fits.
        assert!(matches!(
            ClientConfig::new("wss://relay.example.com")
                .with_token_ttl(Duration::from_millis(1_900))
                .with_connect_timeout(Duration::from_millis(100))
                .with_connection_stability(Duration::from_millis(100))
                .validate(),
            Err(ClientError::InvalidConfig(
                "connect_timeout plus connection_stability must be shorter than token_ttl less one second"
            ))
        ));
        // A 2.9 s token is sure of one second.
        let config = ClientConfig::new("wss://relay.example.com")
            .with_token_ttl(Duration::from_millis(2_900))
            .with_connect_timeout(Duration::from_millis(500));
        assert!(
            config
                .clone()
                .with_connection_stability(Duration::from_millis(499))
                .validate()
                .is_ok()
        );
        assert!(matches!(
            config
                .with_connection_stability(Duration::from_millis(500))
                .validate(),
            Err(ClientError::InvalidConfig(
                "connect_timeout plus connection_stability must be shorter than token_ttl less one second"
            ))
        ));
    }

    #[test]
    fn connect_time_counts_against_the_token_lifetime() {
        // A 4 s token is sure of 3 s.
        let config = ClientConfig::new("wss://relay.example.com")
            .with_token_ttl(Duration::from_secs(4))
            .with_connection_stability(Duration::from_secs(1));
        assert!(
            config
                .clone()
                .with_connect_timeout(Duration::from_millis(1_999))
                .validate()
                .is_ok()
        );
        for connect_timeout in [Duration::from_secs(2), Duration::from_secs(5)] {
            assert!(matches!(
                config
                    .clone()
                    .with_connect_timeout(connect_timeout)
                    .validate(),
                Err(ClientError::InvalidConfig(
                    "connect_timeout plus connection_stability must be shorter than token_ttl less one second"
                ))
            ));
        }
    }
}
