use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

use serde::Deserialize;
use thiserror::Error;

use crate::{
    config::NativeRelayTransportConfig,
    limits::{RateLimit, RelayLimitsConfig},
};

pub const CONFIGURATION_DIRECTORY: &str = "configuration";

pub const ENVIRONMENT_VARIABLE: &str = "APP_ENVIRONMENT";

pub const DEFAULT_ENVIRONMENT: &str = "local";

/// Failures reading or validating the relay configuration.
#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error("{setting} must not be empty")]
    Empty { setting: &'static str },

    #[error("{setting} must be greater than zero")]
    Zero { setting: &'static str },

    #[error("health and application must not share an address, both are {0}")]
    AddressCollision(SocketAddr),

    #[error(
        "limits.identity_inbound_byte_rate.burst ({share}) must be at least \
         connection.max_incoming_frame_bytes ({frame})"
    )]
    ShareBelowFrameCap { share: u32, frame: usize },
}

/// Relay settings.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub application: ApplicationSettings,
    pub health: HealthSettings,
    pub auth: AuthSettings,
    pub session: SessionSettings,
    pub connection: ConnectionSettings,
    pub limits: LimitsSettings,
}

/// WebSocket listener and token audience.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ApplicationSettings {
    /// Interface to accept relay connections on.
    pub host: IpAddr,

    /// Port to accept relay connections on.
    pub port: u16,

    /// Audience expected in connection tokens (`aud`).
    pub audience: String,
}

/// HTTP listener used by probes.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HealthSettings {
    /// Interface to serve health probes on.
    pub host: IpAddr,

    /// Port to serve health probes on.
    pub port: u16,
}

/// Connection token limits.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AuthSettings {
    /// Longest lifetime a connection token may have left when it is presented.
    pub max_token_lifetime_seconds: u64,
}

/// Reconnection buffering.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SessionSettings {
    /// Time a disconnected peer's slot is reserved for reconnection.
    pub grace_seconds: u64,

    /// Frames buffered per disconnected peer.
    pub buffer_max_messages: usize,

    /// How long a buffered frame remains deliverable.
    pub buffer_ttl_seconds: u64,
}

/// Per-connection transport limits.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ConnectionSettings {
    /// Largest incoming WebSocket frame accepted.
    pub max_incoming_frame_bytes: usize,

    /// Time allowed for the WebSocket handshake.
    pub handshake_timeout_seconds: u64,

    /// Time allowed for a single outbound write.
    pub write_timeout_seconds: u64,

    /// Frames queued for a connected peer that is not reading.
    pub outbound_queue_capacity: usize,

    /// Interval between relay keepalive pings.
    pub ping_interval_seconds: u64,

    /// Time to wait for a pong after a keepalive ping.
    pub pong_timeout_seconds: u64,

    /// Time without any inbound traffic before a peer is dropped.
    pub idle_timeout_seconds: u64,
}

/// Relay-wide resource limits.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LimitsSettings {
    /// Maximum concurrent connections across all identities.
    pub max_connections: usize,

    /// Maximum concurrent connections per identity.
    pub max_connections_per_identity: usize,

    /// Maximum concurrent sessions (topics).
    pub max_sessions: usize,

    /// Connection attempt rate per identity.
    pub connect_rate: RateSettings,

    /// Inbound message rate per connection.
    pub inbound_message_rate: RateSettings,

    /// Inbound byte rate per connection.
    pub inbound_byte_rate: RateSettings,

    /// Inbound byte rate one identity may consume from the relay-wide budget.
    pub identity_inbound_byte_rate: RateSettings,

    /// Inbound byte rate across all connections.
    pub global_inbound_byte_rate: RateSettings,
}

/// Token bucket parameters.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RateSettings {
    /// Maximum cost available at once.
    pub burst: u32,

    /// Interval over which the burst refills.
    pub interval_seconds: u64,
}

impl Settings {
    /// Address the WebSocket listener binds to.
    pub fn application_address(&self) -> SocketAddr {
        SocketAddr::new(self.application.host, self.application.port)
    }

    /// Address the health listener binds to.
    pub fn health_address(&self) -> SocketAddr {
        SocketAddr::new(self.health.host, self.health.port)
    }

    /// Fail on settings that would make the relay unusable.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.application.audience.trim().is_empty() {
            return Err(ConfigurationError::Empty {
                setting: "application.audience",
            });
        }
        if self.application_address() == self.health_address() {
            return Err(ConfigurationError::AddressCollision(
                self.application_address(),
            ));
        }

        for (setting, value) in [
            (
                "auth.max_token_lifetime_seconds",
                self.auth.max_token_lifetime_seconds,
            ),
            ("session.grace_seconds", self.session.grace_seconds),
            (
                "session.buffer_ttl_seconds",
                self.session.buffer_ttl_seconds,
            ),
            (
                "connection.handshake_timeout_seconds",
                self.connection.handshake_timeout_seconds,
            ),
            (
                "connection.write_timeout_seconds",
                self.connection.write_timeout_seconds,
            ),
            (
                "connection.ping_interval_seconds",
                self.connection.ping_interval_seconds,
            ),
            (
                "connection.pong_timeout_seconds",
                self.connection.pong_timeout_seconds,
            ),
            (
                "connection.idle_timeout_seconds",
                self.connection.idle_timeout_seconds,
            ),
        ] {
            if value == 0 {
                return Err(ConfigurationError::Zero { setting });
            }
        }

        for (setting, value) in [
            (
                "session.buffer_max_messages",
                self.session.buffer_max_messages,
            ),
            (
                "connection.max_incoming_frame_bytes",
                self.connection.max_incoming_frame_bytes,
            ),
            (
                "connection.outbound_queue_capacity",
                self.connection.outbound_queue_capacity,
            ),
            ("limits.max_connections", self.limits.max_connections),
            (
                "limits.max_connections_per_identity",
                self.limits.max_connections_per_identity,
            ),
            ("limits.max_sessions", self.limits.max_sessions),
        ] {
            if value == 0 {
                return Err(ConfigurationError::Zero { setting });
            }
        }

        for (setting, rate) in [
            ("limits.connect_rate", &self.limits.connect_rate),
            (
                "limits.inbound_message_rate",
                &self.limits.inbound_message_rate,
            ),
            ("limits.inbound_byte_rate", &self.limits.inbound_byte_rate),
            (
                "limits.identity_inbound_byte_rate",
                &self.limits.identity_inbound_byte_rate,
            ),
            (
                "limits.global_inbound_byte_rate",
                &self.limits.global_inbound_byte_rate,
            ),
        ] {
            if rate.burst == 0 || rate.interval_seconds == 0 {
                return Err(ConfigurationError::Zero { setting });
            }
        }

        if u32::try_from(self.connection.max_incoming_frame_bytes)
            .is_ok_and(|frame| self.limits.identity_inbound_byte_rate.burst < frame)
        {
            return Err(ConfigurationError::ShareBelowFrameCap {
                share: self.limits.identity_inbound_byte_rate.burst,
                frame: self.connection.max_incoming_frame_bytes,
            });
        }

        Ok(())
    }

    pub fn get_configuration() -> Result<Settings, ConfigurationError> {
        let directory = Path::new(CONFIGURATION_DIRECTORY);
        let environment =
            std::env::var(ENVIRONMENT_VARIABLE).unwrap_or_else(|_| DEFAULT_ENVIRONMENT.to_owned());

        Self::get_configuration_from(directory, &environment)
    }

    pub fn get_configuration_from(
        directory: &Path,
        environment: &str,
    ) -> Result<Settings, ConfigurationError> {
        let settings = config::Config::builder()
            .add_source(config::File::from(directory.join("base.yaml")))
            .add_source(config::File::from(
                directory.join(format!("{environment}.yaml")),
            ))
            .add_source(config::Environment::default().separator("__"))
            .build()?
            .try_deserialize::<Settings>()?;

        settings.validate()?;
        Ok(settings)
    }
}

impl From<&Settings> for NativeRelayTransportConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            audience: settings.application.audience.clone(),
            max_incoming_frame_bytes: settings.connection.max_incoming_frame_bytes,
            session_grace: Duration::from_secs(settings.session.grace_seconds),
            session_buffer_max_messages: settings.session.buffer_max_messages,
            session_buffer_ttl: Duration::from_secs(settings.session.buffer_ttl_seconds),
            ping_interval: Duration::from_secs(settings.connection.ping_interval_seconds),
            pong_timeout: Duration::from_secs(settings.connection.pong_timeout_seconds),
            idle_timeout: Duration::from_secs(settings.connection.idle_timeout_seconds),
            handshake_timeout: Duration::from_secs(settings.connection.handshake_timeout_seconds),
            write_timeout: Duration::from_secs(settings.connection.write_timeout_seconds),
            outbound_queue_capacity: settings.connection.outbound_queue_capacity,
            max_token_lifetime: Duration::from_secs(settings.auth.max_token_lifetime_seconds),
        }
    }
}

impl From<&Settings> for RelayLimitsConfig {
    fn from(settings: &Settings) -> Self {
        Self {
            max_connections: settings.limits.max_connections,
            max_connections_per_identity: settings.limits.max_connections_per_identity,
            max_sessions: settings.limits.max_sessions,
            connect_rate: (&settings.limits.connect_rate).into(),
            inbound_message_rate: (&settings.limits.inbound_message_rate).into(),
            inbound_byte_rate: (&settings.limits.inbound_byte_rate).into(),
            identity_inbound_byte_rate: (&settings.limits.identity_inbound_byte_rate).into(),
            global_inbound_byte_rate: (&settings.limits.global_inbound_byte_rate).into(),
        }
    }
}

impl From<&RateSettings> for RateLimit {
    fn from(settings: &RateSettings) -> Self {
        Self {
            burst: settings.burst,
            interval: Duration::from_secs(settings.interval_seconds),
        }
    }
}
