use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::Path,
    time::Duration,
};

use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use thiserror::Error;

use crate::{
    config::NativeRelayTransportConfig,
    limits::{RateLimit, RelayLimitsConfig},
    source::{IpPrefix, covered_family},
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
        "connection.max_incoming_frame_bytes ({frame}) must not exceed the u32 byte accounting limit (4294967295)"
    )]
    FrameAboveByteCounter { frame: usize },

    #[error(
        "{setting}.burst ({burst}) must be at least \
         connection.max_incoming_frame_bytes ({frame})"
    )]
    BurstBelowFrameCap {
        setting: &'static str,
        burst: u32,
        frame: u32,
    },

    #[error(
        "connection.outbound_queue_max_bytes ({bytes}) must be at least \
         connection.max_incoming_frame_bytes ({frame})"
    )]
    OutboundBytesBelowFrameCap { bytes: usize, frame: usize },

    #[error("limits.global_paired_reserve_percent ({0}) must be below 100")]
    ReserveTooLarge(u8),

    #[error(
        "limits.global_inbound_byte_rate.burst outside the paired reserve ({unreserved}) \
         must be at least connection.max_incoming_frame_bytes ({frame})"
    )]
    UnreservedBelowFrameCap { unreserved: u32, frame: u32 },

    #[error(
        "limits.inbound_wire_byte_rate ({wire_burst} bytes per {wire_seconds} s) must be at \
         least limits.inbound_byte_rate ({payload_burst} bytes per {payload_seconds} s), in \
         burst and in rate"
    )]
    WireRateBelowPayloadRate {
        wire_burst: u32,
        wire_seconds: u64,
        payload_burst: u32,
        payload_seconds: u64,
    },

    #[error(
        "application.trusted_proxies must not cover {0}: it would let every peer \
         name its own source"
    )]
    TrustsEveryPeer(IpPrefix),
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

    /// Peers allowed to name the client they forward in `X-Real-IP`, as
    /// addresses or `address/length` ranges. A list, or one comma-separated
    /// string so that an environment variable can set it. Empty when absent:
    /// the header is then ignored from every peer.
    #[serde(default, deserialize_with = "address_ranges")]
    pub trusted_proxies: Vec<IpPrefix>,
}

/// Read a list of address ranges, or one string of comma-separated ranges.
fn address_ranges<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpPrefix>, D::Error> {
    struct Ranges;

    impl<'de> Visitor<'de> for Ranges {
        type Value = Vec<IpPrefix>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list of address ranges, or a string of comma-separated ranges")
        }

        fn visit_str<E: de::Error>(self, joined: &str) -> Result<Self::Value, E> {
            joined
                .split(',')
                .filter(|range| !range.trim().is_empty())
                .map(|range| range.parse().map_err(E::custom))
                .collect()
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut ranges: A) -> Result<Self::Value, A::Error> {
            let mut parsed = Vec::new();
            while let Some(range) = ranges.next_element()? {
                parsed.push(range);
            }
            Ok(parsed)
        }
    }

    deserializer.deserialize_any(Ranges)
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

    /// Bytes of frames held for one peer and not yet written: its queue and
    /// backlog, or its buffer while it reconnects.
    pub outbound_queue_max_bytes: usize,

    /// Time a frame may wait in the outbound queue before its slow reader
    /// is dropped.
    pub outbound_queue_timeout_seconds: u64,

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

    /// Rate at which one connection's socket is read, framing, control
    /// frames and fragments included.
    pub inbound_wire_byte_rate: RateSettings,

    /// Inbound byte rate one identity may consume from the relay-wide budget.
    pub identity_inbound_byte_rate: RateSettings,

    /// Inbound byte rate the identities connecting from one address (an IPv6
    /// /64) may consume together from the relay-wide budget.
    pub source_inbound_byte_rate: RateSettings,

    /// Inbound byte rate across all connections.
    pub global_inbound_byte_rate: RateSettings,

    /// Percentage of the global burst only frames between two connected peers
    /// may spend.
    pub global_paired_reserve_percent: u8,
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
        if let Some(family) = covered_family(&self.application.trusted_proxies) {
            return Err(ConfigurationError::TrustsEveryPeer(family));
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
                "connection.outbound_queue_timeout_seconds",
                self.connection.outbound_queue_timeout_seconds,
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
            (
                "connection.outbound_queue_max_bytes",
                self.connection.outbound_queue_max_bytes,
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
                "limits.inbound_wire_byte_rate",
                &self.limits.inbound_wire_byte_rate,
            ),
            (
                "limits.identity_inbound_byte_rate",
                &self.limits.identity_inbound_byte_rate,
            ),
            (
                "limits.source_inbound_byte_rate",
                &self.limits.source_inbound_byte_rate,
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
        if self.limits.global_paired_reserve_percent >= 100 {
            return Err(ConfigurationError::ReserveTooLarge(
                self.limits.global_paired_reserve_percent,
            ));
        }

        // The relay re-encodes a frame no longer than the text it arrived as,
        // so a budget that holds the largest incoming frame can queue any
        // frame the relay accepts.
        if self.connection.outbound_queue_max_bytes < self.connection.max_incoming_frame_bytes {
            return Err(ConfigurationError::OutboundBytesBelowFrameCap {
                bytes: self.connection.outbound_queue_max_bytes,
                frame: self.connection.max_incoming_frame_bytes,
            });
        }

        let frame = self.connection.max_incoming_frame_bytes;
        let frame = u32::try_from(frame)
            .map_err(|_| ConfigurationError::FrameAboveByteCounter { frame })?;
        for (setting, burst) in [
            (
                "limits.identity_inbound_byte_rate",
                self.limits.identity_inbound_byte_rate.burst,
            ),
            (
                "limits.source_inbound_byte_rate",
                self.limits.source_inbound_byte_rate.burst,
            ),
            (
                "limits.inbound_byte_rate",
                self.limits.inbound_byte_rate.burst,
            ),
            // A frame larger than this burst would still be read, only
            // throttled part-way through.
            (
                "limits.inbound_wire_byte_rate",
                self.limits.inbound_wire_byte_rate.burst,
            ),
            (
                "limits.global_inbound_byte_rate",
                self.limits.global_inbound_byte_rate.burst,
            ),
        ] {
            if burst < frame {
                return Err(ConfigurationError::BurstBelowFrameCap {
                    setting,
                    burst,
                    frame,
                });
            }
        }
        // Every payload byte crosses the wire too, framing on top: a wire
        // budget below the payload budget would throttle the reads, pongs
        // included, of a peer within its limits. Rates are compared over the
        // product of the two intervals.
        let wire = &self.limits.inbound_wire_byte_rate;
        let payload = &self.limits.inbound_byte_rate;
        let wire_bytes = u128::from(wire.burst) * u128::from(payload.interval_seconds);
        let payload_bytes = u128::from(payload.burst) * u128::from(wire.interval_seconds);
        if wire.burst < payload.burst || wire_bytes < payload_bytes {
            return Err(ConfigurationError::WireRateBelowPayloadRate {
                wire_burst: wire.burst,
                wire_seconds: wire.interval_seconds,
                payload_burst: payload.burst,
                payload_seconds: payload.interval_seconds,
            });
        }
        // Frames buffered for a reconnecting peer cannot spend the reserve,
        // so what is left of the burst must still hold a whole frame.
        let limits = RelayLimitsConfig::from(self);
        let unreserved = limits
            .global_inbound_byte_rate
            .burst
            .saturating_sub(limits.paired_reserve_bytes());
        if unreserved < frame {
            return Err(ConfigurationError::UnreservedBelowFrameCap { unreserved, frame });
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
            outbound_queue_max_bytes: settings.connection.outbound_queue_max_bytes,
            outbound_queue_timeout: Duration::from_secs(
                settings.connection.outbound_queue_timeout_seconds,
            ),
            max_token_lifetime: Duration::from_secs(settings.auth.max_token_lifetime_seconds),
            trusted_proxies: settings.application.trusted_proxies.clone().into(),
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
            inbound_wire_byte_rate: (&settings.limits.inbound_wire_byte_rate).into(),
            identity_inbound_byte_rate: (&settings.limits.identity_inbound_byte_rate).into(),
            source_inbound_byte_rate: (&settings.limits.source_inbound_byte_rate).into(),
            global_inbound_byte_rate: (&settings.limits.global_inbound_byte_rate).into(),
            global_paired_reserve_percent: settings.limits.global_paired_reserve_percent,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DEFAULT_OUTBOUND_QUEUE_MAX_BYTES, DEFAULT_OUTBOUND_QUEUE_TIMEOUT};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The shipped `base.yaml` with the local overlay, without environment
    /// overrides.
    fn shipped() -> Result<Settings, ConfigurationError> {
        let settings = config::Config::builder()
            .add_source(config::File::from_str(
                include_str!("../configuration/base.yaml"),
                config::FileFormat::Yaml,
            ))
            .add_source(config::File::from_str(
                include_str!("../configuration/local.yaml"),
                config::FileFormat::Yaml,
            ))
            .build()?
            .try_deserialize::<Settings>()?;
        Ok(settings)
    }

    #[test]
    fn shipped_outbound_defaults_are_valid_and_match_the_transport() -> TestResult {
        let settings = shipped()?;
        settings.validate()?;

        let transport = NativeRelayTransportConfig::from(&settings);
        assert_eq!(
            transport.outbound_queue_max_bytes,
            DEFAULT_OUTBOUND_QUEUE_MAX_BYTES
        );
        assert_eq!(
            transport.outbound_queue_timeout,
            DEFAULT_OUTBOUND_QUEUE_TIMEOUT
        );
        Ok(())
    }

    #[test]
    fn outbound_budget_below_the_frame_cap_is_rejected() -> TestResult {
        let mut settings = shipped()?;
        let frame = settings.connection.max_incoming_frame_bytes;

        settings.connection.outbound_queue_max_bytes = frame - 1;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::OutboundBytesBelowFrameCap { .. })
        ));

        settings.connection.outbound_queue_max_bytes = frame;
        settings.validate()?;
        Ok(())
    }

    /// The deployment templates, with the placeholders the container
    /// entrypoint substitutes filled in.
    fn deployed() -> Result<Settings, ConfigurationError> {
        let render = |template: &str| {
            template
                .replace("${RELAY_PORT}", "8080")
                .replace("${HEALTH_PORT}", "8081")
                .replace("${APPLICATION_AUDIENCE}", "wss://relay.example.com")
                .replace("${MAX_TOKEN_LIFETIME_SECONDS}", "600")
        };
        let base = include_str!("../../../deployment/configs/relay/base.yaml.template");
        let production = include_str!("../../../deployment/configs/relay/production.yaml.template");
        let settings = config::Config::builder()
            .add_source(config::File::from_str(
                &render(base),
                config::FileFormat::Yaml,
            ))
            .add_source(config::File::from_str(
                &render(production),
                config::FileFormat::Yaml,
            ))
            .build()?
            .try_deserialize::<Settings>()?;
        Ok(settings)
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    #[test]
    fn shipped_fairness_defaults_match_the_limiter_and_trust_no_proxy() -> TestResult {
        let settings = shipped()?;
        settings.validate()?;

        let limits = RelayLimitsConfig::from(&settings);
        assert_eq!(limits, RelayLimitsConfig::default());
        assert!(
            limits.source_inbound_byte_rate.burst <= limits.identity_inbound_byte_rate.burst,
            "a source's share must default to no more than an identity's"
        );
        assert!(settings.application.trusted_proxies.is_empty());
        assert!(
            NativeRelayTransportConfig::from(&settings)
                .trusted_proxies
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn the_deployment_trusts_only_the_compose_network() -> TestResult {
        let deployed = deployed()?;
        deployed.validate()?;

        let shipped = shipped()?;
        assert_eq!(deployed.limits, shipped.limits);
        assert_eq!(deployed.connection, shipped.connection);
        assert_eq!(deployed.session, shipped.session);

        let trusted = &deployed.application.trusted_proxies;
        let trusts = |peer: &str| trusted.iter().any(|range| range.contains(ip(peer)));
        for nginx in ["172.18.0.3", "192.168.16.2", "10.10.0.5"] {
            assert!(trusts(nginx), "a compose network address {nginx} is nginx");
        }
        for client in ["203.0.113.9", "2001:db8::1", "127.0.0.1"] {
            assert!(!trusts(client), "{client} must not name its own source");
        }
        Ok(())
    }

    #[test]
    fn trusted_proxies_read_from_a_list_or_one_joined_string() -> TestResult {
        let with = |value: &str| -> Result<Settings, ConfigurationError> {
            Ok(config::Config::builder()
                .add_source(config::File::from_str(
                    include_str!("../configuration/base.yaml"),
                    config::FileFormat::Yaml,
                ))
                .add_source(config::File::from_str(
                    include_str!("../configuration/local.yaml"),
                    config::FileFormat::Yaml,
                ))
                .set_override("application.trusted_proxies", value)?
                .build()?
                .try_deserialize::<Settings>()?)
        };

        let settings = with("10.0.0.5, fd00::/8")?;
        assert_eq!(
            settings.application.trusted_proxies,
            ["10.0.0.5/32".parse::<IpPrefix>()?, "fd00::/8".parse()?]
        );
        assert!(with("")?.application.trusted_proxies.is_empty());
        assert!(
            with("10.0.0.0/33").is_err(),
            "an invalid range must fail the configuration, not be skipped"
        );
        Ok(())
    }

    #[test]
    fn fairness_settings_that_break_the_boundary_are_rejected() -> TestResult {
        let everyone: [&[&str]; 4] = [
            &["0.0.0.0/0"],
            &["::/0"],
            &["10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1"],
            &["::/1", "8000::/1"],
        ];
        for ranges in everyone {
            let mut settings = shipped()?;
            settings.application.trusted_proxies = ranges
                .iter()
                .map(|range| range.parse())
                .collect::<Result<_, _>>()?;
            assert!(
                matches!(
                    settings.validate(),
                    Err(ConfigurationError::TrustsEveryPeer(_))
                ),
                "{ranges:?} trusts every peer of a family"
            );
        }

        let mut settings = shipped()?;
        settings.limits.global_paired_reserve_percent = 100;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::ReserveTooLarge(100))
        ));

        // 1% of the shipped 16 MiB burst is less than one maximal frame.
        settings.limits.global_paired_reserve_percent = 99;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::UnreservedBelowFrameCap { .. })
        ));

        let mut settings = shipped()?;
        settings.limits.source_inbound_byte_rate.burst =
            u32::try_from(settings.connection.max_incoming_frame_bytes)? - 1;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::BurstBelowFrameCap {
                setting: "limits.source_inbound_byte_rate",
                ..
            })
        ));

        let mut settings = shipped()?;
        settings.limits.source_inbound_byte_rate.interval_seconds = 0;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::Zero {
                setting: "limits.source_inbound_byte_rate"
            })
        ));
        Ok(())
    }

    #[test]
    fn wire_rate_is_shipped_above_the_payload_rate_and_validated() -> TestResult {
        let settings = shipped()?;
        let limits = RelayLimitsConfig::from(&settings);
        assert!(
            limits.inbound_wire_byte_rate.burst > limits.inbound_byte_rate.burst
                && limits.inbound_wire_byte_rate.interval == limits.inbound_byte_rate.interval,
            "the wire rate must leave room for the framing of payloads within their rate"
        );
        assert_eq!(
            RelayLimitsConfig::from(&deployed()?).inbound_wire_byte_rate,
            limits.inbound_wire_byte_rate
        );

        let mut settings = shipped()?;
        settings.limits.inbound_wire_byte_rate.interval_seconds = 0;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::Zero {
                setting: "limits.inbound_wire_byte_rate"
            })
        ));

        let mut settings = shipped()?;
        settings.limits.inbound_wire_byte_rate.burst =
            u32::try_from(settings.connection.max_incoming_frame_bytes)? - 1;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::BurstBelowFrameCap {
                setting: "limits.inbound_wire_byte_rate",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn wire_rate_below_the_payload_rate_is_rejected() -> TestResult {
        let below = |burst: u32, interval_seconds: u64| -> Result<bool, ConfigurationError> {
            let mut settings = shipped()?;
            settings.limits.inbound_wire_byte_rate = RateSettings {
                burst,
                interval_seconds,
            };
            Ok(matches!(
                settings.validate(),
                Err(ConfigurationError::WireRateBelowPayloadRate { .. })
            ))
        };
        // The shipped payload rate: 512 KiB per 2 seconds.
        let payload = shipped()?.limits.inbound_byte_rate;
        assert_eq!((payload.burst, payload.interval_seconds), (512 * 1024, 2));

        assert!(below(512 * 1024 - 1, 2)?, "a smaller burst");
        assert!(below(1024 * 1024, 5)?, "a larger burst refilling slower");
        assert!(!below(512 * 1024, 2)?, "the payload rate itself");
        assert!(!below(1024 * 1024, 4)?, "a larger burst at the same rate");
        Ok(())
    }

    #[test]
    fn zero_outbound_budget_or_timeout_is_rejected() -> TestResult {
        let mut settings = shipped()?;
        settings.connection.outbound_queue_max_bytes = 0;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::Zero {
                setting: "connection.outbound_queue_max_bytes"
            })
        ));

        let mut settings = shipped()?;
        settings.connection.outbound_queue_timeout_seconds = 0;
        assert!(matches!(
            settings.validate(),
            Err(ConfigurationError::Zero {
                setting: "connection.outbound_queue_timeout_seconds"
            })
        ));
        Ok(())
    }
}
