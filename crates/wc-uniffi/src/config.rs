use std::{fmt, num::NonZeroUsize, time::Duration};

use wc_core::{RelayAuthSeed, SingleSessionClientConfig, SingleSessionRelayConfig};

use crate::{
    error::WcUniFfiError,
    util::{hex_32, i64_to_u64, i64_to_usize, invalid_input, non_empty},
};

/// Opaque `UniFFI` client configuration.
#[derive(uniffi::Object)]
pub struct WcClientConfig {
    project_id: String,
    relay_auth_seed_hex: String,
    auth_subject: String,
    relay_url: Option<String>,
    user_agent: Option<String>,
    auth_ttl_seconds: Option<i64>,
    receive_timeout_ms: Option<i64>,
    max_queued_events: Option<i64>,
    automatic_reconnect_cooldown_ms: Option<i64>,
    receive_timeouts_before_reconnect: Option<i64>,
}

impl fmt::Debug for WcClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WcClientConfig")
            .field("project_id", &self.project_id)
            .field("relay_auth_seed_hex", &"<redacted>")
            .field("auth_subject", &self.auth_subject)
            .field("relay_url", &self.relay_url)
            .field("user_agent", &self.user_agent)
            .field("auth_ttl_seconds", &self.auth_ttl_seconds)
            .field("receive_timeout_ms", &self.receive_timeout_ms)
            .field("max_queued_events", &self.max_queued_events)
            .field(
                "automatic_reconnect_cooldown_ms",
                &self.automatic_reconnect_cooldown_ms,
            )
            .field(
                "receive_timeouts_before_reconnect",
                &self.receive_timeouts_before_reconnect,
            )
            .finish()
    }
}

#[uniffi::export]
impl WcClientConfig {
    /// Builds client configuration without exposing the relay seed as a generated data class field.
    #[uniffi::constructor]
    #[expect(
        clippy::too_many_arguments,
        reason = "UniFFI constructors use flat ABI parameters."
    )]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "UniFFI object constructors are exported as regular FFI functions."
    )]
    #[must_use]
    pub fn new(
        project_id: String,
        relay_auth_seed_hex: String,
        auth_subject: String,
        relay_url: Option<String>,
        user_agent: Option<String>,
        auth_ttl_seconds: Option<i64>,
        receive_timeout_ms: Option<i64>,
        max_queued_events: Option<i64>,
        automatic_reconnect_cooldown_ms: Option<i64>,
        receive_timeouts_before_reconnect: Option<i64>,
    ) -> Self {
        Self {
            project_id,
            relay_auth_seed_hex,
            auth_subject,
            relay_url,
            user_agent,
            auth_ttl_seconds,
            receive_timeout_ms,
            max_queued_events,
            automatic_reconnect_cooldown_ms,
            receive_timeouts_before_reconnect,
        }
    }
}

pub fn single_session_config(
    input: &WcClientConfig,
) -> Result<SingleSessionClientConfig, WcUniFfiError> {
    let seed = RelayAuthSeed::new(hex_32("relay_auth_seed_hex", &input.relay_auth_seed_hex)?);
    let mut pairing = SingleSessionRelayConfig::new(
        non_empty("project_id", input.project_id.clone())?,
        seed,
        non_empty("auth_subject", input.auth_subject.clone())?,
    );
    if let Some(relay_url) = &input.relay_url {
        pairing.relay_url = non_empty("relay_url", relay_url.clone())?;
    }
    if let Some(user_agent) = &input.user_agent {
        pairing.user_agent = non_empty("user_agent", user_agent.clone())?;
    }
    if let Some(ttl) = input.auth_ttl_seconds {
        pairing.auth_ttl_seconds = i64_to_u64("auth_ttl_seconds", ttl)?;
    }
    if let Some(timeout_ms) = input.receive_timeout_ms {
        pairing.receive_timeout =
            Duration::from_millis(i64_to_u64("receive_timeout_ms", timeout_ms)?);
    }

    let mut client_config = SingleSessionClientConfig::new(pairing);
    if let Some(max_queued_events) = input.max_queued_events {
        client_config = client_config
            .with_max_queued_events(i64_to_usize("max_queued_events", max_queued_events)?);
    }
    if let Some(cooldown_ms) = input.automatic_reconnect_cooldown_ms {
        let cooldown =
            Duration::from_millis(i64_to_u64("automatic_reconnect_cooldown_ms", cooldown_ms)?);
        if cooldown.is_zero() {
            return Err(invalid_input(
                "automatic_reconnect_cooldown_ms must be non-zero",
            ));
        }
        client_config = client_config.with_automatic_reconnect_cooldown(cooldown);
    }
    if let Some(count) = input.receive_timeouts_before_reconnect {
        client_config = client_config.with_receive_timeouts_before_reconnect(
            NonZeroUsize::new(i64_to_usize("receive_timeouts_before_reconnect", count)?)
                .ok_or_else(|| {
                    invalid_input("receive_timeouts_before_reconnect must be non-zero")
                })?,
        );
    }
    Ok(client_config)
}
