//! Pairing-topic receive behavior.

use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use tokio::time::timeout;
use wc_protocol::{
    pairing::{PairingSymKey, PairingUri, PairingUriError},
    pairing_message::{PairingMessage, PairingMessageError},
    relay::{
        DEFAULT_RELAY_URL, IrnSubscriptionData, RelayAuthError, RelayAuthToken, RelayConnectionUrl,
        RelayTopic, relay_auth_audience,
    },
};
use wc_transport::{RelayClient, RelayClientConfig, RelayClientError};

/// Default wait time for one live pairing-topic message.
pub const DEFAULT_PAIRING_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

/// Configuration for a native pairing-topic relay client.
///
/// The pairing receive path uses Relay Auth query parameters before opening the
/// WebSocket connection.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth#overview>
///
/// > WalletConnect expects an `Authorization: Bearer <signed jwt>` header when establishing the Websocket connection.
/// > Where websocket headers are not supported i.e. browsers, use the URL query param `?auth=<signed jwt>`.
///
/// # Examples
///
/// ```
/// use wc_core::{PairingClientConfig, DEFAULT_PAIRING_RECEIVE_TIMEOUT};
///
/// let config = PairingClientConfig::new("project-id", [7; 32], "client-subject");
///
/// assert_eq!(config.project_id, "project-id");
/// assert_eq!(config.receive_timeout, DEFAULT_PAIRING_RECEIVE_TIMEOUT);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingClientConfig {
    /// Reown/WalletConnect Cloud project ID used by the public relay.
    pub project_id: String,
    /// Relay WebSocket endpoint.
    pub relay_url: String,
    /// User-agent value placed in the relay connection URL.
    pub user_agent: String,
    /// Ed25519 seed used to sign the Relay Auth JWT.
    pub auth_seed: [u8; 32],
    /// Relay Auth JWT `sub` claim.
    pub auth_subject: String,
    /// Relay Auth JWT lifetime in seconds.
    pub auth_ttl_seconds: u64,
    /// Maximum time spent waiting for one live pairing message.
    pub receive_timeout: Duration,
    /// Runtime limits for the underlying relay client.
    pub relay_client: RelayClientConfig,
}

impl PairingClientConfig {
    /// Builds a config with the public relay URL and conservative runtime defaults.
    #[must_use]
    pub fn new(
        project_id: impl Into<String>,
        auth_seed: [u8; 32],
        auth_subject: impl Into<String>,
    ) -> Self {
        Self {
            project_id: project_id.into(),
            relay_url: DEFAULT_RELAY_URL.to_owned(),
            user_agent: "wc-2/rust-poc-0.1.0/macos/native".to_owned(),
            auth_seed,
            auth_subject: auth_subject.into(),
            auth_ttl_seconds: 86_400,
            receive_timeout: DEFAULT_PAIRING_RECEIVE_TIMEOUT,
            relay_client: RelayClientConfig::default(),
        }
    }
}

/// Native client for receiving encrypted messages on a pairing topic.
///
/// This is the first core behavior layer above the relay transport. It parses
/// and checks pairing metadata, fetches retained relay messages, subscribes to
/// the pairing topic, and decodes encrypted pairing-topic payloads.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionpropose>
///
/// > Used to propose a session through topic A. Requires a success response
/// > with associated data.
///
/// # Examples
///
/// ```no_run
/// use wc_core::{PairingClient, PairingClientConfig};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let mut client = PairingClient::connect(&PairingClientConfig::new(
///     "project-id",
///     [7; 32],
///     "client-subject",
/// ))
/// .await?;
///
/// assert_eq!(client.status(), 101);
/// # Ok(())
/// # }
/// ```
pub struct PairingClient {
    relay: RelayClient,
    receive_timeout: Duration,
}

impl PairingClient {
    /// Opens an authenticated relay connection for pairing-topic operations.
    pub async fn connect(config: &PairingClientConfig) -> Result<Self, PairingClientError> {
        let url = relay_connection_url(config, now_unix_seconds()?)?;
        let relay = RelayClient::connect_with_config(url.as_str(), config.relay_client.clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(Self {
            relay,
            receive_timeout: config.receive_timeout,
        })
    }

    /// HTTP status returned during the relay WebSocket upgrade.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.relay.status()
    }

    /// Fetches retained messages for a parsed pairing URI.
    ///
    /// Relay clients fetch before subscribing so messages published while a
    /// wallet was offline are not skipped.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#fetch-messages>
    ///
    /// > Used when a client wants to fetch all undelivered messages matching a single topic before subscribing.
    pub async fn fetch_pairing_messages(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<Vec<PairingReceivedMessage>, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let response = self
            .relay
            .fetch_messages(pairing.topic())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        response
            .messages
            .into_iter()
            .map(|data| decode_subscription_data(data, pairing.sym_key()))
            .collect()
    }

    /// Subscribes to the relay topic carried by a parsed pairing URI.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#subscribe>
    ///
    /// > Used when a client subscribes a given topic.
    pub async fn subscribe_pairing(
        &mut self,
        pairing: &PairingUri,
    ) -> Result<PairingSubscription, PairingClientError> {
        validate_pairing_not_expired(pairing, now_unix_seconds()?)?;
        let subscription_id = self
            .relay
            .subscribe(pairing.topic().clone())
            .await
            .map_err(|source| PairingClientError::Relay { source })?;

        Ok(PairingSubscription {
            topic: pairing.topic().clone(),
            sym_key: pairing.sym_key().clone(),
            subscription_id,
        })
    }

    /// Waits for one live message for a pairing subscription.
    ///
    /// The underlying relay client acknowledges relay pushes before returning
    /// them. This method then checks the topic and decrypts the `WalletConnect`
    /// envelope with the pairing symmetric key.
    pub async fn next_pairing_message(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<Option<PairingReceivedMessage>, PairingClientError> {
        let Some(subscription_data) = timeout(self.receive_timeout, self.relay.next_message())
            .await
            .map_err(|_| PairingClientError::ReceiveTimedOut {
                timeout: self.receive_timeout,
            })?
            .map_err(|source| PairingClientError::Relay { source })?
        else {
            return Ok(None);
        };

        if subscription_data.data.topic != subscription.topic {
            return Err(PairingClientError::UnexpectedTopic {
                expected: subscription.topic.clone(),
                actual: subscription_data.data.topic,
            });
        }

        decode_subscription_data(subscription_data.data, &subscription.sym_key).map(Some)
    }

    /// Unsubscribes the relay connection from a pairing topic.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#unsubscribe>
    ///
    /// > Used when a client unsubscribes a given topic.
    pub async fn unsubscribe_pairing(
        &mut self,
        subscription: &PairingSubscription,
    ) -> Result<bool, PairingClientError> {
        self.relay
            .unsubscribe(&subscription.topic, &subscription.subscription_id)
            .await
            .map_err(|source| PairingClientError::Relay { source })
    }
}

/// Active relay subscription for one pairing topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingSubscription {
    topic: RelayTopic,
    sym_key: PairingSymKey,
    subscription_id: String,
}

impl PairingSubscription {
    /// Pairing relay topic registered on the connection.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Subscription ID returned by `irn_subscribe`.
    #[must_use]
    pub fn subscription_id(&self) -> &str {
        &self.subscription_id
    }
}

/// Decrypted pairing-topic message plus relay delivery metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingReceivedMessage {
    topic: RelayTopic,
    encoded_message_len: usize,
    published_at: u64,
    tag: Option<u64>,
    message: PairingMessage,
}

impl PairingReceivedMessage {
    /// Relay topic that delivered this message.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Length of the encrypted relay message string before decoding.
    #[must_use]
    pub const fn encoded_message_len(&self) -> usize {
        self.encoded_message_len
    }

    /// Relay server publish timestamp in milliseconds.
    #[must_use]
    pub const fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Optional `WalletConnect` relay tag.
    #[must_use]
    pub const fn tag(&self) -> Option<u64> {
        self.tag
    }

    /// Decrypted and classified pairing-topic payload.
    #[must_use]
    pub const fn message(&self) -> &PairingMessage {
        &self.message
    }
}

/// Pairing receive failure.
#[derive(Debug, thiserror::Error)]
pub enum PairingClientError {
    /// The pairing URI was malformed.
    #[error("pairing URI failed")]
    PairingUri {
        /// Source pairing URI parser error.
        #[source]
        source: PairingUriError,
    },

    /// The pairing URI expired before it was used.
    #[error("pairing URI expired")]
    PairingExpired {
        /// Expiry timestamp from the pairing URI.
        expiry_timestamp: u64,
        /// Unix timestamp used for the comparison.
        now_unix_seconds: u64,
    },

    /// Relay Auth JWT construction failed.
    #[error("pairing relay auth failed")]
    RelayAuth {
        /// Source Relay Auth error.
        #[source]
        source: RelayAuthError,
    },

    /// System clock failed while building relay auth or checking expiry.
    #[error("pairing clock failed")]
    Clock {
        /// Source system time error.
        #[source]
        source: SystemTimeError,
    },

    /// Relay transport or relay JSON-RPC behavior failed.
    #[error("pairing relay failed")]
    Relay {
        /// Source relay client error.
        #[source]
        source: RelayClientError,
    },

    /// No live pairing message arrived before the configured timeout.
    #[error("pairing receive timed out after {timeout:?}")]
    ReceiveTimedOut {
        /// Configured live receive timeout.
        timeout: Duration,
    },

    /// Relay returned a message for a different topic than this subscription.
    #[error("pairing received unexpected topic")]
    UnexpectedTopic {
        /// Topic from the active pairing subscription.
        expected: RelayTopic,
        /// Topic delivered by the relay.
        actual: RelayTopic,
    },

    /// Relay message envelope decoding, decryption, or JSON parsing failed.
    #[error("pairing message failed")]
    PairingMessage {
        /// Source pairing message error.
        #[source]
        source: PairingMessageError,
    },
}

impl PairingClientError {
    /// Parses a pairing URI and preserves the parser as the error source.
    pub fn parse_pairing_uri(uri: &str) -> Result<PairingUri, Self> {
        PairingUri::parse(uri).map_err(|source| Self::PairingUri { source })
    }
}

/// Builds the authenticated relay URL at a specific unix timestamp.
///
/// Keeping timestamp injection here makes Relay Auth testable without sleeping
/// or mocking the system clock.
fn relay_connection_url(
    config: &PairingClientConfig,
    issued_at: u64,
) -> Result<RelayConnectionUrl, PairingClientError> {
    let audience = relay_auth_audience(&config.relay_url);
    let token = RelayAuthToken::sign_with_seed(
        &config.auth_seed,
        &config.auth_subject,
        audience,
        issued_at,
        config.auth_ttl_seconds,
    )
    .map_err(|source| PairingClientError::RelayAuth { source })?;

    Ok(RelayConnectionUrl::new(
        &config.relay_url,
        &config.project_id,
        token.as_str(),
        &config.user_agent,
    ))
}

/// Returns unix seconds for Relay Auth `iat` and pairing expiry comparisons.
///
/// Pairing URI expiry is defined as `expiryTimestamp`; Relay Auth JWTs also
/// carry unix-second `iat` and `exp` claims.
fn now_unix_seconds() -> Result<u64, PairingClientError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| PairingClientError::Clock { source })?
        .as_secs())
}

/// Rejects pairing URIs that cannot receive valid proposals anymore.
const fn validate_pairing_not_expired(
    pairing: &PairingUri,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    if let Some(expiry_timestamp) = pairing.expiry_timestamp()
        && expiry_timestamp <= now_unix_seconds
    {
        return Err(PairingClientError::PairingExpired {
            expiry_timestamp,
            now_unix_seconds,
        });
    }

    Ok(())
}

/// Converts one relay delivery record into a decrypted pairing message.
///
/// The relay only forwards an opaque string. Pairing-specific decoding starts
/// after topic routing has succeeded.
fn decode_subscription_data(
    data: IrnSubscriptionData,
    sym_key: &PairingSymKey,
) -> Result<PairingReceivedMessage, PairingClientError> {
    let encoded_message_len = data.message.len();
    let message = PairingMessage::decode_relay_message(&data.message, sym_key)
        .map_err(|source| PairingClientError::PairingMessage { source })?;

    Ok(PairingReceivedMessage {
        topic: data.topic,
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wc_protocol::{
        envelope::{Envelope, EnvelopeEncoding},
        pairing::PairingSymKey,
        relay::IrnSubscriptionData,
    };

    const PAIRING_URI: &str = concat!(
        "wc:1111111111111111111111111111111111111111111111111111111111111111@2",
        "?relay-protocol=irn",
        "&symKey=2222222222222222222222222222222222222222222222222222222222222222",
        "&expiryTimestamp=4102444800"
    );

    #[test]
    fn config_builds_authenticated_relay_url() -> Result<(), Box<dyn std::error::Error>> {
        let mut config = PairingClientConfig::new("project", [7; 32], "subject");
        config.relay_url = "wss://relay.walletconnect.com?existing=1".to_owned();
        config.user_agent = "wc-2/rust-poc/test".to_owned();

        let url = relay_connection_url(&config, 1_700_000_000)?;
        let value = url.as_str();

        assert!(value.starts_with("wss://relay.walletconnect.com/?existing=1&auth="));
        assert!(value.contains("&projectId=project"));
        assert!(value.contains("&ua=wc-2%2Frust-poc%2Ftest"));

        Ok(())
    }

    #[test]
    fn validates_pairing_expiry() -> Result<(), Box<dyn std::error::Error>> {
        let pairing = PairingUri::parse(PAIRING_URI)?;

        validate_pairing_not_expired(&pairing, 4_000_000_000)?;
        let error = validate_pairing_not_expired(&pairing, 4_102_444_800)
            .expect_err("expired URI should fail");

        assert!(matches!(error, PairingClientError::PairingExpired { .. }));

        Ok(())
    }

    #[test]
    fn decodes_subscription_data_with_pairing_key() -> Result<(), Box<dyn std::error::Error>> {
        let sym_key = PairingSymKey::from_hex(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )?;
        let plaintext = r#"{"id":1,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{}}"#;
        let envelope = Envelope::encrypt_type_0(plaintext, &sym_key)?;
        let data = IrnSubscriptionData {
            topic: RelayTopic::from_hex("11".repeat(32))?,
            message: envelope.encode(EnvelopeEncoding::Base64),
            published_at: 1_700_000_000_000,
            tag: Some(1100),
        };

        let received = decode_subscription_data(data, &sym_key)?;

        assert!(received.encoded_message_len() > plaintext.len());
        assert_eq!(received.published_at(), 1_700_000_000_000);
        assert_eq!(received.tag(), Some(1100));
        assert_eq!(received.message().plaintext(), plaintext);

        Ok(())
    }
}
