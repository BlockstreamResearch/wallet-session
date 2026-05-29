//! Session-authentication review primitives.

use wc_protocol::{
    relay::RelayTopic,
    session::{
        AuthPayload, JsonRpcRequest, SessionAuthenticateParams, SessionParticipant, SignMethod,
    },
};

use crate::pairing::{PairingPayload, PairingReceivedMessage};

/// Wallet-facing review data for a `wc_sessionAuthenticate` request.
///
/// The pairing receive path has already decrypted the request. This type gives
/// callers the stable fields needed for origin/policy review before approving
/// with CACAOs or rejecting with a JSON-RPC error.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2600-L2605>
///
/// > this.client.events.emit("session_authenticate", {
/// > id,
/// > topic,
///
/// # Examples
///
/// ```
/// use wc_core::SessionAuthenticateReview;
/// use wc_protocol::{relay::RelayTopic, session::SessionAuthenticateParams};
///
/// let json = r#"{
///   "requester": {
///     "publicKey": "0b63513c543d34b9bba30e135d57c5dfa7d1bfbf610177c66b9c0ebd2c8564b4",
///     "metadata": {
///       "name": "Example",
///       "description": "Example dapp",
///       "url": "https://example.com",
///       "icons": ["https://example.com/icon.png"]
///     }
///   },
///   "authPayload": {
///     "type": "caip122",
///     "chains": ["eip155:1"],
///     "aud": "https://example.com/login",
///     "domain": "example.com",
///     "version": "1",
///     "nonce": "1234567890",
///     "iat": "2026-05-28T12:00:00.000Z",
///     "statement": "Sign in to Example"
///   },
///   "expiryTimestamp": 4102444800
/// }"#;
/// let params = serde_json::from_str::<SessionAuthenticateParams>(json)?;
/// let topic = RelayTopic::from_bytes([7; 32]);
/// let review = SessionAuthenticateReview::from_params(topic, 9, 1_779_954_250_000, params);
///
/// assert_eq!(review.request_id(), 9);
/// assert_eq!(review.auth_payload().domain, "example.com");
/// assert!(!review.is_expired_at(4_000_000_000));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticateReview {
    topic: RelayTopic,
    request_id: u64,
    requester: SessionParticipant,
    auth_payload: AuthPayload,
    expiry_timestamp: u64,
    published_at: u64,
}

impl SessionAuthenticateReview {
    /// Extracts review data from a received pairing-topic message.
    pub fn from_message(
        message: &PairingReceivedMessage,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        let PairingPayload::SessionAuthenticate(request) = message.payload() else {
            return Err(SessionAuthenticateReviewError::NotSessionAuthenticate);
        };

        Self::from_request(message.topic().clone(), message.published_at(), request)
    }

    /// Builds review data from a typed `wc_sessionAuthenticate` request.
    pub fn from_request(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionAuthenticateParams>,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        if request.method != SignMethod::SessionAuthenticate {
            return Err(SessionAuthenticateReviewError::MethodMismatch {
                method: request.method,
            });
        }

        Ok(Self::from_params(
            topic,
            request.id,
            published_at,
            request.params.clone(),
        ))
    }

    /// Builds review data from already validated request params.
    #[must_use]
    pub fn from_params(
        topic: RelayTopic,
        request_id: u64,
        published_at: u64,
        params: SessionAuthenticateParams,
    ) -> Self {
        Self {
            topic,
            request_id,
            requester: params.requester,
            auth_payload: params.auth_payload,
            expiry_timestamp: params.expiry_timestamp,
            published_at,
        }
    }

    /// Pairing topic that delivered the request.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request id to use in the response.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Dapp public key and UI metadata.
    #[must_use]
    pub const fn requester(&self) -> &SessionParticipant {
        &self.requester
    }

    /// CAIP-122 payload requested for signing.
    #[must_use]
    pub const fn auth_payload(&self) -> &AuthPayload {
        &self.auth_payload
    }

    /// Request expiry timestamp in unix seconds.
    #[must_use]
    pub const fn expiry_timestamp(&self) -> u64 {
        self.expiry_timestamp
    }

    /// Relay publish timestamp in milliseconds.
    #[must_use]
    pub const fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Whether the request expiry has passed at `now_unix_seconds`.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp <= now_unix_seconds
    }
}

/// Session-authentication review construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionAuthenticateReviewError {
    /// The received pairing message is not a `wc_sessionAuthenticate`.
    #[error("session authenticate review target is not a session authenticate request")]
    NotSessionAuthenticate,

    /// The typed request envelope uses a different Sign method.
    #[error("session authenticate review method mismatch: {method}")]
    MethodMismatch {
        /// Sign method from the JSON-RPC request envelope.
        method: SignMethod,
    },
}

#[cfg(test)]
mod tests {
    use wc_protocol::{
        key::X25519PublicKey,
        relay::RelayTopic,
        session::{
            AuthPayload, CacaoHeaderType, DappMetadata, JsonRpcRequest, SessionAuthenticateParams,
            SessionParticipant, SignMethod,
        },
    };

    use super::{SessionAuthenticateReview, SessionAuthenticateReviewError};

    #[test]
    fn builds_review_from_request() -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request(SignMethod::SessionAuthenticate)?;
        let review = SessionAuthenticateReview::from_request(
            RelayTopic::from_bytes([3; 32]),
            1_779_954_250_000,
            &request,
        )?;

        assert_eq!(review.request_id(), 9);
        assert_eq!(review.requester().metadata.name, "Example");
        assert_eq!(review.auth_payload().domain, "example.com");
        assert_eq!(review.expiry_timestamp(), 4_102_444_800);
        assert_eq!(review.published_at(), 1_779_954_250_000);
        assert!(review.is_expired_at(4_102_444_800));

        Ok(())
    }

    #[test]
    fn rejects_wrong_sign_method() -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request(SignMethod::SessionPropose)?;
        let error =
            SessionAuthenticateReview::from_request(RelayTopic::from_bytes([3; 32]), 1, &request)
                .expect_err("wrong method should fail");

        assert_eq!(
            error,
            SessionAuthenticateReviewError::MethodMismatch {
                method: SignMethod::SessionPropose
            }
        );

        Ok(())
    }

    fn authenticate_request(
        method: SignMethod,
    ) -> Result<JsonRpcRequest<SessionAuthenticateParams>, Box<dyn std::error::Error>> {
        Ok(JsonRpcRequest::new(
            9,
            method,
            SessionAuthenticateParams {
                requester: SessionParticipant {
                    public_key: X25519PublicKey::from_hex(
                        "0b63513c543d34b9bba30e135d57c5dfa7d1bfbf610177c66b9c0ebd2c8564b4",
                    )?,
                    metadata: DappMetadata {
                        name: "Example".to_owned(),
                        description: "Example dapp".to_owned(),
                        url: "https://example.com".to_owned(),
                        icons: vec!["https://example.com/icon.png".to_owned()],
                        redirect: None,
                        verify_url: None,
                    },
                },
                auth_payload: AuthPayload {
                    kind: CacaoHeaderType::Caip122,
                    chains: vec!["eip155:1".parse()?],
                    aud: "https://example.com/login".to_owned(),
                    domain: "example.com".to_owned(),
                    version: "1".to_owned(),
                    nonce: "1234567890".to_owned(),
                    iat: "2026-05-28T12:00:00.000Z".to_owned(),
                    statement: Some("Sign in to Example".to_owned()),
                    exp: None,
                    nbf: None,
                    request_id: None,
                    resources: Vec::new(),
                },
                expiry_timestamp: 4_102_444_800,
            },
        ))
    }
}
