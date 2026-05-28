//! Session request review primitives.

use serde_json::Value;
use wc_protocol::{
    caip::Caip2ChainId,
    relay::RelayTopic,
    session::{JsonRpcRequest, SessionMethod, SessionRequestParams, SignMethod},
};

use crate::pairing::{SessionPayload, SessionReceivedMessage};

/// Wallet-facing review data for a valid `wc_sessionRequest`.
///
/// The lower-level receive path has already checked the active session
/// namespace for the request chain and method. This type gives callers the
/// stable fields needed for policy and user approval before sending a success
/// or error response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/session-events.md#session_request>
///
/// > Triggered when a session request is received and should be presented to the user for approval or rejection.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L66-L73>
///
/// > wc_sessionRequest: { request: { method: string; params: any;
/// > expiryTimestamp?: number; }; chainId: string; };
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use wc_core::SessionRequestReview;
/// use wc_protocol::{
///     relay::RelayTopic,
///     session::{
///         JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod,
///     },
/// };
///
/// let request = JsonRpcRequest::new(
///     7,
///     SignMethod::SessionRequest,
///     SessionRequestParams {
///         chain_id: "eip155:1".parse()?,
///         request: SessionRequest {
///             method: "personal_sign".parse()?,
///             params: json!(["0x68656c6c6f", "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]),
///             expiry_timestamp: Some(1_700_000_300),
///         },
///     },
/// );
/// let topic = RelayTopic::from_bytes([9; 32]);
/// let review = SessionRequestReview::from_request(topic, 1_700_000_000_000, &request)?;
///
/// assert_eq!(review.request_id(), 7);
/// assert_eq!(review.chain_id().as_str(), "eip155:1");
/// assert_eq!(review.method().as_str(), "personal_sign");
/// assert!(!review.is_expired_at(1_700_000_000));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestReview {
    topic: RelayTopic,
    request_id: u64,
    chain_id: Caip2ChainId,
    method: SessionMethod,
    params: Value,
    expiry_timestamp: Option<u64>,
    published_at: u64,
}

impl SessionRequestReview {
    /// Extracts review data from a received session-topic message.
    pub fn from_message(
        message: &SessionReceivedMessage,
    ) -> Result<Self, SessionRequestReviewError> {
        let SessionPayload::SessionRequest(request) = message.payload() else {
            return Err(SessionRequestReviewError::NotSessionRequest);
        };

        Self::from_request(message.topic().clone(), message.published_at(), request)
    }

    /// Builds review data from a typed `wc_sessionRequest`.
    pub fn from_request(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionRequestParams>,
    ) -> Result<Self, SessionRequestReviewError> {
        if request.method != SignMethod::SessionRequest {
            return Err(SessionRequestReviewError::MethodMismatch {
                method: request.method,
            });
        }

        Ok(Self {
            topic,
            request_id: request.id,
            chain_id: request.params.chain_id.clone(),
            method: request.params.request.method.clone(),
            params: request.params.request.params.clone(),
            expiry_timestamp: request.params.request.expiry_timestamp,
            published_at,
        })
    }

    /// Session topic that delivered the request.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request id to use in the response.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Requested CAIP-2 chain.
    #[must_use]
    pub const fn chain_id(&self) -> &Caip2ChainId {
        &self.chain_id
    }

    /// Requested chain-specific JSON-RPC method.
    #[must_use]
    pub const fn method(&self) -> &SessionMethod {
        &self.method
    }

    /// Raw JSON params for the wallet UI or signing backend.
    #[must_use]
    pub const fn params(&self) -> &Value {
        &self.params
    }

    /// Optional request expiry timestamp in unix seconds.
    #[must_use]
    pub const fn expiry_timestamp(&self) -> Option<u64> {
        self.expiry_timestamp
    }

    /// Relay publish timestamp in milliseconds.
    #[must_use]
    pub const fn published_at(&self) -> u64 {
        self.published_at
    }

    /// Whether the request expiry has passed at `now_unix_seconds`.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp
            .is_some_and(|expiry| expiry <= now_unix_seconds)
    }
}

/// Session request review construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionRequestReviewError {
    /// The received message is not a `wc_sessionRequest`.
    #[error("session request review target is not a session request")]
    NotSessionRequest,

    /// The typed request envelope uses a different Sign method.
    #[error("session request review method mismatch: {method}")]
    MethodMismatch {
        /// Sign method from the JSON-RPC request envelope.
        method: SignMethod,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wc_protocol::{
        relay::RelayTopic,
        session::{JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod},
    };

    use super::SessionRequestReview;

    #[test]
    fn review_preserves_request_fields() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!(["0x68656c6c6f"]),
                    expiry_timestamp: Some(1_700_000_300),
                },
            },
        );
        let topic = RelayTopic::from_bytes([3; 32]);

        let review =
            SessionRequestReview::from_request(topic.clone(), 1_700_000_000_000, &request)?;

        assert_eq!(review.topic(), &topic);
        assert_eq!(review.request_id(), 42);
        assert_eq!(review.chain_id().as_str(), "eip155:1");
        assert_eq!(review.method().as_str(), "personal_sign");
        assert_eq!(review.params(), &json!(["0x68656c6c6f"]));
        assert_eq!(review.expiry_timestamp(), Some(1_700_000_300));
        assert_eq!(review.published_at(), 1_700_000_000_000);
        assert!(!review.is_expired_at(1_700_000_299));
        assert!(review.is_expired_at(1_700_000_300));

        Ok(())
    }

    #[test]
    fn review_rejects_wrong_sign_method() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionPing,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!([]),
                    expiry_timestamp: None,
                },
            },
        );
        let error =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)
                .expect_err("wrong method should fail");

        assert_eq!(
            error,
            super::SessionRequestReviewError::MethodMismatch {
                method: SignMethod::SessionPing,
            }
        );

        Ok(())
    }
}
