//! Session request review primitives.

use serde_json::Value;
use wc_protocol::{
    caip::Caip2ChainId,
    relay::RelayTopic,
    session::{
        JsonRpcRequest, SessionMethod, SessionRequest, SessionRequestParams, SignMethod,
        WalletCallRequest, WalletCallRequestError,
    },
    verify::{DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext},
};

use crate::pairing::{SessionPayload, SessionReceivedMessage};
use crate::verify_policy::{VerifyContextRisk, classify_verify_context};
use crate::verify_resolver::{VerifyResolver, VerifyResolverError};

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
    verify_context: VerifyContext,
    verify_attestation_hash: Option<VerifyAttestationHash>,
    verify_attestation_jwt: Option<String>,
    verify_encrypted_id: Option<String>,
}

impl SessionRequestReview {
    /// Extracts review data from a received session-topic message.
    pub fn from_message(
        message: &SessionReceivedMessage,
    ) -> Result<Self, SessionRequestReviewError> {
        Self::from_message_with_verify_context(
            message,
            VerifyContext::unknown("", DEFAULT_VERIFY_URL),
        )
    }

    /// Extracts review data and caller-resolved Verify context from a session message.
    ///
    /// The maintained Sign Client attaches `verifyContext` to
    /// `session_request` events after resolving it from the stored peer
    /// metadata and request hash.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2456-L2474>
    ///
    /// > const verifyContext = await this.getVerifyContext({
    /// > metadata: session.peer.metadata,
    /// > const request = {
    /// > verifyContext,
    pub fn from_message_with_verify_context(
        message: &SessionReceivedMessage,
        verify_context: VerifyContext,
    ) -> Result<Self, SessionRequestReviewError> {
        let SessionPayload::SessionRequest(request) = message.payload() else {
            return Err(SessionRequestReviewError::NotSessionRequest);
        };

        Self::from_request_with_verify_context_and_hash(
            message.topic().clone(),
            message.published_at(),
            request,
            verify_context,
            Some(message.verify_attestation_hash().clone()),
            message
                .verify_jwt_attestation()
                .map(|(jwt, _encrypted_id)| jwt.to_owned()),
            message
                .verify_jwt_attestation()
                .map(|(_jwt, encrypted_id)| encrypted_id.to_owned()),
        )
    }

    /// Builds review data from a typed `wc_sessionRequest`.
    pub fn from_request(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionRequestParams>,
    ) -> Result<Self, SessionRequestReviewError> {
        Self::from_request_with_verify_context_and_hash(
            topic,
            published_at,
            request,
            VerifyContext::unknown("", DEFAULT_VERIFY_URL),
            None,
            None,
            None,
        )
    }

    /// Builds review data from a typed request and caller-resolved Verify context.
    pub fn from_request_with_verify_context(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionRequestParams>,
        verify_context: VerifyContext,
    ) -> Result<Self, SessionRequestReviewError> {
        Self::from_request_with_verify_context_and_hash(
            topic,
            published_at,
            request,
            verify_context,
            None,
            None,
            None,
        )
    }

    fn from_request_with_verify_context_and_hash(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionRequestParams>,
        verify_context: VerifyContext,
        verify_attestation_hash: Option<VerifyAttestationHash>,
        verify_attestation_jwt: Option<String>,
        verify_encrypted_id: Option<String>,
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
            verify_context,
            verify_attestation_hash,
            verify_attestation_jwt,
            verify_encrypted_id,
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

    /// Parses this review as an EIP-5792 Wallet Call request when applicable.
    ///
    /// This helper only recognizes the method-specific JSON shape. Wallets
    /// still decide whether the user should approve the request and whether
    /// advertised capabilities are supported.
    ///
    /// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls>
    ///
    /// > MUST NOT send any calls from the request if the user rejects the
    /// > request
    pub fn wallet_call_request(&self) -> Result<Option<WalletCallRequest>, WalletCallRequestError> {
        WalletCallRequest::from_session_request(&SessionRequest {
            method: self.method.clone(),
            params: self.params.clone(),
            expiry_timestamp: self.expiry_timestamp,
        })
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

    /// Verify context associated with the requesting dapp.
    ///
    /// `SingleSessionClient::session_request_review` seeds this from the
    /// active session peer metadata. Lower-level constructors without session
    /// metadata use an unresolved empty-origin context.
    #[must_use]
    pub const fn verify_context(&self) -> &VerifyContext {
        &self.verify_context
    }

    /// Retained Verify hash for reviews built from decrypted relay messages.
    ///
    /// Typed constructors such as `from_request` cannot know the exact JSON
    /// string sent by the peer. Reviews built by the receive path retain the
    /// SDK-compatible hash from `SessionReceivedMessage`.
    #[must_use]
    pub const fn verify_attestation_hash(&self) -> Option<&VerifyAttestationHash> {
        self.verify_attestation_hash.as_ref()
    }

    /// Relay-carried Verify v3 JWT and encrypted identifier, when retained.
    ///
    /// Reviews built from a decrypted relay message can use this pair before
    /// falling back to hash-based Verify resolution.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2456-L2468>
    ///
    /// > const { topic, payload, attestation, encryptedId, transportType } = args;
    /// > hash: hashMessage(JSON.stringify(formatJsonRpcRequest("wc_sessionRequest", params, id))),
    #[must_use]
    pub fn verify_jwt_attestation(&self) -> Option<(&str, &str)> {
        self.verify_attestation_jwt
            .as_deref()
            .zip(self.verify_encrypted_id.as_deref())
    }

    /// Current policy classification for `verify_context`.
    #[must_use]
    pub const fn verify_risk(&self) -> VerifyContextRisk {
        classify_verify_context(&self.verify_context)
    }

    /// Resolves Verify context with the retained SDK-compatible hash.
    ///
    /// This is available for reviews built from a received session-topic
    /// message. Use `resolve_verify_context_with_hash` when constructing a
    /// review from already-typed data.
    pub async fn resolve_verify_context(
        &mut self,
        resolver: &VerifyResolver,
    ) -> Result<&VerifyContext, SessionRequestVerifyResolutionError> {
        let hash = self
            .verify_attestation_hash
            .as_ref()
            .ok_or(SessionRequestVerifyResolutionError::MissingHash)?;
        self.verify_context = resolver
            .resolve_hash_for_context(hash, &self.verify_context)
            .await
            .map_err(|source| SessionRequestVerifyResolutionError::Resolver { source })?;
        Ok(&self.verify_context)
    }

    /// Resolves Verify context from a retained relay JWT, then falls back to hash.
    ///
    /// The explicit clock keeps expiry handling deterministic for tests and
    /// callers. JWT verification errors are surfaced instead of silently using
    /// the hash resolver, because a malformed relay-provided JWT is a distinct
    /// trust signal.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L117-L137>
    ///
    /// > if (decoded.payload.id !== encryptedId) return;
    /// > const validation = await this.isValidJwtAttestation(attestationId);
    pub async fn resolve_verify_context_at(
        &mut self,
        resolver: &VerifyResolver,
        now_unix_seconds: u64,
    ) -> Result<&VerifyContext, SessionRequestVerifyResolutionError> {
        if let Some((attestation_jwt, encrypted_id)) =
            self.verify_jwt_attestation()
                .map(|(attestation_jwt, encrypted_id)| {
                    (attestation_jwt.to_owned(), encrypted_id.to_owned())
                })
        {
            self.verify_context = resolver
                .resolve_jwt_for_context(
                    &attestation_jwt,
                    &encrypted_id,
                    &self.verify_context,
                    now_unix_seconds,
                )
                .await
                .map_err(|source| SessionRequestVerifyResolutionError::Resolver { source })?;
            return Ok(&self.verify_context);
        }

        self.resolve_verify_context(resolver).await
    }

    /// Resolves Verify context with a caller-provided SDK-compatible hash.
    ///
    /// The maintained Sign Client hashes
    /// `JSON.stringify(formatJsonRpcRequest("wc_sessionRequest", params, id))`
    /// for session requests. The caller should pass that exact hash when it is
    /// available.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2462-L2468>
    ///
    /// > hash: hashMessage(JSON.stringify(formatJsonRpcRequest("wc_sessionRequest", params, id))),
    /// > metadata: session.peer.metadata,
    pub async fn resolve_verify_context_with_hash(
        &mut self,
        resolver: &VerifyResolver,
        hash: &VerifyAttestationHash,
    ) -> Result<&VerifyContext, VerifyResolverError> {
        self.verify_context = resolver
            .resolve_hash_for_context(hash, &self.verify_context)
            .await?;
        Ok(&self.verify_context)
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

/// Verify resolution error for a session request review.
#[derive(Debug, thiserror::Error)]
pub enum SessionRequestVerifyResolutionError {
    /// The review was built from typed data and has no exact relay plaintext hash.
    #[error("session request verify hash is missing")]
    MissingHash,

    /// Verify resolver failed.
    #[error("session request verify resolver failed")]
    Resolver {
        /// Resolver failure source.
        #[source]
        source: VerifyResolverError,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wc_protocol::{
        relay::RelayTopic,
        session::{
            JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod, WalletCallRequest,
            WalletSendCallsParams,
        },
        verify::{VerifyContext, VerifyValidation},
    };

    use super::SessionRequestReview;
    use crate::VerifyContextRisk;

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
        assert_eq!(review.verify_context().verified.origin, "");
        assert!(review.verify_attestation_hash().is_none());
        assert!(review.verify_jwt_attestation().is_none());
        assert_eq!(review.verify_risk(), VerifyContextRisk::Unknown);
        assert!(!review.is_expired_at(1_700_000_299));
        assert!(review.is_expired_at(1_700_000_300));

        Ok(())
    }

    #[tokio::test]
    async fn resolving_verify_context_requires_retained_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!([]),
                    expiry_timestamp: None,
                },
            },
        );
        let mut review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?;
        let resolver = crate::VerifyResolver::new()?;

        let error = review
            .resolve_verify_context(&resolver)
            .await
            .expect_err("typed request has no exact relay hash");

        assert!(matches!(
            error,
            super::SessionRequestVerifyResolutionError::MissingHash
        ));

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

    #[test]
    fn review_preserves_supplied_verify_context() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!([]),
                    expiry_timestamp: None,
                },
            },
        );
        let verify_context =
            VerifyContext::unknown("https://example.com", "https://verify.walletconnect.org");

        let review = SessionRequestReview::from_request_with_verify_context(
            RelayTopic::from_bytes([3; 32]),
            1_700_000_000_000,
            &request,
            verify_context,
        )?;

        assert_eq!(
            review.verify_context().verified.origin,
            "https://example.com"
        );
        assert_eq!(
            review.verify_context().verified.validation,
            VerifyValidation::Unknown
        );

        Ok(())
    }

    #[test]
    fn review_parses_wallet_call_request() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_sendCalls".parse()?,
                    params: json!([{
                        "version": "2.0.0",
                        "chainId": "0x1",
                        "atomicRequired": true,
                        "calls": [{
                            "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
                            "value": "0x0",
                            "data": "0x"
                        }]
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?;

        let wallet_call = review
            .wallet_call_request()?
            .expect("wallet_sendCalls should parse");

        let WalletCallRequest::SendCalls(WalletSendCallsParams(send_calls)) = wallet_call else {
            panic!("expected wallet_sendCalls");
        };
        assert_eq!(send_calls.chain_id, "0x1");
        assert_eq!(
            send_calls.calls[0].to.as_deref(),
            Some("0xd46e8dd67c5d32be8058bb8eb970870f07244567")
        );

        Ok(())
    }
}
