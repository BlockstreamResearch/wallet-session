//! Session-authentication review primitives.

use wc_protocol::{
    relay::RelayTopic,
    session::{
        AuthPayload, Cacao, DappMetadata, JsonRpcRequest, SessionAuthenticateParams,
        SessionParticipant, SignMethod,
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

/// Caller-provided approval data for a `wc_sessionAuthenticate` request.
///
/// Core does not sign authentication messages. The caller formats the message,
/// obtains user consent, signs with wallet-owned key material, builds CACAO
/// objects, and passes those signed objects into this approval primitive.
///
/// <https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#approving-authentication-requests>
///
/// > Build the authentication object(s)
/// > ...
/// > auths: [auth],
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticateApproval {
    wallet_metadata: DappMetadata,
    cacaos: Vec<Cacao>,
}

impl SessionAuthenticateApproval {
    /// Builds approval data from wallet metadata and signed CACAO objects.
    pub fn new(
        wallet_metadata: DappMetadata,
        cacaos: Vec<Cacao>,
    ) -> Result<Self, SessionAuthenticateApprovalError> {
        if cacaos.is_empty() {
            return Err(SessionAuthenticateApprovalError::EmptyCacaos);
        }

        Ok(Self {
            wallet_metadata,
            cacaos,
        })
    }

    /// Wallet metadata sent as the authentication responder.
    #[must_use]
    pub const fn wallet_metadata(&self) -> &DappMetadata {
        &self.wallet_metadata
    }

    /// Signed CACAO objects returned to the requester.
    #[must_use]
    pub fn cacaos(&self) -> &[Cacao] {
        &self.cacaos
    }

    pub(crate) fn into_parts(self) -> (DappMetadata, Vec<Cacao>) {
        (self.wallet_metadata, self.cacaos)
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

/// Session-authentication approval construction error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionAuthenticateApprovalError {
    /// Approval must include at least one signed CACAO.
    #[error("session authenticate approval requires at least one CACAO")]
    EmptyCacaos,
}

#[cfg(test)]
mod tests {
    use crate::SessionAuthenticateApprovalError;
    use wc_protocol::{
        did::DidPkh,
        key::X25519PublicKey,
        relay::RelayTopic,
        session::{
            AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
            CacaoSignatureType, CacaoSignatureValue, DappMetadata, JsonRpcRequest,
            SessionAuthenticateParams, SessionParticipant, SignMethod,
        },
    };

    use super::{
        SessionAuthenticateApproval, SessionAuthenticateReview, SessionAuthenticateReviewError,
    };

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

    #[test]
    fn approval_requires_at_least_one_cacao() {
        let error = SessionAuthenticateApproval::new(wallet_metadata(), Vec::new())
            .expect_err("empty approval is rejected");

        assert_eq!(error, SessionAuthenticateApprovalError::EmptyCacaos);
    }

    #[test]
    fn approval_preserves_caller_provided_cacaos() -> Result<(), Box<dyn std::error::Error>> {
        let approval = SessionAuthenticateApproval::new(wallet_metadata(), vec![cacao()?])?;

        assert_eq!(approval.wallet_metadata().name, "Wallet");
        assert_eq!(approval.cacaos().len(), 1);
        assert_eq!(
            approval.cacaos()[0].p.iss.as_str(),
            "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"
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

    fn wallet_metadata() -> DappMetadata {
        DappMetadata {
            name: "Wallet".to_owned(),
            description: "Wallet".to_owned(),
            url: "https://example.com/wallet".to_owned(),
            icons: Vec::new(),
            redirect: None,
            verify_url: None,
        }
    }

    fn cacao() -> Result<Cacao, Box<dyn std::error::Error>> {
        Ok(Cacao {
            h: CacaoHeader {
                kind: CacaoHeaderType::Caip122,
            },
            p: CacaoPayload {
                iss: DidPkh::parse("did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87")?,
                domain: "example.com".to_owned(),
                aud: "https://example.com/login".to_owned(),
                version: "1".to_owned(),
                nonce: "1234567890".to_owned(),
                iat: "2026-05-28T12:00:00.000Z".to_owned(),
                statement: Some("Sign in to Example".to_owned()),
                exp: None,
                nbf: None,
                request_id: None,
                resources: Vec::new(),
            },
            s: CacaoSignature {
                kind: CacaoSignatureType::Eip191,
                signature: CacaoSignatureValue::from_wire("0x00"),
                meta: None,
            },
        })
    }
}
