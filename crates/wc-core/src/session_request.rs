//! Session request review primitives.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde_json::Value;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId},
    relay::RelayTopic,
    session::{
        JsonRpcRequest, SessionMethod, SessionRequest, SessionRequestParams, SignMethod,
        WalletCall, WalletCallRequest, WalletCallRequestError, WalletSendCallsResult,
    },
    verify::{DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext},
};

use crate::pairing::{SessionPayload, SessionReceivedMessage};
use crate::redirect::{WalletRedirectOrigin, WalletRedirectReview};
use crate::verify_policy::{
    VerifyContextRisk, VerifyRiskReview, VerifyRiskSurface, classify_verify_context,
};
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
#[derive(Clone, PartialEq, Eq)]
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
    redirect: WalletRedirectReview,
    authorized_accounts: Vec<Caip10AccountId>,
}

impl fmt::Debug for SessionRequestReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRequestReview")
            .field("topic", &self.topic)
            .field("request_id", &self.request_id)
            .field("chain_id", &self.chain_id)
            .field("method", &self.method)
            .field("params", &RedactedJsonDebug(&self.params))
            .field("expiry_timestamp", &self.expiry_timestamp)
            .field("published_at", &self.published_at)
            .field(
                "verify_context",
                &RedactedVerifyContextDebug(&self.verify_context),
            )
            .field("verify_risk", &self.verify_risk())
            .field("verify_attestation_hash", &self.verify_attestation_hash)
            .field(
                "verify_attestation_jwt",
                &self
                    .verify_attestation_jwt
                    .as_deref()
                    .map(SensitiveStrDebug),
            )
            .field(
                "verify_encrypted_id",
                &self.verify_encrypted_id.as_deref().map(SensitiveStrDebug),
            )
            .field("redirect", &self.redirect)
            .field("authorized_account_count", &self.authorized_accounts.len())
            .finish()
    }
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
            redirect: WalletRedirectReview::empty(WalletRedirectOrigin::Unknown),
            authorized_accounts: Vec::new(),
        })
    }

    /// Replaces the redirect review associated with this request.
    #[must_use]
    pub fn with_redirect_review(mut self, redirect: WalletRedirectReview) -> Self {
        self.redirect = redirect;
        self
    }

    /// Replaces the authorized accounts attached to this review.
    ///
    /// The list is filtered to accounts on the request chain and deduplicated.
    /// Lower-level constructors cannot infer this without the active session;
    /// `SingleSessionClient::session_request_review` fills it from the active
    /// namespace set.
    #[must_use]
    pub fn with_authorized_accounts<I>(mut self, accounts: I) -> Self
    where
        I: IntoIterator<Item = Caip10AccountId>,
    {
        self.authorized_accounts = filter_accounts_for_chain(&self.chain_id, accounts);
        self
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

    /// Redirect metadata and automatic-return recommendation for the active session.
    #[must_use]
    pub const fn redirect(&self) -> &WalletRedirectReview {
        &self.redirect
    }

    /// CAIP-10 accounts authorized for the request chain.
    ///
    /// An empty list means this review was built without active-session
    /// context, not that the peer is allowed to choose any account.
    #[must_use]
    pub fn authorized_accounts(&self) -> &[Caip10AccountId] {
        &self.authorized_accounts
    }

    /// Builds a wallet-policy review for recognized high-risk methods.
    ///
    /// Unknown methods remain `Raw`, because namespace authorization only says
    /// the dapp may ask for the method. Wallet code should still decide how to
    /// render or reject method-specific params before returning a result.
    pub fn method_review(
        &self,
    ) -> Result<SessionRequestMethodReview, SessionRequestMethodReviewError> {
        self.method_review_with_unknown_policy(UnknownSessionRequestMethodPolicy::AllowRaw)
    }

    /// Builds a wallet-policy review while applying an explicit unknown-method policy.
    ///
    /// Namespace authorization only proves that the dapp may ask for a method.
    /// It does not prove that the wallet can safely render, simulate, or
    /// execute arbitrary method params. Wallets that require typed review for
    /// every success response should use `Reject` and send an error for methods
    /// they do not understand.
    pub fn method_review_with_unknown_policy(
        &self,
        unknown_policy: UnknownSessionRequestMethodPolicy,
    ) -> Result<SessionRequestMethodReview, SessionRequestMethodReviewError> {
        self.method_review_with_status_registry(unknown_policy, None)
    }

    /// Builds a method review with unknown-method policy and Wallet Call status binding.
    pub fn method_review_with_wallet_call_status_registry(
        &self,
        unknown_policy: UnknownSessionRequestMethodPolicy,
        registry: &WalletCallStatusRegistry,
    ) -> Result<SessionRequestMethodReview, SessionRequestMethodReviewError> {
        self.method_review_with_status_registry(unknown_policy, Some(registry))
    }

    fn method_review_with_status_registry(
        &self,
        unknown_policy: UnknownSessionRequestMethodPolicy,
        registry: Option<&WalletCallStatusRegistry>,
    ) -> Result<SessionRequestMethodReview, SessionRequestMethodReviewError> {
        if let Some(wallet_call) = self.wallet_call_review_with_status_registry(registry)? {
            return Ok(SessionRequestMethodReview::WalletCall(Box::new(
                wallet_call,
            )));
        }
        if let Some(signing) = self.signing_request_review()? {
            return Ok(SessionRequestMethodReview::Signing(Box::new(signing)));
        }
        if let Some(transaction) = self.transaction_request_review()? {
            return Ok(SessionRequestMethodReview::Transaction(Box::new(
                transaction,
            )));
        }
        match unknown_policy {
            UnknownSessionRequestMethodPolicy::AllowRaw => Ok(SessionRequestMethodReview::Raw),
            UnknownSessionRequestMethodPolicy::Reject => {
                Err(SessionRequestMethodReviewError::UnknownMethod {
                    method: self.method.clone(),
                })
            }
        }
    }

    /// Builds a typed review for common EVM signing methods.
    pub fn signing_request_review(
        &self,
    ) -> Result<Option<SigningRequestReview>, SessionRequestMethodReviewError> {
        let Some(kind) = SigningRequestKind::from_method(self.method.as_str()) else {
            return Ok(None);
        };

        let params = self.params_array(kind.method_name())?;
        let (account_index, payload_index) = kind.param_indexes();
        let payload = params.get(payload_index).cloned().ok_or_else(|| {
            SessionRequestMethodReviewError::MalformedParams {
                method: kind.method_name(),
                reason: "missing signing payload",
            }
        })?;
        let requested_address = if kind == SigningRequestKind::EthSignTransaction {
            payload
                .get("from")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        } else {
            params
                .get(account_index)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        };
        let chain = match kind {
            SigningRequestKind::EthSignTypedData
            | SigningRequestKind::EthSignTypedDataV3
            | SigningRequestKind::EthSignTypedDataV4 => {
                eip712_domain_chain_id(&payload).map(|raw_chain_id| {
                    SessionRequestChainConstraint::new(&self.chain_id, raw_chain_id)
                })
            }
            SigningRequestKind::EthSignTransaction => {
                payload.get("chainId").cloned().map(|raw_chain_id| {
                    SessionRequestChainConstraint::new(&self.chain_id, raw_chain_id)
                })
            }
            SigningRequestKind::PersonalSign | SigningRequestKind::EthSign => None,
        };

        let typed_data = kind
            .is_typed_data()
            .then(|| Eip712TypedDataSummary::new(&self.chain_id, &payload));
        let message = kind
            .is_message_signing()
            .then(|| SigningMessageSummary::new(kind, &payload));
        let transaction = (kind == SigningRequestKind::EthSignTransaction)
            .then(|| EvmTransactionSummary::new(&payload));

        Ok(Some(SigningRequestReview {
            kind,
            account: self.account_constraint(requested_address),
            chain,
            payload,
            message,
            typed_data,
            transaction,
        }))
    }

    /// Builds a typed review for `eth_sendTransaction`.
    ///
    /// This is not treated as signing, but it carries the same account
    /// constraint risk and should not be blindly executed.
    pub fn transaction_request_review(
        &self,
    ) -> Result<Option<TransactionRequestReview>, SessionRequestMethodReviewError> {
        if self.method.as_str() != "eth_sendTransaction" {
            return Ok(None);
        }

        let params = self.params_array("eth_sendTransaction")?;
        let transaction =
            params
                .first()
                .cloned()
                .ok_or(SessionRequestMethodReviewError::MalformedParams {
                    method: "eth_sendTransaction",
                    reason: "missing transaction object",
                })?;
        let requested_address = transaction
            .get("from")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let chain = transaction
            .get("chainId")
            .cloned()
            .map(|raw_chain_id| SessionRequestChainConstraint::new(&self.chain_id, raw_chain_id));

        Ok(Some(TransactionRequestReview {
            account: self.account_constraint(requested_address),
            chain,
            summary: EvmTransactionSummary::new(&transaction),
            transaction,
        }))
    }

    /// Builds a Wallet Call review that summarizes account, chain, and
    /// capability-disclosure constraints without returning capabilities or
    /// executing calls.
    pub fn wallet_call_review(
        &self,
    ) -> Result<Option<WalletCallReview>, SessionRequestMethodReviewError> {
        self.wallet_call_review_with_status_registry(None)
    }

    /// Builds a Wallet Call review and binds status IDs to a caller-owned registry.
    ///
    /// The registry is intentionally supplied by the wallet application. This
    /// keeps the single-session runtime stateless while still letting status
    /// lookups prove that an ID belongs to a wallet-returned `wallet_sendCalls`
    /// result for the same session topic and request chain.
    pub fn wallet_call_review_for_registry(
        &self,
        registry: &WalletCallStatusRegistry,
    ) -> Result<Option<WalletCallReview>, SessionRequestMethodReviewError> {
        self.wallet_call_review_with_status_registry(Some(registry))
    }

    fn wallet_call_review_with_status_registry(
        &self,
        registry: Option<&WalletCallStatusRegistry>,
    ) -> Result<Option<WalletCallReview>, SessionRequestMethodReviewError> {
        let Some(wallet_call) = self.wallet_call_request()? else {
            return Ok(None);
        };

        let review = match wallet_call {
            WalletCallRequest::GetCapabilities(params) => {
                let requested_chains = params
                    .1
                    .unwrap_or_default()
                    .into_iter()
                    .map(|chain_id| self.wallet_call_chain_constraint(chain_id))
                    .collect();
                WalletCallReview::GetCapabilities(WalletGetCapabilitiesReview {
                    address: self.account_constraint(Some(params.0)),
                    requested_chains,
                })
            }
            WalletCallRequest::SendCalls(params) => {
                let request = params.0;
                let capability_keys =
                    wallet_call_capability_keys(request.capabilities.as_ref())
                        .chain(request.calls.iter().flat_map(|call| {
                            wallet_call_capability_keys(call.capabilities.as_ref())
                        }))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                WalletCallReview::SendCalls(WalletSendCallsReview {
                    from: self.account_constraint(request.from),
                    requested_chain: self.wallet_call_chain_constraint(request.chain_id),
                    call_count: request.calls.len(),
                    atomic_required: request.atomic_required,
                    capability_keys,
                    calls: request
                        .calls
                        .iter()
                        .map(EvmCallSummary::from_wallet_call)
                        .collect(),
                })
            }
            WalletCallRequest::GetCallsStatus(params) => {
                WalletCallReview::GetCallsStatus(self.wallet_call_status_review(params.0, registry))
            }
            WalletCallRequest::ShowCallsStatus(params) => WalletCallReview::ShowCallsStatus(
                self.wallet_call_status_review(params.0, registry),
            ),
        };

        Ok(Some(review))
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

    /// Verify risk review required before returning a signing/result success.
    #[must_use]
    pub fn verify_risk_review(&self) -> VerifyRiskReview {
        VerifyRiskReview::new(
            VerifyRiskSurface::SessionRequestSigning,
            self.topic.clone(),
            self.request_id,
            self.verify_attestation_hash.clone(),
            self.verify_context.clone(),
        )
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

    fn params_array(
        &self,
        method: &'static str,
    ) -> Result<&[Value], SessionRequestMethodReviewError> {
        self.params.as_array().map(Vec::as_slice).ok_or(
            SessionRequestMethodReviewError::MalformedParams {
                method,
                reason: "params must be an array",
            },
        )
    }

    fn account_constraint(
        &self,
        requested_address: Option<String>,
    ) -> SessionRequestAccountConstraint {
        SessionRequestAccountConstraint::new(
            &self.chain_id,
            self.authorized_accounts.clone(),
            requested_address,
        )
    }

    fn wallet_call_chain_constraint(&self, raw_chain_id: String) -> WalletCallChainConstraint {
        WalletCallChainConstraint::new(&self.chain_id, raw_chain_id)
    }

    fn wallet_call_status_review(
        &self,
        id: String,
        registry: Option<&WalletCallStatusRegistry>,
    ) -> WalletCallStatusReview {
        let binding = registry.map_or_else(WalletCallStatusIdBinding::unchecked, |registry| {
            registry.binding_for(&id, &self.topic, &self.chain_id)
        });
        WalletCallStatusReview { id, binding }
    }
}

/// Wallet-facing method-specific review for high-risk session requests.
#[derive(Clone, PartialEq, Eq)]
pub enum SessionRequestMethodReview {
    /// Recognized EVM signing request.
    Signing(Box<SigningRequestReview>),
    /// Recognized EVM transaction submission request.
    Transaction(Box<TransactionRequestReview>),
    /// Recognized EIP-5792 Wallet Call request.
    WalletCall(Box<WalletCallReview>),
    /// Namespace-authorized method without a built-in method-specific parser.
    Raw,
}

impl fmt::Debug for SessionRequestMethodReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signing(review) => formatter.debug_tuple("Signing").field(review).finish(),
            Self::Transaction(review) => {
                formatter.debug_tuple("Transaction").field(review).finish()
            }
            Self::WalletCall(review) => formatter.debug_tuple("WalletCall").field(review).finish(),
            Self::Raw => formatter.write_str("Raw"),
        }
    }
}

/// Policy for namespace-authorized methods without built-in typed review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSessionRequestMethodPolicy {
    /// Return `SessionRequestMethodReview::Raw` so the caller can handle params itself.
    AllowRaw,
    /// Fail closed instead of allowing a success response from opaque params.
    Reject,
}

/// Review error for method-specific session request helpers.
#[derive(Debug, thiserror::Error)]
pub enum SessionRequestMethodReviewError {
    /// Params for a recognized method were malformed.
    #[error("{method} session request params are malformed: {reason}")]
    MalformedParams {
        /// Session request method being reviewed.
        method: &'static str,
        /// Stable reason suitable for logging or tests.
        reason: &'static str,
    },

    /// Wallet Call params failed the EIP-5792 DTO parser.
    #[error(transparent)]
    WalletCall(#[from] WalletCallRequestError),

    /// The method has no built-in typed review and policy requires rejection.
    #[error("session request method has no typed review: {method}")]
    UnknownMethod {
        /// Namespace-authorized but wallet-unknown method.
        method: SessionMethod,
    },
}

/// Wallet-reviewed approval token required before returning a session request success.
///
/// Constructing this type is the explicit point where wallet code chooses how
/// to handle unknown methods and, for Wallet Call status lookups, supplies the
/// wallet-owned call registry. `SingleSessionClient` requires this token so a
/// success response cannot be published with only origin/Verify review.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRequestApproval {
    topic: RelayTopic,
    request_id: u64,
    verify_risk_review: VerifyRiskReview,
    method_review: SessionRequestMethodReview,
}

impl fmt::Debug for SessionRequestApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRequestApproval")
            .field("topic", &self.topic)
            .field("request_id", &self.request_id)
            .field("verify_risk_review", &self.verify_risk_review)
            .field("method_review", &self.method_review)
            .finish()
    }
}

impl SessionRequestApproval {
    /// Builds approval for a reviewed request without a Wallet Call status registry.
    ///
    /// Wallet Call status methods are rejected by this constructor because the
    /// ID cannot be proven wallet-owned without a registry. Use
    /// `with_wallet_call_status_registry` for those methods.
    pub fn new(
        review: &SessionRequestReview,
        unknown_policy: UnknownSessionRequestMethodPolicy,
    ) -> Result<Self, SessionRequestApprovalError> {
        let method_review = review
            .method_review_with_unknown_policy(unknown_policy)
            .map_err(|source| SessionRequestApprovalError::MethodReview { source })?;
        Self::from_method_review(review, method_review)
    }

    /// Builds approval using a caller-owned Wallet Call status registry.
    pub fn with_wallet_call_status_registry(
        review: &SessionRequestReview,
        unknown_policy: UnknownSessionRequestMethodPolicy,
        registry: &WalletCallStatusRegistry,
    ) -> Result<Self, SessionRequestApprovalError> {
        let method_review = review
            .method_review_with_status_registry(unknown_policy, Some(registry))
            .map_err(|source| SessionRequestApprovalError::MethodReview { source })?;
        Self::from_method_review(review, method_review)
    }

    fn from_method_review(
        review: &SessionRequestReview,
        method_review: SessionRequestMethodReview,
    ) -> Result<Self, SessionRequestApprovalError> {
        validate_method_review_for_approval(&method_review)?;
        Ok(Self {
            topic: review.topic().clone(),
            request_id: review.request_id(),
            verify_risk_review: review.verify_risk_review(),
            method_review,
        })
    }

    /// Session topic approved by this token.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// JSON-RPC request id approved by this token.
    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Verify risk review bound to this approved request.
    #[must_use]
    pub const fn verify_risk_review(&self) -> &VerifyRiskReview {
        &self.verify_risk_review
    }

    /// Method-specific review that was validated for this approval.
    #[must_use]
    pub const fn method_review(&self) -> &SessionRequestMethodReview {
        &self.method_review
    }
}

/// Session request approval construction error.
#[derive(thiserror::Error)]
pub enum SessionRequestApprovalError {
    /// Method-specific review failed.
    #[error("session request approval method review failed")]
    MethodReview {
        /// Source method review error.
        #[source]
        source: SessionRequestMethodReviewError,
    },

    /// Request names an account that is not approved for this session request.
    #[error("session request approval account constraint failed: {status:?}")]
    Account {
        /// Account constraint status.
        status: SessionRequestAccountConstraintStatus,
    },

    /// Request names a chain that does not match the enclosing request chain.
    #[error("session request approval chain constraint failed: {status:?}")]
    Chain {
        /// Chain constraint status.
        status: SessionRequestChainConstraintStatus,
    },

    /// Request contains malformed transaction display data.
    #[error("session request approval transaction display field failed: {field}={status}")]
    TransactionDisplay {
        /// Field being decoded for wallet display.
        field: &'static str,
        /// Stable display decode status.
        status: &'static str,
    },

    /// Request contains malformed EIP-712 typed-data payload.
    #[error("session request approval typed-data payload failed: {status:?}")]
    TypedData {
        /// Typed-data payload parse status.
        status: Eip712TypedDataPayloadStatus,
    },

    /// Request contains EIP-712 typed data without enough displayable structure.
    #[error("session request approval typed-data display failed: {status:?}")]
    TypedDataDisplay {
        /// Typed-data displayability status.
        status: Eip712TypedDataDisplayStatus,
    },

    /// Request contains a message-signing payload that cannot be safely displayed.
    #[error("session request approval signing message payload failed: {status:?}")]
    SigningMessage {
        /// Message payload display status.
        status: SigningMessagePayloadStatus,
    },

    /// Request contains an unsupported transaction payload shape.
    #[error("session request approval transaction payload failed: {status:?}")]
    TransactionPayload {
        /// Transaction payload shape status.
        status: EvmTransactionPayloadStatus,
    },

    /// Wallet Call requested chain is not the enclosing request chain.
    #[error("wallet call approval chain constraint failed for {raw_chain_id}: {status:?}")]
    WalletCallChain {
        /// Raw Wallet Call chain id.
        raw_chain_id: String,
        /// Chain constraint status.
        status: WalletCallChainConstraintStatus,
    },

    /// Wallet Call status ID is not owned by this wallet session and chain.
    #[error("wallet call status id approval failed: {status:?}")]
    WalletCallStatusId {
        /// Requested status ID.
        id: String,
        /// Registry binding status.
        status: WalletCallStatusIdBindingStatus,
    },
}

impl fmt::Debug for SessionRequestApprovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MethodReview { source } => formatter
                .debug_struct("MethodReview")
                .field("source", source)
                .finish(),
            Self::Account { status } => formatter
                .debug_struct("Account")
                .field("status", status)
                .finish(),
            Self::Chain { status } => formatter
                .debug_struct("Chain")
                .field("status", status)
                .finish(),
            Self::TransactionDisplay { field, status } => formatter
                .debug_struct("TransactionDisplay")
                .field("field", field)
                .field("status", status)
                .finish(),
            Self::TypedData { status } => formatter
                .debug_struct("TypedData")
                .field("status", status)
                .finish(),
            Self::TypedDataDisplay { status } => formatter
                .debug_struct("TypedDataDisplay")
                .field("status", status)
                .finish(),
            Self::SigningMessage { status } => formatter
                .debug_struct("SigningMessage")
                .field("status", status)
                .finish(),
            Self::TransactionPayload { status } => formatter
                .debug_struct("TransactionPayload")
                .field("status", status)
                .finish(),
            Self::WalletCallChain {
                raw_chain_id,
                status,
            } => formatter
                .debug_struct("WalletCallChain")
                .field("raw_chain_id", &SensitiveStrDebug(raw_chain_id))
                .field("status", status)
                .finish(),
            Self::WalletCallStatusId { id, status } => formatter
                .debug_struct("WalletCallStatusId")
                .field("id", &SensitiveStrDebug(id))
                .field("status", status)
                .finish(),
        }
    }
}

/// Account-authorization status for a method-specific request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRequestAccountConstraintStatus {
    /// The request shape did not name an account.
    NoAccountRequested,
    /// The requested account matches an authorized CAIP-10 account.
    Authorized,
    /// The request names an account, but the review has no active-session accounts.
    NoAuthorizedAccounts,
    /// The requested account is not among authorized accounts for the request chain.
    Unauthorized,
}

/// Requested account matched against authorized session accounts.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionRequestAccountConstraint {
    requested_address: Option<String>,
    authorized_accounts: Vec<Caip10AccountId>,
    matched_account: Option<Caip10AccountId>,
    status: SessionRequestAccountConstraintStatus,
}

impl fmt::Debug for SessionRequestAccountConstraint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionRequestAccountConstraint")
            .field(
                "requested_address",
                &self.requested_address.as_deref().map(SensitiveStrDebug),
            )
            .field("authorized_account_count", &self.authorized_accounts.len())
            .field(
                "matched_account",
                &self.matched_account.as_ref().map(|_| "<present>"),
            )
            .field("status", &self.status)
            .finish()
    }
}

impl SessionRequestAccountConstraint {
    fn new(
        chain_id: &Caip2ChainId,
        authorized_accounts: Vec<Caip10AccountId>,
        requested_address: Option<String>,
    ) -> Self {
        let Some(address) = requested_address else {
            return Self {
                requested_address: None,
                authorized_accounts,
                matched_account: None,
                status: SessionRequestAccountConstraintStatus::NoAccountRequested,
            };
        };

        if authorized_accounts.is_empty() {
            return Self {
                requested_address: Some(address),
                authorized_accounts,
                matched_account: None,
                status: SessionRequestAccountConstraintStatus::NoAuthorizedAccounts,
            };
        }

        let matched_account = authorized_accounts
            .iter()
            .find(|account| account_matches_requested_address(chain_id, account, &address))
            .cloned();
        let status = if matched_account.is_some() {
            SessionRequestAccountConstraintStatus::Authorized
        } else {
            SessionRequestAccountConstraintStatus::Unauthorized
        };

        Self {
            requested_address: Some(address),
            authorized_accounts,
            matched_account,
            status,
        }
    }

    /// Address carried by the method params, when present.
    #[must_use]
    pub fn requested_address(&self) -> Option<&str> {
        self.requested_address.as_deref()
    }

    /// Authorized CAIP-10 accounts considered for this request chain.
    #[must_use]
    pub fn authorized_accounts(&self) -> &[Caip10AccountId] {
        &self.authorized_accounts
    }

    /// Authorized account that matched the requested address.
    #[must_use]
    pub const fn matched_account(&self) -> Option<&Caip10AccountId> {
        self.matched_account.as_ref()
    }

    /// Constraint status.
    #[must_use]
    pub const fn status(&self) -> SessionRequestAccountConstraintStatus {
        self.status
    }

    /// Whether the request named an account authorized for this chain.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        matches!(
            self.status,
            SessionRequestAccountConstraintStatus::Authorized
        )
    }
}

/// Common EVM signing method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRequestKind {
    /// `personal_sign`, usually `[message, address]`.
    PersonalSign,
    /// `eth_sign`, `[address, message]`.
    EthSign,
    /// `eth_signTypedData`, `[address, typedData]`.
    EthSignTypedData,
    /// `eth_signTypedData_v3`, `[address, typedData]`.
    EthSignTypedDataV3,
    /// `eth_signTypedData_v4`, `[address, typedData]`.
    EthSignTypedDataV4,
    /// `eth_signTransaction`, `[transaction]`.
    EthSignTransaction,
}

impl SigningRequestKind {
    fn from_method(method: &str) -> Option<Self> {
        match method {
            "personal_sign" => Some(Self::PersonalSign),
            "eth_sign" => Some(Self::EthSign),
            "eth_signTypedData" => Some(Self::EthSignTypedData),
            "eth_signTypedData_v3" => Some(Self::EthSignTypedDataV3),
            "eth_signTypedData_v4" => Some(Self::EthSignTypedDataV4),
            "eth_signTransaction" => Some(Self::EthSignTransaction),
            _ => None,
        }
    }

    /// JSON-RPC method name.
    #[must_use]
    pub const fn method_name(self) -> &'static str {
        match self {
            Self::PersonalSign => "personal_sign",
            Self::EthSign => "eth_sign",
            Self::EthSignTypedData => "eth_signTypedData",
            Self::EthSignTypedDataV3 => "eth_signTypedData_v3",
            Self::EthSignTypedDataV4 => "eth_signTypedData_v4",
            Self::EthSignTransaction => "eth_signTransaction",
        }
    }

    const fn param_indexes(self) -> (usize, usize) {
        match self {
            Self::PersonalSign => (1, 0),
            Self::EthSign
            | Self::EthSignTypedData
            | Self::EthSignTypedDataV3
            | Self::EthSignTypedDataV4 => (0, 1),
            Self::EthSignTransaction => (0, 0),
        }
    }

    const fn is_typed_data(self) -> bool {
        matches!(
            self,
            Self::EthSignTypedData | Self::EthSignTypedDataV3 | Self::EthSignTypedDataV4
        )
    }

    const fn is_message_signing(self) -> bool {
        matches!(self, Self::PersonalSign | Self::EthSign)
    }

    /// Whether this method should be surfaced as raw-hash signing risk.
    #[must_use]
    pub const fn requires_unsafe_raw_signing_warning(self) -> bool {
        matches!(self, Self::EthSign)
    }
}

/// Parsed signing request review.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningRequestReview {
    kind: SigningRequestKind,
    account: SessionRequestAccountConstraint,
    chain: Option<SessionRequestChainConstraint>,
    payload: Value,
    message: Option<SigningMessageSummary>,
    typed_data: Option<Eip712TypedDataSummary>,
    transaction: Option<EvmTransactionSummary>,
}

impl fmt::Debug for SigningRequestReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningRequestReview")
            .field("kind", &self.kind)
            .field("account", &self.account)
            .field("chain", &self.chain)
            .field("payload", &RedactedJsonDebug(&self.payload))
            .field("message", &self.message)
            .field("typed_data", &self.typed_data)
            .field("transaction", &self.transaction)
            .finish()
    }
}

impl SigningRequestReview {
    /// Signing method kind.
    #[must_use]
    pub const fn kind(&self) -> SigningRequestKind {
        self.kind
    }

    /// Requested account matched against authorized accounts.
    #[must_use]
    pub const fn account(&self) -> &SessionRequestAccountConstraint {
        &self.account
    }

    /// Payload-level chain constraint, when the signing payload names one.
    #[must_use]
    pub const fn chain(&self) -> Option<&SessionRequestChainConstraint> {
        self.chain.as_ref()
    }

    /// Raw message, typed data, or transaction payload that would be signed.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    /// Message display summary for `personal_sign` and `eth_sign`.
    #[must_use]
    pub const fn message(&self) -> Option<&SigningMessageSummary> {
        self.message.as_ref()
    }

    /// Whether wallet UI should warn about raw `eth_sign` semantics.
    #[must_use]
    pub const fn requires_unsafe_raw_signing_warning(&self) -> bool {
        self.kind.requires_unsafe_raw_signing_warning()
    }

    /// EIP-712 typed-data display summary for typed-data signing methods.
    #[must_use]
    pub const fn typed_data(&self) -> Option<&Eip712TypedDataSummary> {
        self.typed_data.as_ref()
    }

    /// Transaction display summary for `eth_signTransaction`.
    #[must_use]
    pub const fn transaction(&self) -> Option<&EvmTransactionSummary> {
        self.transaction.as_ref()
    }
}

/// Parsed `eth_sendTransaction` review.
#[derive(Clone, PartialEq, Eq)]
pub struct TransactionRequestReview {
    account: SessionRequestAccountConstraint,
    chain: Option<SessionRequestChainConstraint>,
    transaction: Value,
    summary: EvmTransactionSummary,
}

impl fmt::Debug for TransactionRequestReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionRequestReview")
            .field("account", &self.account)
            .field("chain", &self.chain)
            .field("transaction", &RedactedJsonDebug(&self.transaction))
            .field("summary", &self.summary)
            .finish()
    }
}

impl TransactionRequestReview {
    /// Requested `from` account matched against authorized accounts.
    #[must_use]
    pub const fn account(&self) -> &SessionRequestAccountConstraint {
        &self.account
    }

    /// Transaction `chainId` matched against the enclosing request chain.
    #[must_use]
    pub const fn chain(&self) -> Option<&SessionRequestChainConstraint> {
        self.chain.as_ref()
    }

    /// Raw transaction object.
    #[must_use]
    pub const fn transaction(&self) -> &Value {
        &self.transaction
    }

    /// Decoded display facts for value, recipient, and calldata.
    #[must_use]
    pub const fn summary(&self) -> &EvmTransactionSummary {
        &self.summary
    }
}

/// Message-signing payload shape for `personal_sign` and `eth_sign`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMessagePayloadStatus {
    /// A non-empty non-hex string that can be rendered as text.
    Utf8String,
    /// A non-empty `0x`-prefixed byte string.
    HexBytes,
    /// The message is empty or `0x` with no bytes.
    Empty,
    /// A `0x`-prefixed byte string has an odd number of hex digits.
    OddLengthHex,
    /// A `0x`-prefixed byte string contains non-hex digits.
    InvalidHex,
    /// The JSON payload is not a string.
    UnsupportedPayload,
}

/// Display summary for a signing message without exposing the message itself.
#[derive(Clone, PartialEq, Eq)]
pub struct SigningMessageSummary {
    status: SigningMessagePayloadStatus,
    byte_len: Option<usize>,
    character_len: Option<usize>,
    payload_hash: VerifyAttestationHash,
    requires_unsafe_raw_signing_warning: bool,
}

impl fmt::Debug for SigningMessageSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningMessageSummary")
            .field("status", &self.status)
            .field("byte_len", &self.byte_len)
            .field("character_len", &self.character_len)
            .field("payload_hash", &self.payload_hash)
            .field(
                "requires_unsafe_raw_signing_warning",
                &self.requires_unsafe_raw_signing_warning,
            )
            .finish()
    }
}

impl SigningMessageSummary {
    fn new(kind: SigningRequestKind, payload: &Value) -> Self {
        let payload_hash = VerifyAttestationHash::from_message(&payload.to_string());
        let Some(message) = payload.as_str() else {
            return Self {
                status: SigningMessagePayloadStatus::UnsupportedPayload,
                byte_len: None,
                character_len: None,
                payload_hash,
                requires_unsafe_raw_signing_warning: kind.requires_unsafe_raw_signing_warning(),
            };
        };

        let Some(hex) = message
            .strip_prefix("0x")
            .or_else(|| message.strip_prefix("0X"))
        else {
            return Self {
                status: if message.is_empty() {
                    SigningMessagePayloadStatus::Empty
                } else {
                    SigningMessagePayloadStatus::Utf8String
                },
                byte_len: Some(message.len()),
                character_len: Some(message.chars().count()),
                payload_hash,
                requires_unsafe_raw_signing_warning: kind.requires_unsafe_raw_signing_warning(),
            };
        };

        let (status, byte_len) = if hex.is_empty() {
            (SigningMessagePayloadStatus::Empty, Some(0))
        } else if hex.len() % 2 != 0 {
            (SigningMessagePayloadStatus::OddLengthHex, None)
        } else if !hex.chars().all(|character| character.is_ascii_hexdigit()) {
            (SigningMessagePayloadStatus::InvalidHex, None)
        } else {
            (SigningMessagePayloadStatus::HexBytes, Some(hex.len() / 2))
        };

        Self {
            status,
            byte_len,
            character_len: None,
            payload_hash,
            requires_unsafe_raw_signing_warning: kind.requires_unsafe_raw_signing_warning(),
        }
    }

    /// Message payload display status.
    #[must_use]
    pub const fn status(&self) -> SigningMessagePayloadStatus {
        self.status
    }

    /// UTF-8 byte length or decoded hex byte length, when known.
    #[must_use]
    pub const fn byte_len(&self) -> Option<usize> {
        self.byte_len
    }

    /// Text character count for non-hex strings, when applicable.
    #[must_use]
    pub const fn character_len(&self) -> Option<usize> {
        self.character_len
    }

    /// Stable hash of the raw signing payload.
    #[must_use]
    pub const fn payload_hash(&self) -> &VerifyAttestationHash {
        &self.payload_hash
    }

    /// Whether wallet UI should warn about raw `eth_sign` semantics.
    #[must_use]
    pub const fn requires_unsafe_raw_signing_warning(&self) -> bool {
        self.requires_unsafe_raw_signing_warning
    }
}

/// Parsed EIP-712 payload shape for typed-data signing UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eip712TypedDataPayloadStatus {
    /// The payload was already a JSON object.
    Object,
    /// The payload was a JSON string that decoded to an object.
    JsonStringObject,
    /// The payload was a string but did not contain valid JSON.
    InvalidJsonString,
    /// The payload was not an object after JSON decoding.
    UnsupportedPayload,
}

/// EIP-712 payload displayability status for wallet approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eip712TypedDataDisplayStatus {
    /// Payload has primary type, matching type definition, and message fields.
    Displayable,
    /// `primaryType` is missing or empty.
    MissingPrimaryType,
    /// `types` does not define the declared primary type.
    MissingPrimaryTypeDefinition,
    /// `message` is missing, not an object, or empty.
    MissingMessageFields,
}

/// EIP-712 typed-data summary for wallet display.
#[derive(Clone, PartialEq, Eq)]
pub struct Eip712TypedDataSummary {
    status: Eip712TypedDataPayloadStatus,
    display_status: Eip712TypedDataDisplayStatus,
    primary_type: Option<String>,
    domain: Eip712DomainSummary,
    type_names: Vec<String>,
    message_keys: Vec<String>,
}

impl fmt::Debug for Eip712TypedDataSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Eip712TypedDataSummary")
            .field("status", &self.status)
            .field("display_status", &self.display_status)
            .field(
                "primary_type",
                &self.primary_type.as_deref().map(SensitiveStrDebug),
            )
            .field("domain", &self.domain)
            .field("type_count", &self.type_names.len())
            .field("message_key_count", &self.message_keys.len())
            .finish()
    }
}

impl Eip712TypedDataSummary {
    fn new(request_chain_id: &Caip2ChainId, payload: &Value) -> Self {
        let (status, parsed) = eip712_payload_object(payload);
        let primary_type = parsed
            .as_ref()
            .and_then(|value| value.get("primaryType"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let domain = parsed
            .as_ref()
            .and_then(|value| value.get("domain"))
            .map_or_else(Eip712DomainSummary::empty, |domain| {
                Eip712DomainSummary::new(request_chain_id, domain)
            });
        let type_names = parsed
            .as_ref()
            .and_then(|value| value.get("types"))
            .and_then(Value::as_object)
            .map_or_else(Vec::new, sorted_keys);
        let message_keys = parsed
            .as_ref()
            .and_then(|value| value.get("message"))
            .and_then(Value::as_object)
            .map_or_else(Vec::new, sorted_keys);
        let display_status =
            eip712_display_status(primary_type.as_deref(), &type_names, &message_keys);

        Self {
            status,
            display_status,
            primary_type,
            domain,
            type_names,
            message_keys,
        }
    }

    /// Payload parse status.
    #[must_use]
    pub const fn status(&self) -> Eip712TypedDataPayloadStatus {
        self.status
    }

    /// Whether the payload has enough structure for wallet display.
    #[must_use]
    pub const fn display_status(&self) -> Eip712TypedDataDisplayStatus {
        self.display_status
    }

    /// EIP-712 `primaryType`, when present.
    #[must_use]
    pub fn primary_type(&self) -> Option<&str> {
        self.primary_type.as_deref()
    }

    /// EIP-712 domain summary.
    #[must_use]
    pub const fn domain(&self) -> &Eip712DomainSummary {
        &self.domain
    }

    /// Sorted top-level type names from the `types` object.
    #[must_use]
    pub fn type_names(&self) -> &[String] {
        &self.type_names
    }

    /// Sorted message object keys.
    #[must_use]
    pub fn message_keys(&self) -> &[String] {
        &self.message_keys
    }
}

/// EIP-712 domain fields most relevant to wallet approval.
#[derive(Clone, PartialEq, Eq)]
pub struct Eip712DomainSummary {
    name: Option<String>,
    version: Option<String>,
    chain: Option<SessionRequestChainConstraint>,
    verifying_contract: Option<EvmAddressSummary>,
    keys: Vec<String>,
}

impl fmt::Debug for Eip712DomainSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Eip712DomainSummary")
            .field("name", &self.name.as_deref().map(SensitiveStrDebug))
            .field("version", &self.version.as_deref().map(SensitiveStrDebug))
            .field("chain", &self.chain)
            .field("verifying_contract", &self.verifying_contract)
            .field("key_count", &self.keys.len())
            .finish()
    }
}

impl Eip712DomainSummary {
    const fn empty() -> Self {
        Self {
            name: None,
            version: None,
            chain: None,
            verifying_contract: None,
            keys: Vec::new(),
        }
    }

    fn new(request_chain_id: &Caip2ChainId, domain: &Value) -> Self {
        let Some(domain) = domain.as_object() else {
            return Self::empty();
        };

        Self {
            name: domain
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            version: domain
                .get("version")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            chain: domain.get("chainId").cloned().map(|raw_chain_id| {
                SessionRequestChainConstraint::new(request_chain_id, raw_chain_id)
            }),
            verifying_contract: domain.get("verifyingContract").map(EvmAddressSummary::new),
            keys: sorted_keys(domain),
        }
    }

    /// EIP-712 domain `name`, when present.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// EIP-712 domain `version`, when present.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Domain `chainId` matched against the enclosing request chain.
    #[must_use]
    pub const fn chain(&self) -> Option<&SessionRequestChainConstraint> {
        self.chain.as_ref()
    }

    /// Domain `verifyingContract` address summary, when present.
    #[must_use]
    pub const fn verifying_contract(&self) -> Option<&EvmAddressSummary> {
        self.verifying_contract.as_ref()
    }

    /// Sorted domain keys present in the typed-data payload.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
}

/// Decoded transaction fields for wallet display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmTransactionSummary {
    status: EvmTransactionPayloadStatus,
    display_field_count: usize,
    to: Option<EvmAddressSummary>,
    value: Option<EvmHexQuantity>,
    data: Option<EvmCalldataSummary>,
}

impl EvmTransactionSummary {
    fn new(transaction: &Value) -> Self {
        let object = transaction.as_object();
        let display_field_count = object.map_or(0, |object| {
            ["to", "value", "data"]
                .into_iter()
                .filter(|field| object.contains_key(*field))
                .count()
        });
        Self {
            status: if object.is_some() {
                EvmTransactionPayloadStatus::Object
            } else {
                EvmTransactionPayloadStatus::UnsupportedPayload
            },
            display_field_count,
            to: transaction.get("to").map(EvmAddressSummary::new),
            value: transaction.get("value").map(EvmHexQuantity::new),
            data: transaction.get("data").map(EvmCalldataSummary::new),
        }
    }

    /// Transaction payload shape status.
    #[must_use]
    pub const fn status(&self) -> EvmTransactionPayloadStatus {
        self.status
    }

    /// Number of display-relevant fields present in the transaction object.
    #[must_use]
    pub const fn display_field_count(&self) -> usize {
        self.display_field_count
    }

    /// Recipient address summary from the `to` field.
    #[must_use]
    pub const fn to(&self) -> Option<&EvmAddressSummary> {
        self.to.as_ref()
    }

    /// Hex wei value summary from the `value` field.
    #[must_use]
    pub const fn value(&self) -> Option<&EvmHexQuantity> {
        self.value.as_ref()
    }

    /// Calldata byte length and selector summary from the `data` field.
    #[must_use]
    pub const fn data(&self) -> Option<&EvmCalldataSummary> {
        self.data.as_ref()
    }
}

/// Transaction payload shape status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmTransactionPayloadStatus {
    /// The payload is a JSON object.
    Object,
    /// The payload is not a JSON object and cannot be safely displayed as a transaction.
    UnsupportedPayload,
}

/// Decoded EVM call tuple for wallet display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmCallSummary {
    display_field_count: usize,
    to: Option<EvmAddressSummary>,
    value: Option<EvmHexQuantity>,
    data: Option<EvmCalldataSummary>,
}

impl EvmCallSummary {
    fn from_wallet_call(call: &WalletCall) -> Self {
        Self {
            display_field_count: usize::from(call.to.is_some())
                + usize::from(call.value.is_some())
                + usize::from(call.data.is_some()),
            to: call
                .to
                .as_deref()
                .map(|to| EvmAddressSummary::new(&Value::String(to.to_owned()))),
            value: call
                .value
                .as_deref()
                .map(|value| EvmHexQuantity::new(&Value::String(value.to_owned()))),
            data: call
                .data
                .as_deref()
                .map(|data| EvmCalldataSummary::new(&Value::String(data.to_owned()))),
        }
    }

    /// Number of display-relevant fields present in the call.
    #[must_use]
    pub const fn display_field_count(&self) -> usize {
        self.display_field_count
    }

    /// Recipient address summary from the `to` field.
    #[must_use]
    pub const fn to(&self) -> Option<&EvmAddressSummary> {
        self.to.as_ref()
    }

    /// Hex wei value summary from the `value` field.
    #[must_use]
    pub const fn value(&self) -> Option<&EvmHexQuantity> {
        self.value.as_ref()
    }

    /// Calldata byte length and selector summary from the `data` field.
    #[must_use]
    pub const fn data(&self) -> Option<&EvmCalldataSummary> {
        self.data.as_ref()
    }
}

/// EVM address display status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmAddressStatus {
    /// The value is a `0x`-prefixed 20-byte hex address.
    Valid,
    /// The value is a string but not a valid 20-byte hex address.
    Invalid,
    /// The JSON value is not a string.
    UnsupportedType,
}

/// EVM address display summary.
#[derive(Clone, PartialEq, Eq)]
pub struct EvmAddressSummary {
    raw: Value,
    address: Option<String>,
    status: EvmAddressStatus,
}

impl fmt::Debug for EvmAddressSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvmAddressSummary")
            .field("raw", &RedactedJsonDebug(&self.raw))
            .field("address", &self.address.as_deref().map(SensitiveStrDebug))
            .field("status", &self.status)
            .finish()
    }
}

impl EvmAddressSummary {
    fn new(raw: &Value) -> Self {
        let Some(address) = raw.as_str() else {
            return Self {
                raw: raw.clone(),
                address: None,
                status: EvmAddressStatus::UnsupportedType,
            };
        };
        let status = if is_prefixed_hex_with_len(address, 40) {
            EvmAddressStatus::Valid
        } else {
            EvmAddressStatus::Invalid
        };
        Self {
            raw: raw.clone(),
            address: Some(address.to_owned()),
            status,
        }
    }

    /// Raw JSON value from the request.
    #[must_use]
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    /// Address string when the request value was a string.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.address.as_deref()
    }

    /// Address parse status.
    #[must_use]
    pub const fn status(&self) -> EvmAddressStatus {
        self.status
    }
}

/// Hex quantity display status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmHexQuantityStatus {
    /// The value decoded as a `0x`-prefixed hex quantity.
    Decoded,
    /// The value is a string without a `0x` prefix.
    MissingPrefix,
    /// The value is `0x` without hex digits.
    Empty,
    /// The value contains non-hex characters.
    InvalidHex,
    /// The JSON value is not a string.
    UnsupportedType,
}

/// Hex quantity summary with an arbitrary-size decimal rendering.
#[derive(Clone, PartialEq, Eq)]
pub struct EvmHexQuantity {
    raw: Value,
    decimal: Option<String>,
    status: EvmHexQuantityStatus,
}

impl fmt::Debug for EvmHexQuantity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvmHexQuantity")
            .field("raw", &RedactedJsonDebug(&self.raw))
            .field("decimal", &self.decimal.as_deref().map(SensitiveStrDebug))
            .field("status", &self.status)
            .finish()
    }
}

impl EvmHexQuantity {
    fn new(raw: &Value) -> Self {
        let Some(value) = raw.as_str() else {
            return Self {
                raw: raw.clone(),
                decimal: None,
                status: EvmHexQuantityStatus::UnsupportedType,
            };
        };
        let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        else {
            return Self {
                raw: raw.clone(),
                decimal: None,
                status: EvmHexQuantityStatus::MissingPrefix,
            };
        };
        if hex.is_empty() {
            return Self {
                raw: raw.clone(),
                decimal: None,
                status: EvmHexQuantityStatus::Empty,
            };
        }
        let Some(decimal) = hex_to_decimal_string(hex) else {
            return Self {
                raw: raw.clone(),
                decimal: None,
                status: EvmHexQuantityStatus::InvalidHex,
            };
        };
        Self {
            raw: raw.clone(),
            decimal: Some(decimal),
            status: EvmHexQuantityStatus::Decoded,
        }
    }

    /// Raw JSON value from the request.
    #[must_use]
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    /// Decimal quantity string when decoding succeeded.
    #[must_use]
    pub fn decimal(&self) -> Option<&str> {
        self.decimal.as_deref()
    }

    /// Quantity decode status.
    #[must_use]
    pub const fn status(&self) -> EvmHexQuantityStatus {
        self.status
    }
}

/// Calldata display status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmCalldataStatus {
    /// The value decoded as `0x`-prefixed bytes.
    Decoded,
    /// The value is a string without a `0x` prefix.
    MissingPrefix,
    /// The value contains an odd number of hex characters.
    OddLength,
    /// The value contains non-hex characters.
    InvalidHex,
    /// The JSON value is not a string.
    UnsupportedType,
}

/// Calldata summary for wallet display.
#[derive(Clone, PartialEq, Eq)]
pub struct EvmCalldataSummary {
    raw: Value,
    byte_len: Option<usize>,
    function_selector: Option<String>,
    status: EvmCalldataStatus,
}

impl fmt::Debug for EvmCalldataSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvmCalldataSummary")
            .field("raw", &RedactedJsonDebug(&self.raw))
            .field("byte_len", &self.byte_len)
            .field(
                "function_selector",
                &self.function_selector.as_deref().map(SensitiveStrDebug),
            )
            .field("status", &self.status)
            .finish()
    }
}

impl EvmCalldataSummary {
    fn new(raw: &Value) -> Self {
        let Some(value) = raw.as_str() else {
            return Self {
                raw: raw.clone(),
                byte_len: None,
                function_selector: None,
                status: EvmCalldataStatus::UnsupportedType,
            };
        };
        let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        else {
            return Self {
                raw: raw.clone(),
                byte_len: None,
                function_selector: None,
                status: EvmCalldataStatus::MissingPrefix,
            };
        };
        if hex.len() % 2 != 0 {
            return Self {
                raw: raw.clone(),
                byte_len: None,
                function_selector: None,
                status: EvmCalldataStatus::OddLength,
            };
        }
        if !hex.chars().all(|character| character.is_ascii_hexdigit()) {
            return Self {
                raw: raw.clone(),
                byte_len: None,
                function_selector: None,
                status: EvmCalldataStatus::InvalidHex,
            };
        }
        Self {
            raw: raw.clone(),
            byte_len: Some(hex.len() / 2),
            function_selector: (hex.len() >= 8).then(|| format!("0x{}", &hex[..8])),
            status: EvmCalldataStatus::Decoded,
        }
    }

    /// Raw JSON value from the request.
    #[must_use]
    pub const fn raw(&self) -> &Value {
        &self.raw
    }

    /// Decoded byte length.
    #[must_use]
    pub const fn byte_len(&self) -> Option<usize> {
        self.byte_len
    }

    /// First four calldata bytes as a function selector, when present.
    #[must_use]
    pub fn function_selector(&self) -> Option<&str> {
        self.function_selector.as_deref()
    }

    /// Calldata decode status.
    #[must_use]
    pub const fn status(&self) -> EvmCalldataStatus {
        self.status
    }
}

/// Chain comparison status for method payload chain IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRequestChainConstraintStatus {
    /// Payload chain parses to the enclosing `wc_sessionRequest` chain.
    MatchesRequestChain,
    /// Payload chain parses but differs from the enclosing request chain.
    DiffersFromRequestChain,
    /// Payload chain is not an EIP-155 CAIP-2, decimal, or hexadecimal chain ID.
    UnsupportedChainIdFormat,
}

/// Method payload chain ID matched against the enclosing request chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestChainConstraint {
    raw_chain_id: Value,
    caip2_chain_id: Option<Caip2ChainId>,
    status: SessionRequestChainConstraintStatus,
}

impl SessionRequestChainConstraint {
    fn new(request_chain_id: &Caip2ChainId, raw_chain_id: Value) -> Self {
        let caip2_chain_id = eip155_value_to_caip2(&raw_chain_id);
        let status = match caip2_chain_id.as_ref() {
            Some(chain_id) if chain_id == request_chain_id => {
                SessionRequestChainConstraintStatus::MatchesRequestChain
            }
            Some(_) => SessionRequestChainConstraintStatus::DiffersFromRequestChain,
            None => SessionRequestChainConstraintStatus::UnsupportedChainIdFormat,
        };

        Self {
            raw_chain_id,
            caip2_chain_id,
            status,
        }
    }

    /// Raw payload chain value.
    #[must_use]
    pub const fn raw_chain_id(&self) -> &Value {
        &self.raw_chain_id
    }

    /// Parsed CAIP-2 `eip155:<decimal>` chain, when valid.
    #[must_use]
    pub const fn caip2_chain_id(&self) -> Option<&Caip2ChainId> {
        self.caip2_chain_id.as_ref()
    }

    /// Chain comparison status.
    #[must_use]
    pub const fn status(&self) -> SessionRequestChainConstraintStatus {
        self.status
    }
}

/// EIP-5792 Wallet Call method review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletCallReview {
    /// `wallet_getCapabilities` disclosure request.
    GetCapabilities(WalletGetCapabilitiesReview),
    /// `wallet_sendCalls` batch submission request.
    SendCalls(WalletSendCallsReview),
    /// `wallet_getCallsStatus` status lookup request.
    GetCallsStatus(WalletCallStatusReview),
    /// `wallet_showCallsStatus` display request.
    ShowCallsStatus(WalletCallStatusReview),
}

/// Review for `wallet_getCapabilities`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletGetCapabilitiesReview {
    address: SessionRequestAccountConstraint,
    requested_chains: Vec<WalletCallChainConstraint>,
}

impl WalletGetCapabilitiesReview {
    /// Address whose capabilities would be disclosed.
    #[must_use]
    pub const fn address(&self) -> &SessionRequestAccountConstraint {
        &self.address
    }

    /// Requested EIP-155 chains, when the dapp supplied the optional list.
    #[must_use]
    pub fn requested_chains(&self) -> &[WalletCallChainConstraint] {
        &self.requested_chains
    }
}

/// Review for `wallet_sendCalls`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSendCallsReview {
    from: SessionRequestAccountConstraint,
    requested_chain: WalletCallChainConstraint,
    call_count: usize,
    atomic_required: bool,
    capability_keys: Vec<String>,
    calls: Vec<EvmCallSummary>,
}

impl WalletSendCallsReview {
    /// Sender account matched against authorized accounts.
    #[must_use]
    pub const fn from(&self) -> &SessionRequestAccountConstraint {
        &self.from
    }

    /// EIP-155 chain ID matched against the enclosing CAIP-2 request chain.
    #[must_use]
    pub const fn requested_chain(&self) -> &WalletCallChainConstraint {
        &self.requested_chain
    }

    /// Number of calls in the requested batch.
    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.call_count
    }

    /// Whether the dapp requires atomic execution.
    #[must_use]
    pub const fn atomic_required(&self) -> bool {
        self.atomic_required
    }

    /// Capability keys requested at top level or per call.
    #[must_use]
    pub fn capability_keys(&self) -> &[String] {
        &self.capability_keys
    }

    /// Per-call display summaries for target, value, and calldata.
    #[must_use]
    pub fn calls(&self) -> &[EvmCallSummary] {
        &self.calls
    }
}

/// Status identifier review for Wallet Call status methods.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletCallStatusReview {
    id: String,
    binding: WalletCallStatusIdBinding,
}

impl fmt::Debug for WalletCallStatusReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletCallStatusReview")
            .field("id", &SensitiveStrDebug(&self.id))
            .field("binding", &self.binding)
            .finish()
    }
}

impl WalletCallStatusReview {
    /// Wallet Call bundle identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Registry binding for this status identifier.
    #[must_use]
    pub const fn binding(&self) -> &WalletCallStatusIdBinding {
        &self.binding
    }
}

/// Wallet-owned registry of `wallet_sendCalls` result identifiers.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct WalletCallStatusRegistry {
    entries: BTreeMap<String, Vec<WalletCallStatusRegistryEntry>>,
}

impl fmt::Debug for WalletCallStatusRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry_count: usize = self.entries.values().map(Vec::len).sum();
        formatter
            .debug_struct("WalletCallStatusRegistry")
            .field("id_count", &self.entries.len())
            .field("entry_count", &entry_count)
            .finish()
    }
}

impl WalletCallStatusRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a wallet-returned Wallet Call status identifier.
    pub fn insert(&mut self, entry: WalletCallStatusRegistryEntry) {
        let entries = self.entries.entry(entry.id.clone()).or_default();
        if !entries.contains(&entry) {
            entries.push(entry);
        }
    }

    /// Inserts the ID returned for a reviewed `wallet_sendCalls` request.
    ///
    /// This helper only accepts send-call reviews whose EIP-5792 chain matches
    /// the enclosing `wc_sessionRequest` chain, so later status requests can be
    /// bound to the same session topic and chain.
    pub fn insert_send_calls_result(
        &mut self,
        review: &SessionRequestReview,
        result: &WalletSendCallsResult,
    ) -> Result<(), WalletCallStatusRegistryError> {
        let Some(WalletCallReview::SendCalls(send_calls)) = review.wallet_call_review()? else {
            return Err(WalletCallStatusRegistryError::NotSendCalls {
                method: review.method().clone(),
            });
        };
        if send_calls.requested_chain().status()
            != WalletCallChainConstraintStatus::MatchesRequestChain
        {
            return Err(WalletCallStatusRegistryError::UnsupportedChain {
                raw_chain_id: send_calls.requested_chain().raw_chain_id().to_owned(),
                status: send_calls.requested_chain().status(),
            });
        }
        let chain_id = send_calls
            .requested_chain()
            .caip2_chain_id()
            .expect("matching wallet-call chain has parsed CAIP-2")
            .clone();
        self.insert(WalletCallStatusRegistryEntry::new(
            result.id.clone(),
            review.topic().clone(),
            chain_id,
        ));
        Ok(())
    }

    fn binding_for(
        &self,
        id: &str,
        topic: &RelayTopic,
        chain_id: &Caip2ChainId,
    ) -> WalletCallStatusIdBinding {
        let Some(entries) = self.entries.get(id) else {
            return WalletCallStatusIdBinding {
                status: WalletCallStatusIdBindingStatus::Unknown,
                matched_entry: None,
            };
        };
        if let Some(entry) = entries
            .iter()
            .find(|entry| entry.topic() == topic && entry.chain_id() == chain_id)
        {
            return WalletCallStatusIdBinding {
                status: WalletCallStatusIdBindingStatus::Owned,
                matched_entry: Some(entry.clone()),
            };
        }
        if entries.iter().any(|entry| entry.topic() == topic) {
            return WalletCallStatusIdBinding {
                status: WalletCallStatusIdBindingStatus::ChainMismatch,
                matched_entry: None,
            };
        }
        WalletCallStatusIdBinding {
            status: WalletCallStatusIdBindingStatus::TopicMismatch,
            matched_entry: None,
        }
    }
}

/// Wallet-owned Wallet Call status registry insertion error.
#[derive(Debug, thiserror::Error)]
pub enum WalletCallStatusRegistryError {
    /// The source review is not for `wallet_sendCalls`.
    #[error("wallet call status registry entry requires wallet_sendCalls, got {method}")]
    NotSendCalls {
        /// Method carried by the source review.
        method: SessionMethod,
    },

    /// The send-calls chain was malformed or did not match the request chain.
    #[error("wallet call status registry entry has unsupported chain {raw_chain_id}: {status:?}")]
    UnsupportedChain {
        /// Raw Wallet Call chain id.
        raw_chain_id: String,
        /// Chain comparison status.
        status: WalletCallChainConstraintStatus,
    },

    /// The source review could not be parsed as Wallet Call.
    #[error(transparent)]
    Review(#[from] SessionRequestMethodReviewError),
}

/// Wallet-owned status identifier registry entry.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletCallStatusRegistryEntry {
    id: String,
    topic: RelayTopic,
    chain_id: Caip2ChainId,
}

impl fmt::Debug for WalletCallStatusRegistryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletCallStatusRegistryEntry")
            .field("id", &SensitiveStrDebug(&self.id))
            .field("topic", &self.topic)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl WalletCallStatusRegistryEntry {
    /// Creates a registry entry for a wallet-returned call bundle ID.
    #[must_use]
    pub fn new(id: impl Into<String>, topic: RelayTopic, chain_id: Caip2ChainId) -> Self {
        Self {
            id: id.into(),
            topic,
            chain_id,
        }
    }

    /// Wallet Call bundle identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Session topic that received the original `wallet_sendCalls` request.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Chain used by the original call bundle.
    #[must_use]
    pub const fn chain_id(&self) -> &Caip2ChainId {
        &self.chain_id
    }
}

/// Registry binding for a Wallet Call status ID.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletCallStatusIdBinding {
    status: WalletCallStatusIdBindingStatus,
    matched_entry: Option<WalletCallStatusRegistryEntry>,
}

impl fmt::Debug for WalletCallStatusIdBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletCallStatusIdBinding")
            .field("status", &self.status)
            .field(
                "matched_entry",
                &self.matched_entry.as_ref().map(|_| "<present>"),
            )
            .finish()
    }
}

impl WalletCallStatusIdBinding {
    const fn unchecked() -> Self {
        Self {
            status: WalletCallStatusIdBindingStatus::Unchecked,
            matched_entry: None,
        }
    }

    /// Status identifier binding status.
    #[must_use]
    pub const fn status(&self) -> WalletCallStatusIdBindingStatus {
        self.status
    }

    /// Matching registry entry when the ID is owned by this session and chain.
    #[must_use]
    pub const fn matched_entry(&self) -> Option<&WalletCallStatusRegistryEntry> {
        self.matched_entry.as_ref()
    }
}

/// Status for binding a Wallet Call status ID to wallet-owned state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCallStatusIdBindingStatus {
    /// No registry was supplied, so the ID has not been checked.
    Unchecked,
    /// The ID is owned by the same session topic and request chain.
    Owned,
    /// The ID is not known to the wallet registry.
    Unknown,
    /// The ID exists but belongs to another session topic.
    TopicMismatch,
    /// The ID exists for this topic but another chain.
    ChainMismatch,
}

/// Chain comparison status for Wallet Call EIP-155 chain IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCallChainConstraintStatus {
    /// Chain ID parses to the enclosing `wc_sessionRequest` chain.
    MatchesRequestChain,
    /// Chain ID parses but differs from the enclosing request chain.
    DiffersFromRequestChain,
    /// Chain ID is not an EIP-155 CAIP-2, decimal, or hexadecimal chain ID.
    UnsupportedChainIdFormat,
}

/// Wallet Call EIP-155 chain ID matched against the enclosing CAIP-2 request chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCallChainConstraint {
    raw_chain_id: String,
    caip2_chain_id: Option<Caip2ChainId>,
    status: WalletCallChainConstraintStatus,
}

impl WalletCallChainConstraint {
    fn new(request_chain_id: &Caip2ChainId, raw_chain_id: String) -> Self {
        let caip2_chain_id = eip155_string_to_caip2(&raw_chain_id);
        let status = match caip2_chain_id.as_ref() {
            Some(chain_id) if chain_id == request_chain_id => {
                WalletCallChainConstraintStatus::MatchesRequestChain
            }
            Some(_) => WalletCallChainConstraintStatus::DiffersFromRequestChain,
            None => WalletCallChainConstraintStatus::UnsupportedChainIdFormat,
        };

        Self {
            raw_chain_id,
            caip2_chain_id,
            status,
        }
    }

    /// Raw chain ID from the Wallet Call params.
    #[must_use]
    pub fn raw_chain_id(&self) -> &str {
        &self.raw_chain_id
    }

    /// Parsed CAIP-2 `eip155:<decimal>` chain, when valid.
    #[must_use]
    pub const fn caip2_chain_id(&self) -> Option<&Caip2ChainId> {
        self.caip2_chain_id.as_ref()
    }

    /// Chain comparison status.
    #[must_use]
    pub const fn status(&self) -> WalletCallChainConstraintStatus {
        self.status
    }
}

fn validate_method_review_for_approval(
    review: &SessionRequestMethodReview,
) -> Result<(), SessionRequestApprovalError> {
    match review {
        SessionRequestMethodReview::Signing(signing) => {
            if let Some(message) = signing.message() {
                validate_signing_message_summary_for_approval(message)?;
            }
            if let Some(typed_data) = signing.typed_data() {
                validate_typed_data_summary_for_approval(typed_data)?;
            }
            if let Some(transaction) = signing.transaction() {
                validate_transaction_summary_for_approval(transaction)?;
            }
            validate_explicit_account_for_approval(signing.account())?;
            validate_session_chain_for_approval(signing.chain())?;
        }
        SessionRequestMethodReview::Transaction(transaction) => {
            validate_transaction_summary_for_approval(transaction.summary())?;
            validate_explicit_account_for_approval(transaction.account())?;
            validate_session_chain_for_approval(transaction.chain())?;
        }
        SessionRequestMethodReview::WalletCall(wallet_call) => {
            validate_wallet_call_for_approval(wallet_call)?;
        }
        SessionRequestMethodReview::Raw => {}
    }
    Ok(())
}

fn validate_wallet_call_for_approval(
    review: &WalletCallReview,
) -> Result<(), SessionRequestApprovalError> {
    match review {
        WalletCallReview::GetCapabilities(capabilities) => {
            validate_account_for_approval(capabilities.address())?;
            for chain in capabilities.requested_chains() {
                validate_wallet_call_chain_for_approval(chain)?;
            }
        }
        WalletCallReview::SendCalls(send_calls) => {
            validate_account_for_approval(send_calls.from())?;
            validate_wallet_call_chain_for_approval(send_calls.requested_chain())?;
            if send_calls.call_count() == 0 {
                return Err(SessionRequestApprovalError::TransactionDisplay {
                    field: "calls",
                    status: "missing_display_fields",
                });
            }
            for call in send_calls.calls() {
                validate_call_summary_for_approval(call)?;
            }
        }
        WalletCallReview::GetCallsStatus(status) | WalletCallReview::ShowCallsStatus(status) => {
            validate_wallet_call_status_binding_for_approval(status)?;
        }
    }
    Ok(())
}

const fn validate_account_for_approval(
    account: &SessionRequestAccountConstraint,
) -> Result<(), SessionRequestApprovalError> {
    match account.status() {
        SessionRequestAccountConstraintStatus::NoAccountRequested
        | SessionRequestAccountConstraintStatus::Authorized => Ok(()),
        status => Err(SessionRequestApprovalError::Account { status }),
    }
}

const fn validate_explicit_account_for_approval(
    account: &SessionRequestAccountConstraint,
) -> Result<(), SessionRequestApprovalError> {
    match account.status() {
        SessionRequestAccountConstraintStatus::Authorized => Ok(()),
        status => Err(SessionRequestApprovalError::Account { status }),
    }
}

fn validate_session_chain_for_approval(
    chain: Option<&SessionRequestChainConstraint>,
) -> Result<(), SessionRequestApprovalError> {
    match chain.map(SessionRequestChainConstraint::status) {
        None | Some(SessionRequestChainConstraintStatus::MatchesRequestChain) => Ok(()),
        Some(status) => Err(SessionRequestApprovalError::Chain { status }),
    }
}

fn validate_wallet_call_chain_for_approval(
    chain: &WalletCallChainConstraint,
) -> Result<(), SessionRequestApprovalError> {
    if chain.status() == WalletCallChainConstraintStatus::MatchesRequestChain {
        return Ok(());
    }
    Err(SessionRequestApprovalError::WalletCallChain {
        raw_chain_id: chain.raw_chain_id().to_owned(),
        status: chain.status(),
    })
}

fn validate_wallet_call_status_binding_for_approval(
    status: &WalletCallStatusReview,
) -> Result<(), SessionRequestApprovalError> {
    if status.binding().status() == WalletCallStatusIdBindingStatus::Owned {
        return Ok(());
    }
    Err(SessionRequestApprovalError::WalletCallStatusId {
        id: status.id().to_owned(),
        status: status.binding().status(),
    })
}

fn validate_typed_data_summary_for_approval(
    summary: &Eip712TypedDataSummary,
) -> Result<(), SessionRequestApprovalError> {
    match summary.status() {
        Eip712TypedDataPayloadStatus::Object | Eip712TypedDataPayloadStatus::JsonStringObject => {}
        status => return Err(SessionRequestApprovalError::TypedData { status }),
    }
    if summary.display_status() != Eip712TypedDataDisplayStatus::Displayable {
        return Err(SessionRequestApprovalError::TypedDataDisplay {
            status: summary.display_status(),
        });
    }
    if let Some(chain) = summary.domain().chain() {
        validate_session_chain_for_approval(Some(chain))?;
    }
    if let Some(verifying_contract) = summary.domain().verifying_contract() {
        validate_address_summary_for_approval("typed_data.verifyingContract", verifying_contract)?;
    }
    Ok(())
}

const fn validate_signing_message_summary_for_approval(
    summary: &SigningMessageSummary,
) -> Result<(), SessionRequestApprovalError> {
    match summary.status() {
        SigningMessagePayloadStatus::Utf8String | SigningMessagePayloadStatus::HexBytes => Ok(()),
        status => Err(SessionRequestApprovalError::SigningMessage { status }),
    }
}

fn validate_transaction_summary_for_approval(
    summary: &EvmTransactionSummary,
) -> Result<(), SessionRequestApprovalError> {
    if summary.status() != EvmTransactionPayloadStatus::Object {
        return Err(SessionRequestApprovalError::TransactionPayload {
            status: summary.status(),
        });
    }
    if summary.display_field_count() == 0 {
        return Err(SessionRequestApprovalError::TransactionDisplay {
            field: "transaction",
            status: "missing_display_fields",
        });
    }
    if let Some(to) = summary.to() {
        validate_address_summary_for_approval("to", to)?;
    }
    if let Some(value) = summary.value() {
        validate_hex_quantity_for_approval("value", value)?;
    }
    if let Some(data) = summary.data() {
        validate_calldata_for_approval("data", data)?;
    }
    Ok(())
}

fn validate_call_summary_for_approval(
    summary: &EvmCallSummary,
) -> Result<(), SessionRequestApprovalError> {
    if summary.display_field_count() == 0 {
        return Err(SessionRequestApprovalError::TransactionDisplay {
            field: "call",
            status: "missing_display_fields",
        });
    }
    if let Some(to) = summary.to() {
        validate_address_summary_for_approval("to", to)?;
    }
    if let Some(value) = summary.value() {
        validate_hex_quantity_for_approval("value", value)?;
    }
    if let Some(data) = summary.data() {
        validate_calldata_for_approval("data", data)?;
    }
    Ok(())
}

fn validate_address_summary_for_approval(
    field: &'static str,
    summary: &EvmAddressSummary,
) -> Result<(), SessionRequestApprovalError> {
    if summary.status() == EvmAddressStatus::Valid {
        return Ok(());
    }
    Err(SessionRequestApprovalError::TransactionDisplay {
        field,
        status: evm_address_status_name(summary.status()),
    })
}

fn validate_hex_quantity_for_approval(
    field: &'static str,
    summary: &EvmHexQuantity,
) -> Result<(), SessionRequestApprovalError> {
    if summary.status() == EvmHexQuantityStatus::Decoded {
        return Ok(());
    }
    Err(SessionRequestApprovalError::TransactionDisplay {
        field,
        status: evm_hex_quantity_status_name(summary.status()),
    })
}

fn validate_calldata_for_approval(
    field: &'static str,
    summary: &EvmCalldataSummary,
) -> Result<(), SessionRequestApprovalError> {
    if summary.status() == EvmCalldataStatus::Decoded {
        return Ok(());
    }
    Err(SessionRequestApprovalError::TransactionDisplay {
        field,
        status: evm_calldata_status_name(summary.status()),
    })
}

const fn evm_address_status_name(status: EvmAddressStatus) -> &'static str {
    match status {
        EvmAddressStatus::Valid => "valid",
        EvmAddressStatus::Invalid => "invalid",
        EvmAddressStatus::UnsupportedType => "unsupported_type",
    }
}

const fn evm_hex_quantity_status_name(status: EvmHexQuantityStatus) -> &'static str {
    match status {
        EvmHexQuantityStatus::Decoded => "decoded",
        EvmHexQuantityStatus::MissingPrefix => "missing_prefix",
        EvmHexQuantityStatus::Empty => "empty",
        EvmHexQuantityStatus::InvalidHex => "invalid_hex",
        EvmHexQuantityStatus::UnsupportedType => "unsupported_type",
    }
}

const fn evm_calldata_status_name(status: EvmCalldataStatus) -> &'static str {
    match status {
        EvmCalldataStatus::Decoded => "decoded",
        EvmCalldataStatus::MissingPrefix => "missing_prefix",
        EvmCalldataStatus::OddLength => "odd_length",
        EvmCalldataStatus::InvalidHex => "invalid_hex",
        EvmCalldataStatus::UnsupportedType => "unsupported_type",
    }
}

fn eip712_payload_object(payload: &Value) -> (Eip712TypedDataPayloadStatus, Option<Value>) {
    match payload {
        Value::Object(_) => (Eip712TypedDataPayloadStatus::Object, Some(payload.clone())),
        Value::String(value) => match serde_json::from_str::<Value>(value) {
            Ok(parsed @ Value::Object(_)) => {
                (Eip712TypedDataPayloadStatus::JsonStringObject, Some(parsed))
            }
            Ok(_) => (Eip712TypedDataPayloadStatus::UnsupportedPayload, None),
            Err(_) => (Eip712TypedDataPayloadStatus::InvalidJsonString, None),
        },
        _ => (Eip712TypedDataPayloadStatus::UnsupportedPayload, None),
    }
}

fn eip712_display_status(
    primary_type: Option<&str>,
    type_names: &[String],
    message_keys: &[String],
) -> Eip712TypedDataDisplayStatus {
    let Some(primary_type) = primary_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Eip712TypedDataDisplayStatus::MissingPrimaryType;
    };
    if !type_names.iter().any(|type_name| type_name == primary_type) {
        return Eip712TypedDataDisplayStatus::MissingPrimaryTypeDefinition;
    }
    if message_keys.is_empty() {
        return Eip712TypedDataDisplayStatus::MissingMessageFields;
    }
    Eip712TypedDataDisplayStatus::Displayable
}

struct RedactedJsonDebug<'a>(&'a Value);

impl fmt::Debug for RedactedJsonDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let canonical = self.0.to_string();
        let hash = VerifyAttestationHash::from_message(&canonical);
        formatter
            .debug_struct("RedactedJson")
            .field("kind", &json_kind(self.0))
            .field("len", &json_value_len(self.0))
            .field("hash", &hash)
            .finish()
    }
}

struct SensitiveStrDebug<'a>(&'a str);

impl fmt::Debug for SensitiveStrDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = VerifyAttestationHash::from_message(self.0);
        formatter
            .debug_struct("SensitiveStr")
            .field("len", &self.0.len())
            .field("hash", &hash)
            .finish()
    }
}

struct RedactedVerifyContextDebug<'a>(&'a VerifyContext);

impl fmt::Debug for RedactedVerifyContextDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifyContext")
            .field("risk", &classify_verify_context(self.0))
            .finish_non_exhaustive()
    }
}

const fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn json_value_len(value: &Value) -> Option<usize> {
    match value {
        Value::String(value) => Some(value.len()),
        Value::Array(value) => Some(value.len()),
        Value::Object(value) => Some(value.len()),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

fn sorted_keys(map: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut keys = map.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    keys
}

fn is_prefixed_hex_with_len(value: &str, expected_hex_len: usize) -> bool {
    let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    else {
        return false;
    };
    hex.len() == expected_hex_len && hex.chars().all(|character| character.is_ascii_hexdigit())
}

fn hex_to_decimal_string(hex: &str) -> Option<String> {
    let mut digits = vec![0_u8];
    for character in hex.chars() {
        let nibble = u8::try_from(character.to_digit(16)?).ok()?;
        let mut carry = nibble;
        for digit in &mut digits {
            let value = (*digit * 16) + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    Some(
        digits
            .into_iter()
            .rev()
            .map(|digit| char::from(b'0' + digit))
            .collect(),
    )
}

fn filter_accounts_for_chain<I>(chain_id: &Caip2ChainId, accounts: I) -> Vec<Caip10AccountId>
where
    I: IntoIterator<Item = Caip10AccountId>,
{
    let mut seen = BTreeSet::new();
    let mut filtered = Vec::new();
    for account in accounts {
        if account.chain_id() == *chain_id && seen.insert(account.clone()) {
            filtered.push(account);
        }
    }
    filtered
}

fn account_matches_requested_address(
    chain_id: &Caip2ChainId,
    account: &Caip10AccountId,
    requested_address: &str,
) -> bool {
    if account.chain_id() != *chain_id {
        return false;
    }
    if chain_id.namespace() == "eip155" {
        account.address().eq_ignore_ascii_case(requested_address)
    } else {
        account.address() == requested_address
    }
}

fn wallet_call_capability_keys<T>(
    capabilities: Option<&BTreeMap<String, T>>,
) -> impl Iterator<Item = String> + '_ {
    capabilities
        .into_iter()
        .flat_map(|capabilities| capabilities.keys().cloned())
}

fn eip712_domain_chain_id(payload: &Value) -> Option<Value> {
    let parsed;
    let value = if let Some(payload) = payload.as_str() {
        parsed = serde_json::from_str::<Value>(payload).ok()?;
        &parsed
    } else {
        payload
    };
    value.get("domain")?.get("chainId").cloned()
}

fn eip155_value_to_caip2(raw_chain_id: &Value) -> Option<Caip2ChainId> {
    match raw_chain_id {
        Value::Number(number) => number
            .as_u64()
            .and_then(|chain_id| Caip2ChainId::from_parts("eip155", &chain_id.to_string()).ok()),
        Value::String(value) => eip155_string_to_caip2(value),
        _ => None,
    }
}

fn eip155_string_to_caip2(raw_chain_id: &str) -> Option<Caip2ChainId> {
    if let Ok(chain_id) = raw_chain_id.parse::<Caip2ChainId>() {
        return (chain_id.namespace() == "eip155").then_some(chain_id);
    }

    if let Some(hex) = raw_chain_id
        .strip_prefix("0x")
        .or_else(|| raw_chain_id.strip_prefix("0X"))
    {
        if hex.is_empty() {
            return None;
        }
        return u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|chain_id| Caip2ChainId::from_parts("eip155", &chain_id.to_string()).ok());
    }

    raw_chain_id
        .parse::<u64>()
        .ok()
        .and_then(|chain_id| Caip2ChainId::from_parts("eip155", &chain_id.to_string()).ok())
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
            WalletSendCallsParams, WalletSendCallsResult,
        },
        verify::{VerifyContext, VerifyValidation},
    };

    use super::{
        Eip712TypedDataDisplayStatus, Eip712TypedDataPayloadStatus, EvmAddressStatus,
        EvmCalldataStatus, EvmHexQuantityStatus, EvmTransactionPayloadStatus,
        SessionRequestAccountConstraintStatus, SessionRequestApproval, SessionRequestApprovalError,
        SessionRequestChainConstraintStatus, SessionRequestMethodReview,
        SessionRequestMethodReviewError, SessionRequestReview, SigningMessagePayloadStatus,
        SigningRequestKind, UnknownSessionRequestMethodPolicy, WalletCallChainConstraintStatus,
        WalletCallReview, WalletCallStatusIdBindingStatus, WalletCallStatusRegistry,
        WalletCallStatusRegistryEntry,
    };
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

    #[test]
    fn signing_review_matches_personal_sign_account_case_insensitively()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!(["0x68656c6c6f", "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?,
                    "eip155:137:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".parse()?,
                ]);

        let signing = review
            .signing_request_review()?
            .expect("personal_sign review");

        assert_eq!(signing.kind(), SigningRequestKind::PersonalSign);
        assert_eq!(signing.payload(), &json!("0x68656c6c6f"));
        let message = signing.message().expect("message summary");
        assert_eq!(message.status(), SigningMessagePayloadStatus::HexBytes);
        assert_eq!(message.byte_len(), Some(5));
        assert_eq!(message.character_len(), None);
        assert!(!message.requires_unsafe_raw_signing_warning());
        assert_eq!(
            signing.account().status(),
            SessionRequestAccountConstraintStatus::Authorized
        );
        assert_eq!(signing.account().authorized_accounts().len(), 1);
        assert_eq!(
            signing.account().matched_account().map(ToString::to_string),
            Some("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".to_owned())
        );

        Ok(())
    }

    #[test]
    fn signing_review_flags_unauthorized_account() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_sign".parse()?,
                    params: json!(["0x2222222222222222222222222222222222222222", "0x68656c6c6f"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let signing = review.signing_request_review()?.expect("eth_sign review");

        assert_eq!(signing.kind(), SigningRequestKind::EthSign);
        let message = signing.message().expect("message summary");
        assert_eq!(message.status(), SigningMessagePayloadStatus::HexBytes);
        assert!(message.requires_unsafe_raw_signing_warning());
        assert_eq!(
            signing.account().status(),
            SessionRequestAccountConstraintStatus::Unauthorized
        );
        assert!(signing.account().matched_account().is_none());

        Ok(())
    }

    #[test]
    fn typed_data_review_flags_domain_chain_mismatch() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_signTypedData_v4".parse()?,
                    params: json!([
                        "0x1111111111111111111111111111111111111111",
                        {
                            "types": {},
                            "primaryType": "Mail",
                            "domain": {"name": "Example", "chainId": 137},
                            "message": {}
                        }
                    ]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let signing = review.signing_request_review()?.expect("typed data review");
        let chain = signing.chain().expect("typed data domain chain");

        assert_eq!(signing.kind(), SigningRequestKind::EthSignTypedDataV4);
        assert_eq!(
            chain.status(),
            SessionRequestChainConstraintStatus::DiffersFromRequestChain
        );
        assert_eq!(
            chain.caip2_chain_id().map(ToString::to_string),
            Some("eip155:137".to_owned())
        );

        Ok(())
    }

    #[test]
    fn typed_data_review_summarizes_domain_and_message_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let typed_data = serde_json::to_string(&json!({
            "types": {
                "EIP712Domain": [],
                "Mail": []
            },
            "primaryType": "Mail",
            "domain": {
                "name": "Example Mail",
                "version": "1",
                "chainId": "0x1",
                "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
            },
            "message": {
                "from": "Alice",
                "contents": "Hello"
            }
        }))?;
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_signTypedData_v4".parse()?,
                    params: json!(["0x1111111111111111111111111111111111111111", typed_data]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let signing = review.signing_request_review()?.expect("typed data review");
        let summary = signing.typed_data().expect("typed data summary");

        assert_eq!(
            summary.status(),
            Eip712TypedDataPayloadStatus::JsonStringObject
        );
        assert_eq!(
            summary.display_status(),
            Eip712TypedDataDisplayStatus::Displayable
        );
        assert_eq!(summary.primary_type(), Some("Mail"));
        assert_eq!(summary.domain().name(), Some("Example Mail"));
        assert_eq!(summary.domain().version(), Some("1"));
        assert_eq!(
            summary
                .domain()
                .chain()
                .map(super::SessionRequestChainConstraint::status),
            Some(SessionRequestChainConstraintStatus::MatchesRequestChain)
        );
        assert_eq!(
            summary
                .domain()
                .verifying_contract()
                .map(super::EvmAddressSummary::status),
            Some(EvmAddressStatus::Valid)
        );
        assert_eq!(
            summary.type_names(),
            &["EIP712Domain".to_owned(), "Mail".to_owned()]
        );
        assert_eq!(
            summary.message_keys(),
            &["contents".to_owned(), "from".to_owned()]
        );
        let approval =
            SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)?;
        assert!(matches!(
            approval.method_review(),
            SessionRequestMethodReview::Signing(_)
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_malformed_typed_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_signTypedData_v4".parse()?,
                    params: json!(["0x1111111111111111111111111111111111111111", "{not-json"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("malformed typed data cannot build approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::TypedData {
                status: Eip712TypedDataPayloadStatus::InvalidJsonString
            }
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_non_displayable_typed_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_signTypedData_v4".parse()?,
                    params: json!(["0x1111111111111111111111111111111111111111", {}]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let summary = review
            .signing_request_review()?
            .and_then(|review| review.typed_data().cloned())
            .expect("typed-data summary");
        assert_eq!(
            summary.display_status(),
            Eip712TypedDataDisplayStatus::MissingPrimaryType
        );

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("empty typed data cannot build approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::TypedDataDisplay {
                status: Eip712TypedDataDisplayStatus::MissingPrimaryType
            }
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_malformed_signing_message()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!(["0x123", "0x1111111111111111111111111111111111111111"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let summary = review
            .signing_request_review()?
            .and_then(|review| review.message().cloned())
            .expect("message summary");
        assert_eq!(summary.status(), SigningMessagePayloadStatus::OddLengthHex);

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("malformed message cannot build approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::SigningMessage {
                status: SigningMessagePayloadStatus::OddLengthHex
            }
        ));

        Ok(())
    }

    #[test]
    fn session_request_debug_redacts_sensitive_fields() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "personal_sign".parse()?,
                    params: json!([
                        "secret message",
                        "0x1111111111111111111111111111111111111111"
                    ]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);
        let signing = review.signing_request_review()?.expect("signing review");
        let approval =
            SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)?;

        let review_debug = format!("{review:?}");
        let signing_debug = format!("{signing:?}");
        let approval_debug = format!("{approval:?}");

        for debug in [&review_debug, &signing_debug, &approval_debug] {
            assert!(!debug.contains("secret message"));
            assert!(!debug.contains("0x1111111111111111111111111111111111111111"));
            assert!(debug.contains("hash"));
        }

        Ok(())
    }

    #[test]
    fn transaction_review_decodes_display_value_to_and_calldata()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_sendTransaction".parse()?,
                    params: json!([{
                        "from": "0x1111111111111111111111111111111111111111",
                        "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
                        "value": "0xde0b6b3a7640000",
                        "data": "0xa9059cbb00000000",
                        "chainId": "0x1"
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let transaction = review
            .transaction_request_review()?
            .expect("transaction review");
        let summary = transaction.summary();

        assert_eq!(summary.status(), EvmTransactionPayloadStatus::Object);
        assert_eq!(summary.display_field_count(), 3);
        assert_eq!(
            summary.to().map(super::EvmAddressSummary::status),
            Some(EvmAddressStatus::Valid)
        );
        assert_eq!(
            summary.value().map(super::EvmHexQuantity::status),
            Some(EvmHexQuantityStatus::Decoded)
        );
        assert_eq!(
            summary.value().and_then(super::EvmHexQuantity::decimal),
            Some("1000000000000000000")
        );
        assert_eq!(
            summary.data().map(super::EvmCalldataSummary::status),
            Some(EvmCalldataStatus::Decoded)
        );
        assert_eq!(
            summary
                .data()
                .and_then(super::EvmCalldataSummary::function_selector),
            Some("0xa9059cbb")
        );
        assert_eq!(
            summary.data().and_then(super::EvmCalldataSummary::byte_len),
            Some(8)
        );
        let approval =
            SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)?;
        assert!(matches!(
            approval.method_review(),
            SessionRequestMethodReview::Transaction(_)
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_non_object_transaction()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_sendTransaction".parse()?,
                    params: json!(["not-a-transaction-object"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("non-object transaction cannot build approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::TransactionPayload {
                status: EvmTransactionPayloadStatus::UnsupportedPayload
            }
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_empty_transaction_display()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_sendTransaction".parse()?,
                    params: json!([{}]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("empty transaction cannot build approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::TransactionDisplay {
                field: "transaction",
                status: "missing_display_fields",
            }
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_transaction_without_explicit_account()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_sendTransaction".parse()?,
                    params: json!([{
                        "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567"
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("transaction approval must bind an account");

        assert!(matches!(
            error,
            SessionRequestApprovalError::Account {
                status: SessionRequestAccountConstraintStatus::NoAccountRequested
            }
        ));

        Ok(())
    }

    #[test]
    fn unknown_method_policy_can_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_nonstandardSecret".parse()?,
                    params: json!([{"opaque": true}]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?;

        assert_eq!(review.method_review()?, SessionRequestMethodReview::Raw);
        let error = review
            .method_review_with_unknown_policy(UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("unknown method should fail closed");

        assert!(matches!(
            error,
            SessionRequestMethodReviewError::UnknownMethod { method }
                if method.as_str() == "wallet_nonstandardSecret"
        ));

        Ok(())
    }

    #[test]
    fn session_request_approval_rejects_unknown_methods_when_policy_rejects()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_nonstandardSecret".parse()?,
                    params: json!([{"opaque": true}]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?;

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("unknown method cannot build a strict approval");

        assert!(matches!(
            error,
            SessionRequestApprovalError::MethodReview {
                source: SessionRequestMethodReviewError::UnknownMethod { method },
            } if method.as_str() == "wallet_nonstandardSecret"
        ));

        Ok(())
    }

    #[test]
    fn eth_sign_transaction_review_decodes_transaction_summary()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "eth_signTransaction".parse()?,
                    params: json!([{
                        "from": "0x1111111111111111111111111111111111111111",
                        "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
                        "value": "0x2a",
                        "data": "0x12345678",
                        "chainId": "0x1"
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let signing = review
            .signing_request_review()?
            .expect("sign transaction review");
        let summary = signing.transaction().expect("transaction summary");

        assert_eq!(signing.kind(), SigningRequestKind::EthSignTransaction);
        assert_eq!(summary.status(), EvmTransactionPayloadStatus::Object);
        assert_eq!(summary.display_field_count(), 3);
        assert_eq!(
            summary.to().map(super::EvmAddressSummary::status),
            Some(EvmAddressStatus::Valid)
        );
        assert_eq!(
            summary.value().and_then(super::EvmHexQuantity::decimal),
            Some("42")
        );
        assert_eq!(
            summary
                .data()
                .and_then(super::EvmCalldataSummary::function_selector),
            Some("0x12345678")
        );
        let approval =
            SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)?;
        assert!(matches!(
            approval.method_review(),
            SessionRequestMethodReview::Signing(_)
        ));

        Ok(())
    }

    #[test]
    fn wallet_get_capabilities_review_summarizes_disclosure_constraints()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_getCapabilities".parse()?,
                    params: json!([
                        "0x1111111111111111111111111111111111111111",
                        ["0x1", "eip155:1", "0x89", "not-hex"]
                    ]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let Some(WalletCallReview::GetCapabilities(capabilities)) = review.wallet_call_review()?
        else {
            panic!("expected getCapabilities review");
        };

        assert_eq!(
            capabilities.address().status(),
            SessionRequestAccountConstraintStatus::Authorized
        );
        let statuses = capabilities
            .requested_chains()
            .iter()
            .map(super::WalletCallChainConstraint::status)
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            vec![
                WalletCallChainConstraintStatus::MatchesRequestChain,
                WalletCallChainConstraintStatus::MatchesRequestChain,
                WalletCallChainConstraintStatus::DiffersFromRequestChain,
                WalletCallChainConstraintStatus::UnsupportedChainIdFormat,
            ]
        );

        Ok(())
    }

    #[test]
    fn wallet_send_calls_review_summarizes_chain_and_capability_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_sendCalls".parse()?,
                    params: json!([{
                        "version": "2.0.0",
                        "from": "0x1111111111111111111111111111111111111111",
                        "chainId": "0x89",
                        "atomicRequired": true,
                        "capabilities": {"paymasterService": {}},
                        "calls": [{
                            "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
                            "value": "0x0",
                            "capabilities": {"sessionKey": {}}
                        }]
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let review =
            SessionRequestReview::from_request(RelayTopic::from_bytes([3; 32]), 0, &request)?
                .with_authorized_accounts(vec![
                    "eip155:1:0x1111111111111111111111111111111111111111".parse()?,
                ]);

        let SessionRequestMethodReview::WalletCall(wallet_call) = review.method_review()? else {
            panic!("expected Wallet Call method review");
        };
        let WalletCallReview::SendCalls(send_calls) = wallet_call.as_ref() else {
            panic!("expected sendCalls method review");
        };
        assert_eq!(send_calls.call_count(), 1);
        assert!(send_calls.atomic_required());
        assert_eq!(
            send_calls.from().status(),
            SessionRequestAccountConstraintStatus::Authorized
        );
        assert_eq!(
            send_calls.requested_chain().status(),
            WalletCallChainConstraintStatus::DiffersFromRequestChain
        );
        assert_eq!(
            send_calls.capability_keys(),
            &["paymasterService".to_owned(), "sessionKey".to_owned()]
        );
        assert_eq!(send_calls.calls().len(), 1);
        assert_eq!(
            send_calls.calls()[0]
                .to()
                .map(super::EvmAddressSummary::status),
            Some(EvmAddressStatus::Valid)
        );
        assert_eq!(
            send_calls.calls()[0]
                .value()
                .map(super::EvmHexQuantity::status),
            Some(EvmHexQuantityStatus::Decoded)
        );

        Ok(())
    }

    #[test]
    fn wallet_call_status_review_binds_ids_to_wallet_registry()
    -> Result<(), Box<dyn std::error::Error>> {
        let topic = RelayTopic::from_bytes([3; 32]);
        let send_request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_sendCalls".parse()?,
                    params: json!([{
                        "version": "2.0.0",
                        "from": "0x1111111111111111111111111111111111111111",
                        "chainId": "0x1",
                        "atomicRequired": true,
                        "calls": [{"to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567"}]
                    }]),
                    expiry_timestamp: None,
                },
            },
        );
        let send_review = SessionRequestReview::from_request(topic.clone(), 0, &send_request)?;
        let mut registry = WalletCallStatusRegistry::new();
        registry.insert_send_calls_result(
            &send_review,
            &WalletSendCallsResult {
                id: "call-bundle-1".to_owned(),
                capabilities: None,
            },
        )?;

        let status_request = JsonRpcRequest::new(
            43,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_getCallsStatus".parse()?,
                    params: json!(["call-bundle-1"]),
                    expiry_timestamp: None,
                },
            },
        );
        let status_review = SessionRequestReview::from_request(topic.clone(), 0, &status_request)?;
        let Some(WalletCallReview::GetCallsStatus(status)) =
            status_review.wallet_call_review_for_registry(&registry)?
        else {
            panic!("expected status review");
        };

        assert_eq!(
            status.binding().status(),
            WalletCallStatusIdBindingStatus::Owned
        );
        assert_eq!(
            status
                .binding()
                .matched_entry()
                .map(WalletCallStatusRegistryEntry::id),
            Some("call-bundle-1")
        );

        let other_topic_review = SessionRequestReview::from_request(
            RelayTopic::from_bytes([4; 32]),
            0,
            &status_request,
        )?;
        let Some(WalletCallReview::GetCallsStatus(status)) =
            other_topic_review.wallet_call_review_for_registry(&registry)?
        else {
            panic!("expected status review");
        };
        assert_eq!(
            status.binding().status(),
            WalletCallStatusIdBindingStatus::TopicMismatch
        );

        let unknown_request = JsonRpcRequest::new(
            44,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_showCallsStatus".parse()?,
                    params: json!(["unknown-bundle"]),
                    expiry_timestamp: None,
                },
            },
        );
        let unknown_review = SessionRequestReview::from_request(topic, 0, &unknown_request)?;
        let Some(WalletCallReview::ShowCallsStatus(status)) =
            unknown_review.wallet_call_review_for_registry(&registry)?
        else {
            panic!("expected show status review");
        };
        assert_eq!(
            status.binding().status(),
            WalletCallStatusIdBindingStatus::Unknown
        );

        Ok(())
    }

    #[test]
    fn session_request_approval_requires_owned_wallet_call_status_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let topic = RelayTopic::from_bytes([3; 32]);
        let request = JsonRpcRequest::new(
            42,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: "eip155:1".parse()?,
                request: SessionRequest {
                    method: "wallet_getCallsStatus".parse()?,
                    params: json!(["call-bundle-1"]),
                    expiry_timestamp: None,
                },
            },
        );
        let review = SessionRequestReview::from_request(topic.clone(), 0, &request)?;

        let error = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
            .expect_err("status approval requires a registry");
        assert!(matches!(
            error,
            SessionRequestApprovalError::WalletCallStatusId {
                status: WalletCallStatusIdBindingStatus::Unchecked,
                ..
            }
        ));

        let empty_registry = WalletCallStatusRegistry::new();
        let error = SessionRequestApproval::with_wallet_call_status_registry(
            &review,
            UnknownSessionRequestMethodPolicy::Reject,
            &empty_registry,
        )
        .expect_err("unknown status id is not wallet-owned");
        assert!(matches!(
            error,
            SessionRequestApprovalError::WalletCallStatusId {
                status: WalletCallStatusIdBindingStatus::Unknown,
                ..
            }
        ));

        let mut registry = WalletCallStatusRegistry::new();
        registry.insert(WalletCallStatusRegistryEntry::new(
            "call-bundle-1",
            topic,
            "eip155:1".parse()?,
        ));
        let approval = SessionRequestApproval::with_wallet_call_status_registry(
            &review,
            UnknownSessionRequestMethodPolicy::Reject,
            &registry,
        )?;

        let SessionRequestMethodReview::WalletCall(wallet_call) = approval.method_review() else {
            panic!("expected Wallet Call approval review");
        };
        let WalletCallReview::GetCallsStatus(status) = wallet_call.as_ref() else {
            panic!("expected approved status method review");
        };
        assert_eq!(
            status.binding().status(),
            WalletCallStatusIdBindingStatus::Owned
        );

        Ok(())
    }
}
