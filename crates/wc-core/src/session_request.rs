//! Session request review primitives.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId},
    relay::RelayTopic,
    session::{
        JsonRpcRequest, SessionMethod, SessionRequest, SessionRequestParams, SignMethod,
        WalletCallRequest, WalletCallRequestError,
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
    redirect: WalletRedirectReview,
    authorized_accounts: Vec<Caip10AccountId>,
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
        if let Some(wallet_call) = self.wallet_call_review()? {
            return Ok(SessionRequestMethodReview::WalletCall(wallet_call));
        }
        if let Some(signing) = self.signing_request_review()? {
            return Ok(SessionRequestMethodReview::Signing(signing));
        }
        if let Some(transaction) = self.transaction_request_review()? {
            return Ok(SessionRequestMethodReview::Transaction(transaction));
        }
        Ok(SessionRequestMethodReview::Raw)
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

        Ok(Some(SigningRequestReview {
            kind,
            account: self.account_constraint(requested_address),
            chain,
            payload,
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
            transaction,
        }))
    }

    /// Builds a Wallet Call review that summarizes account, chain, and
    /// capability-disclosure constraints without returning capabilities or
    /// executing calls.
    pub fn wallet_call_review(
        &self,
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
                })
            }
            WalletCallRequest::GetCallsStatus(params) => {
                WalletCallReview::GetCallsStatus(WalletCallStatusReview { id: params.0 })
            }
            WalletCallRequest::ShowCallsStatus(params) => {
                WalletCallReview::ShowCallsStatus(WalletCallStatusReview { id: params.0 })
            }
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
}

/// Wallet-facing method-specific review for high-risk session requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRequestMethodReview {
    /// Recognized EVM signing request.
    Signing(SigningRequestReview),
    /// Recognized EVM transaction submission request.
    Transaction(TransactionRequestReview),
    /// Recognized EIP-5792 Wallet Call request.
    WalletCall(WalletCallReview),
    /// Namespace-authorized method without a built-in method-specific parser.
    Raw,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequestAccountConstraint {
    requested_address: Option<String>,
    authorized_accounts: Vec<Caip10AccountId>,
    matched_account: Option<Caip10AccountId>,
    status: SessionRequestAccountConstraintStatus,
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
}

/// Parsed signing request review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRequestReview {
    kind: SigningRequestKind,
    account: SessionRequestAccountConstraint,
    chain: Option<SessionRequestChainConstraint>,
    payload: Value,
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
}

/// Parsed `eth_sendTransaction` review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequestReview {
    account: SessionRequestAccountConstraint,
    chain: Option<SessionRequestChainConstraint>,
    transaction: Value,
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
}

/// Chain comparison status for method payload chain IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRequestChainConstraintStatus {
    /// Payload chain parses to the enclosing `wc_sessionRequest` chain.
    MatchesRequestChain,
    /// Payload chain parses but differs from the enclosing request chain.
    DiffersFromRequestChain,
    /// Payload chain is not an EIP-155 decimal or hexadecimal chain ID.
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
}

impl WalletSendCallsReview {
    /// Sender account matched against authorized accounts.
    #[must_use]
    pub const fn from(&self) -> &SessionRequestAccountConstraint {
        &self.from
    }

    /// EIP-5792 hex chain ID matched against the enclosing CAIP-2 request chain.
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
}

/// Status identifier review for Wallet Call status methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCallStatusReview {
    id: String,
}

impl WalletCallStatusReview {
    /// Wallet Call bundle identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Chain comparison status for EIP-5792 hex chain IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletCallChainConstraintStatus {
    /// Hex chain ID parses to the enclosing `wc_sessionRequest` chain.
    MatchesRequestChain,
    /// Hex chain ID parses but differs from the enclosing request chain.
    DiffersFromRequestChain,
    /// Hex chain ID is not an EIP-155 hexadecimal chain ID.
    UnsupportedChainIdFormat,
}

/// EIP-5792 hex chain ID matched against the enclosing CAIP-2 request chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletCallChainConstraint {
    raw_chain_id: String,
    caip2_chain_id: Option<Caip2ChainId>,
    status: WalletCallChainConstraintStatus,
}

impl WalletCallChainConstraint {
    fn new(request_chain_id: &Caip2ChainId, raw_chain_id: String) -> Self {
        let caip2_chain_id = eip155_hex_to_caip2(&raw_chain_id);
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

    /// Raw hex chain ID from the Wallet Call params.
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

fn eip155_hex_to_caip2(raw_chain_id: &str) -> Option<Caip2ChainId> {
    raw_chain_id
        .strip_prefix("0x")
        .or_else(|| raw_chain_id.strip_prefix("0X"))?;
    eip155_string_to_caip2(raw_chain_id)
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
            WalletSendCallsParams,
        },
        verify::{VerifyContext, VerifyValidation},
    };

    use super::{
        SessionRequestAccountConstraintStatus, SessionRequestChainConstraintStatus,
        SessionRequestMethodReview, SessionRequestReview, SigningRequestKind,
        WalletCallChainConstraintStatus, WalletCallReview,
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
                        ["0x1", "0x89", "not-hex"]
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

        let SessionRequestMethodReview::WalletCall(WalletCallReview::SendCalls(send_calls)) =
            review.method_review()?
        else {
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

        Ok(())
    }
}
