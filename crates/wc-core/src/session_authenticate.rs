//! Session-authentication review primitives.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, CaipNamespace, NamespaceKey},
    relay::RelayTopic,
    session::{
        AuthPayload, Cacao, CacaoValidationError, DappMetadata, JsonRpcRequest, Recap,
        RecapParseError, SessionAuthenticateParams, SessionEventName, SessionMethod,
        SessionNamespace, SessionNamespaces, SessionParticipant, SignMethod, decode_recap,
        recap_from_resources,
    },
    verify::{VerifyAttestationHash, VerifyContext},
};

use crate::pairing::{PairingPayload, PairingReceivedMessage};
use crate::redirect::{WalletRedirectOrigin, WalletRedirectReview};
use crate::verify_policy::{
    VerifyContextRisk, VerifyRiskReview, VerifyRiskSurface, classify_verify_context,
};
use crate::verify_resolver::{VerifyResolver, VerifyResolverError};

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
    verify_context: VerifyContext,
    verify_attestation_hash: Option<VerifyAttestationHash>,
    verify_attestation_jwt: Option<String>,
    verify_encrypted_id: Option<String>,
    redirect: WalletRedirectReview,
}

impl SessionAuthenticateReview {
    /// Extracts review data from a received pairing-topic message.
    pub fn from_message(
        message: &PairingReceivedMessage,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        let PairingPayload::SessionAuthenticate(request) = message.payload() else {
            return Err(SessionAuthenticateReviewError::NotSessionAuthenticate);
        };

        let verify_context =
            VerifyContext::unresolved_from_metadata(&request.params.requester.metadata);
        Self::from_message_with_verify_context(message, verify_context)
    }

    /// Extracts review data and caller-resolved Verify context from a pairing message.
    ///
    /// The maintained Sign Client attaches `verifyContext` to
    /// `session_authenticate` events.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2574-L2605>
    ///
    /// > const verifyContext = await this.getVerifyContext({
    /// > metadata: requester.metadata,
    /// > verifyContext,
    pub fn from_message_with_verify_context(
        message: &PairingReceivedMessage,
        verify_context: VerifyContext,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        let PairingPayload::SessionAuthenticate(request) = message.payload() else {
            return Err(SessionAuthenticateReviewError::NotSessionAuthenticate);
        };

        let mut review = Self::from_request_with_verify_context(
            message.topic().clone(),
            message.published_at(),
            request,
            verify_context,
        )?;
        review.verify_attestation_hash = Some(VerifyAttestationHash::from_message(
            message.message().plaintext(),
        ));
        review.verify_attestation_jwt = message
            .verify_jwt_attestation()
            .map(|(jwt, _encrypted_id)| jwt.to_owned());
        review.verify_encrypted_id = message
            .verify_jwt_attestation()
            .map(|(_jwt, encrypted_id)| encrypted_id.to_owned());

        Ok(review)
    }

    /// Builds review data from a typed `wc_sessionAuthenticate` request.
    pub fn from_request(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionAuthenticateParams>,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        let verify_context =
            VerifyContext::unresolved_from_metadata(&request.params.requester.metadata);
        Self::from_request_with_verify_context(topic, published_at, request, verify_context)
    }

    /// Builds review data from a typed request and caller-resolved Verify context.
    pub fn from_request_with_verify_context(
        topic: RelayTopic,
        published_at: u64,
        request: &JsonRpcRequest<SessionAuthenticateParams>,
        verify_context: VerifyContext,
    ) -> Result<Self, SessionAuthenticateReviewError> {
        if request.method != SignMethod::SessionAuthenticate {
            return Err(SessionAuthenticateReviewError::MethodMismatch {
                method: request.method,
            });
        }

        Ok(Self::from_params_with_verify_context(
            topic,
            request.id,
            published_at,
            request.params.clone(),
            verify_context,
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
        let verify_context = VerifyContext::unresolved_from_metadata(&params.requester.metadata);
        Self::from_params_with_verify_context(
            topic,
            request_id,
            published_at,
            params,
            verify_context,
        )
    }

    /// Builds review data from already validated params and Verify context.
    #[must_use]
    pub fn from_params_with_verify_context(
        topic: RelayTopic,
        request_id: u64,
        published_at: u64,
        params: SessionAuthenticateParams,
        verify_context: VerifyContext,
    ) -> Self {
        Self {
            topic,
            request_id,
            requester: params.requester,
            auth_payload: params.auth_payload,
            expiry_timestamp: params.expiry_timestamp,
            published_at,
            verify_context,
            verify_attestation_hash: None,
            verify_attestation_jwt: None,
            verify_encrypted_id: None,
            redirect: WalletRedirectReview::empty(WalletRedirectOrigin::Unknown),
        }
    }

    /// Replaces the redirect review associated with this authentication request.
    #[must_use]
    pub fn with_redirect_review(mut self, redirect: WalletRedirectReview) -> Self {
        self.redirect = redirect;
        self
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

    /// Summarizes the CAIP-122 payload before a wallet formats or signs CACAO.
    #[must_use]
    pub fn auth_payload_review(&self) -> SessionAuthenticatePayloadReview {
        SessionAuthenticatePayloadReview::new(&self.auth_payload)
    }

    /// Reviews a wallet-selected issuer account against the requested auth chains.
    ///
    /// The auth request does not carry the wallet account. Wallets should call
    /// this before formatting the CACAO message for a selected account, so a
    /// dapp cannot silently authenticate an account on an unrequested chain.
    #[must_use]
    pub fn account_review(&self, account: Caip10AccountId) -> SessionAuthenticateAccountReview {
        SessionAuthenticateAccountReview::new(account, self.auth_payload.chains.clone())
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

    /// Verify context associated with the requesting dapp.
    #[must_use]
    pub const fn verify_context(&self) -> &VerifyContext {
        &self.verify_context
    }

    /// Redirect metadata and automatic-return recommendation for this request.
    #[must_use]
    pub const fn redirect(&self) -> &WalletRedirectReview {
        &self.redirect
    }

    /// Relay-carried Verify v3 JWT and encrypted identifier, when retained.
    ///
    /// `wc_sessionAuthenticate` carries origin-sensitive auth payloads, so
    /// reviews built from relay messages keep the Verify v3 pair beside the
    /// metadata-derived unresolved context.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2574-L2605>
    ///
    /// > attestationId: attestation,
    /// > encryptedId,
    /// > verifyContext,
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

    /// Verify hash computed from the exact decrypted pairing payload, when retained.
    #[must_use]
    pub const fn verify_attestation_hash(&self) -> Option<&VerifyAttestationHash> {
        self.verify_attestation_hash.as_ref()
    }

    /// Verify risk review required before approving authentication.
    #[must_use]
    pub fn verify_risk_review(&self) -> VerifyRiskReview {
        VerifyRiskReview::new(
            VerifyRiskSurface::SessionAuthenticateApproval,
            self.topic.clone(),
            self.request_id,
            self.verify_attestation_hash.clone(),
            self.verify_context.clone(),
        )
    }

    /// Resolves Verify context with a caller-provided SDK-compatible hash.
    ///
    /// The high-level `SingleSessionAuthenticate` event can resolve from the
    /// retained exact decrypted payload. This review helper accepts an explicit
    /// hash for callers that construct reviews directly.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2574-L2580>
    ///
    /// > hash: hashMessage(JSON.stringify(payload)),
    /// > metadata: requester.metadata,
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

    /// Resolves Verify context from retained relay JWT metadata when present.
    ///
    /// Reviews built from typed params have no transport metadata and therefore
    /// keep the existing unresolved context. Use
    /// `resolve_verify_context_with_hash` when only a hash is available.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L117-L137>
    ///
    /// > if (decoded.payload.id !== encryptedId) return;
    /// > const validation = await this.isValidJwtAttestation(attestationId);
    pub async fn resolve_verify_context_at(
        &mut self,
        resolver: &VerifyResolver,
        now_unix_seconds: u64,
    ) -> Result<&VerifyContext, VerifyResolverError> {
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
                .await?;
        }

        Ok(&self.verify_context)
    }

    /// Whether the request expiry has passed at `now_unix_seconds`.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp <= now_unix_seconds
    }
}

/// Wallet-facing summary of a `wc_sessionAuthenticate` CAIP-122 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticatePayloadReview {
    chains: Vec<Caip2ChainId>,
    audience: String,
    domain: String,
    nonce: String,
    statement: Option<String>,
    resources: Vec<String>,
    recap_resources: Vec<String>,
}

impl SessionAuthenticatePayloadReview {
    fn new(payload: &AuthPayload) -> Self {
        let recap_resources = payload
            .resources
            .iter()
            .filter(|resource| resource.starts_with("urn:recap:"))
            .cloned()
            .collect();
        Self {
            chains: payload.chains.clone(),
            audience: payload.aud.clone(),
            domain: payload.domain.clone(),
            nonce: payload.nonce.clone(),
            statement: payload.statement.clone(),
            resources: payload.resources.clone(),
            recap_resources,
        }
    }

    /// Requested CAIP-2 chains.
    #[must_use]
    pub fn chains(&self) -> &[Caip2ChainId] {
        &self.chains
    }

    /// Audience URI.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Domain that will appear in the CAIP-122 message.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Request nonce.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Human-readable statement, when present.
    #[must_use]
    pub fn statement(&self) -> Option<&str> {
        self.statement.as_deref()
    }

    /// Resource URIs requested by the dapp.
    #[must_use]
    pub fn resources(&self) -> &[String] {
        &self.resources
    }

    /// Recap resource URNs that may imply method/capability grants.
    #[must_use]
    pub fn recap_resources(&self) -> &[String] {
        &self.recap_resources
    }
}

/// Wallet-selected auth account status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthenticateAccountStatus {
    /// The account chain is one of the requested auth chains.
    RequestedChain,
    /// The request contains no auth chains.
    NoRequestedChains,
    /// The account chain is not requested by the auth payload.
    UnrequestedChain,
}

/// Wallet-selected auth account checked against requested auth chains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticateAccountReview {
    account: Caip10AccountId,
    requested_chains: Vec<Caip2ChainId>,
    status: SessionAuthenticateAccountStatus,
}

impl SessionAuthenticateAccountReview {
    fn new(account: Caip10AccountId, requested_chains: Vec<Caip2ChainId>) -> Self {
        let status = if requested_chains.is_empty() {
            SessionAuthenticateAccountStatus::NoRequestedChains
        } else if requested_chains.contains(&account.chain_id()) {
            SessionAuthenticateAccountStatus::RequestedChain
        } else {
            SessionAuthenticateAccountStatus::UnrequestedChain
        };
        Self {
            account,
            requested_chains,
            status,
        }
    }

    /// Wallet-selected account.
    #[must_use]
    pub const fn account(&self) -> &Caip10AccountId {
        &self.account
    }

    /// Requested CAIP-2 auth chains.
    #[must_use]
    pub fn requested_chains(&self) -> &[Caip2ChainId] {
        &self.requested_chains
    }

    /// Chain status for the selected account.
    #[must_use]
    pub const fn status(&self) -> SessionAuthenticateAccountStatus {
        self.status
    }

    /// Whether the account is on a requested auth chain.
    #[must_use]
    pub const fn is_requested_chain(&self) -> bool {
        matches!(
            self.status,
            SessionAuthenticateAccountStatus::RequestedChain
        )
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
/// > auths: \[auth],
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuthenticateApproval {
    wallet_metadata: DappMetadata,
    cacaos: Vec<Cacao>,
    session_namespaces: Option<SessionNamespaces>,
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
            session_namespaces: None,
        })
    }

    /// Adds namespaces for an authenticated session created by this approval.
    ///
    /// The maintained SDK creates and stores an acknowledged session only when
    /// approved methods are present.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1350-L1375>
    ///
    /// > if (approvedMethods?.length > 0) {
    /// > session = {
    #[must_use]
    pub fn with_session_namespaces(mut self, namespaces: SessionNamespaces) -> Self {
        self.session_namespaces = Some(namespaces);
        self
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

    /// Namespaces for the auth-created session, when the caller grants methods.
    #[must_use]
    pub const fn session_namespaces(&self) -> Option<&SessionNamespaces> {
        self.session_namespaces.as_ref()
    }

    /// Verifies every signed CACAO mirrors the exact authentication payload.
    pub fn validate_against_auth_payload(
        &self,
        auth_payload: &AuthPayload,
    ) -> Result<(), SessionAuthenticateApprovalError> {
        for (index, cacao) in self.cacaos.iter().enumerate() {
            cacao
                .validate_against_auth_payload(auth_payload)
                .map_err(
                    |source| SessionAuthenticateApprovalError::CacaoAuthPayloadMismatch {
                        index,
                        source,
                    },
                )?;
        }

        if let Some(namespaces) = &self.session_namespaces {
            AuthSessionGrant::from_signed_cacaos(auth_payload, &self.cacaos)?
                .validate_namespaces(namespaces)?;
        }

        Ok(())
    }

    pub(crate) fn into_parts(self) -> (DappMetadata, Vec<Cacao>, Option<SessionNamespaces>) {
        (self.wallet_metadata, self.cacaos, self.session_namespaces)
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

    /// A signed CACAO did not mirror the exact auth payload under review.
    #[error("session authenticate approval CACAO {index} does not match auth payload")]
    CacaoAuthPayloadMismatch {
        /// Zero-based index in the approval CACAO list.
        index: usize,
        /// CACAO/auth-payload mismatch.
        #[source]
        source: CacaoValidationError,
    },

    /// A signed CACAO Recap could not be decoded for auth-session bounding.
    #[error("session authenticate approval CACAO {index} Recap is invalid")]
    InvalidRecap {
        /// Zero-based index in the approval CACAO list.
        index: usize,
        /// Recap decode failure.
        #[source]
        source: RecapParseError,
    },

    /// Auth-created session namespace has no usable request methods.
    #[error("auth session namespace {namespace} has no methods")]
    SessionNamespaceMethodsEmpty {
        /// Namespace that would disclose accounts without request permissions.
        namespace: NamespaceKey,
    },

    /// Auth-created session namespace has no accounts.
    #[error("auth session namespace {namespace} has no accounts")]
    SessionNamespaceAccountsEmpty {
        /// Namespace with no account grant.
        namespace: NamespaceKey,
    },

    /// A namespace key, chain entry, or account chain crosses CAIP namespaces.
    #[error("auth session namespace {namespace} cannot include chain {chain_id}")]
    SessionNamespaceChainMismatch {
        /// Namespace being validated.
        namespace: NamespaceKey,
        /// Chain that does not belong under the namespace key.
        chain_id: Caip2ChainId,
    },

    /// A namespace account is outside the signed CACAO/Recap grant.
    #[error("auth session namespace {namespace} account {account} is not signed")]
    SessionNamespaceAccountUnauthorized {
        /// Namespace being validated.
        namespace: NamespaceKey,
        /// Account not authorized by signed CACAO issuers.
        account: Caip10AccountId,
    },

    /// A namespace chain is outside the signed CACAO/Recap grant.
    #[error("auth session namespace {namespace} chain {chain_id} is not authorized")]
    SessionNamespaceChainUnauthorized {
        /// Namespace being validated.
        namespace: NamespaceKey,
        /// Chain not authorized by the signed authentication grant.
        chain_id: Caip2ChainId,
    },

    /// A namespace method is outside the signed CACAO/Recap grant.
    #[error("auth session namespace {namespace} method {method} is not authorized for {chain_id}")]
    SessionNamespaceMethodUnauthorized {
        /// Namespace being validated.
        namespace: NamespaceKey,
        /// Chain where the method would be authorized by the session.
        chain_id: Caip2ChainId,
        /// Method not authorized by a signed Recap request ability.
        method: SessionMethod,
    },

    /// A namespace event is outside the auth-session event allow-list.
    #[error("auth session namespace {namespace} event {event} is not authorized for {chain_id}")]
    SessionNamespaceEventUnauthorized {
        /// Namespace being validated.
        namespace: NamespaceKey,
        /// Chain where the event would be authorized by the session.
        chain_id: Caip2ChainId,
        /// Event not authorized for an auth-created session.
        event: SessionEventName,
    },
}

#[derive(Debug, Clone, Default)]
struct AuthSessionGrant(BTreeMap<String, AuthNamespaceGrant>);

#[derive(Debug, Clone, Default)]
struct AuthNamespaceGrant {
    chains: BTreeSet<Caip2ChainId>,
    accounts: BTreeSet<Caip10AccountId>,
    request_methods_by_chain: BTreeMap<Caip2ChainId, BTreeSet<SessionMethod>>,
    events_by_chain: BTreeMap<Caip2ChainId, BTreeSet<SessionEventName>>,
}

impl AuthSessionGrant {
    fn from_signed_cacaos(
        auth_payload: &AuthPayload,
        cacaos: &[Cacao],
    ) -> Result<Self, SessionAuthenticateApprovalError> {
        let requested_chains = auth_payload.chains.iter().cloned().collect::<BTreeSet<_>>();
        let mut grant = Self::default();

        for (index, cacao) in cacaos.iter().enumerate() {
            let issuer_account = cacao.p.iss.account_id();
            let issuer_chain = issuer_account.chain_id();
            let issuer_namespace = issuer_account.namespace().to_owned();
            let mut cacao_chains = BTreeSet::from([issuer_chain.clone()]);
            let mut request_methods_by_chain = BTreeMap::new();
            let mut events_by_chain = BTreeMap::new();

            if let Some(recap_resource) = recap_from_resources(&cacao.p.resources) {
                let recap = decode_recap(recap_resource).map_err(|source| {
                    SessionAuthenticateApprovalError::InvalidRecap { index, source }
                })?;
                collect_recap_permissions(
                    &recap,
                    &issuer_namespace,
                    &issuer_chain,
                    &requested_chains,
                    &mut cacao_chains,
                    &mut request_methods_by_chain,
                    &mut events_by_chain,
                );
            }

            let namespace_grant = grant.0.entry(issuer_namespace).or_default();
            for chain_id in cacao_chains {
                if !requested_chains.contains(&chain_id) {
                    continue;
                }
                if chain_id.namespace() != issuer_account.namespace() {
                    continue;
                }
                namespace_grant.chains.insert(chain_id.clone());
                namespace_grant.accounts.insert(
                    Caip10AccountId::from_parts(&chain_id, issuer_account.address())
                        .expect("issuer address is already a valid CAIP-10 address"),
                );
            }
            merge_chain_permissions(
                &mut namespace_grant.request_methods_by_chain,
                request_methods_by_chain,
            );
            merge_chain_permissions(&mut namespace_grant.events_by_chain, events_by_chain);
        }

        Ok(grant)
    }

    fn validate_namespaces(
        &self,
        namespaces: &SessionNamespaces,
    ) -> Result<(), SessionAuthenticateApprovalError> {
        for (namespace_key, namespace) in namespaces {
            validate_auth_session_namespace(
                namespace_key,
                namespace,
                self.0.get(namespace_key.namespace()),
            )?;
        }

        Ok(())
    }
}

fn validate_auth_session_namespace(
    namespace_key: &NamespaceKey,
    namespace: &SessionNamespace,
    namespace_grant: Option<&AuthNamespaceGrant>,
) -> Result<(), SessionAuthenticateApprovalError> {
    if namespace.methods.is_empty() {
        return Err(
            SessionAuthenticateApprovalError::SessionNamespaceMethodsEmpty {
                namespace: namespace_key.clone(),
            },
        );
    }
    if namespace.accounts.is_empty() {
        return Err(
            SessionAuthenticateApprovalError::SessionNamespaceAccountsEmpty {
                namespace: namespace_key.clone(),
            },
        );
    }

    let namespace_chains =
        validate_auth_session_namespace_chains(namespace_key, namespace, namespace_grant)?;
    validate_auth_session_namespace_methods(
        namespace_key,
        &namespace_chains,
        &namespace.methods,
        namespace_grant,
    )?;
    validate_auth_session_namespace_events(
        namespace_key,
        &namespace_chains,
        &namespace.events,
        namespace_grant,
    )
}

fn validate_auth_session_namespace_chains(
    namespace_key: &NamespaceKey,
    namespace: &SessionNamespace,
    namespace_grant: Option<&AuthNamespaceGrant>,
) -> Result<BTreeSet<Caip2ChainId>, SessionAuthenticateApprovalError> {
    let mut namespace_chains = BTreeSet::new();
    let key_chain = namespace_key.chain_id();
    if let Some(chain_id) = key_chain {
        validate_namespace_chain_shape(namespace_key, chain_id)?;
        validate_granted_chain(namespace_key, namespace_grant, chain_id)?;
        namespace_chains.insert(chain_id.clone());
    }
    if let Some(chains) = &namespace.chains {
        for chain_id in chains {
            if key_chain.is_some_and(|key_chain| key_chain != chain_id) {
                return Err(
                    SessionAuthenticateApprovalError::SessionNamespaceChainMismatch {
                        namespace: namespace_key.clone(),
                        chain_id: chain_id.clone(),
                    },
                );
            }
            validate_namespace_chain_shape(namespace_key, chain_id)?;
            validate_granted_chain(namespace_key, namespace_grant, chain_id)?;
            namespace_chains.insert(chain_id.clone());
        }
    }

    for account in &namespace.accounts {
        let chain_id = account.chain_id();
        validate_namespace_chain_shape(namespace_key, &chain_id)?;
        if key_chain.is_some_and(|key_chain| key_chain != &chain_id) {
            return Err(
                SessionAuthenticateApprovalError::SessionNamespaceAccountUnauthorized {
                    namespace: namespace_key.clone(),
                    account: account.clone(),
                },
            );
        }
        if !namespace_grant.is_some_and(|grant| grant.accounts.contains(account)) {
            return Err(
                SessionAuthenticateApprovalError::SessionNamespaceAccountUnauthorized {
                    namespace: namespace_key.clone(),
                    account: account.clone(),
                },
            );
        }
        validate_granted_chain(namespace_key, namespace_grant, &chain_id)?;
        namespace_chains.insert(chain_id);
    }

    Ok(namespace_chains)
}

fn validate_auth_session_namespace_methods(
    namespace_key: &NamespaceKey,
    namespace_chains: &BTreeSet<Caip2ChainId>,
    methods: &[SessionMethod],
    namespace_grant: Option<&AuthNamespaceGrant>,
) -> Result<(), SessionAuthenticateApprovalError> {
    for method in methods {
        for chain_id in namespace_chains {
            let authorized = namespace_grant.is_some_and(|grant| {
                grant
                    .request_methods_by_chain
                    .get(chain_id)
                    .is_some_and(|methods| methods.contains(method))
            });
            if !authorized {
                return Err(
                    SessionAuthenticateApprovalError::SessionNamespaceMethodUnauthorized {
                        namespace: namespace_key.clone(),
                        chain_id: chain_id.clone(),
                        method: method.clone(),
                    },
                );
            }
        }
    }

    Ok(())
}

fn validate_auth_session_namespace_events(
    namespace_key: &NamespaceKey,
    namespace_chains: &BTreeSet<Caip2ChainId>,
    events: &[SessionEventName],
    namespace_grant: Option<&AuthNamespaceGrant>,
) -> Result<(), SessionAuthenticateApprovalError> {
    for event in events {
        for chain_id in namespace_chains {
            let authorized = is_default_auth_session_event(event)
                || namespace_grant.is_some_and(|grant| {
                    grant
                        .events_by_chain
                        .get(chain_id)
                        .is_some_and(|events| events.contains(event))
                });
            if !authorized {
                return Err(
                    SessionAuthenticateApprovalError::SessionNamespaceEventUnauthorized {
                        namespace: namespace_key.clone(),
                        chain_id: chain_id.clone(),
                        event: event.clone(),
                    },
                );
            }
        }
    }

    Ok(())
}

fn collect_recap_permissions(
    recap: &Recap,
    issuer_namespace: &str,
    issuer_chain: &Caip2ChainId,
    requested_chains: &BTreeSet<Caip2ChainId>,
    chains: &mut BTreeSet<Caip2ChainId>,
    request_methods_by_chain: &mut BTreeMap<Caip2ChainId, BTreeSet<SessionMethod>>,
    events_by_chain: &mut BTreeMap<Caip2ChainId, BTreeSet<SessionEventName>>,
) {
    for (resource, abilities) in recap.att() {
        let Some(resource_namespace) = recap_resource_namespace(resource) else {
            continue;
        };
        if resource_namespace.as_str() != issuer_namespace {
            continue;
        }

        let resource_chain = Caip2ChainId::parse(resource).ok();
        let Some(abilities) = abilities.as_object() else {
            continue;
        };
        for (ability, limits) in abilities {
            let Some((ability_kind, action)) = ability.split_once('/') else {
                continue;
            };
            match ability_kind {
                "request" => {
                    if let Ok(method) = SessionMethod::parse(action) {
                        let ability_chains = recap_ability_chains(
                            resource_chain.as_ref(),
                            limits,
                            issuer_chain,
                            requested_chains,
                        );
                        chains.extend(ability_chains.iter().cloned());
                        for chain_id in ability_chains {
                            request_methods_by_chain
                                .entry(chain_id)
                                .or_default()
                                .insert(method.clone());
                        }
                    }
                }
                "event" => {
                    if let Ok(event) = SessionEventName::parse(action) {
                        let ability_chains = recap_ability_chains(
                            resource_chain.as_ref(),
                            limits,
                            issuer_chain,
                            requested_chains,
                        );
                        chains.extend(ability_chains.iter().cloned());
                        for chain_id in ability_chains {
                            events_by_chain
                                .entry(chain_id)
                                .or_default()
                                .insert(event.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn recap_ability_chains(
    resource_chain: Option<&Caip2ChainId>,
    limits: &Value,
    default_chain: &Caip2ChainId,
    requested_chains: &BTreeSet<Caip2ChainId>,
) -> BTreeSet<Caip2ChainId> {
    let mut chains = BTreeSet::new();
    let mut found_limited_chain = false;
    if let Some(limits) = limits.as_array() {
        for limit in limits {
            let Some(limit_chains) = limit.get("chains") else {
                continue;
            };
            found_limited_chain = true;
            let Some(limit_chains) = limit_chains.as_array() else {
                continue;
            };
            for chain in limit_chains {
                let Some(chain) = chain.as_str() else {
                    continue;
                };
                let Ok(chain_id) = Caip2ChainId::parse(chain) else {
                    continue;
                };
                if requested_chains.contains(&chain_id) {
                    chains.insert(chain_id);
                }
            }
        }
    }

    if !found_limited_chain
        && let Some(resource_chain) = resource_chain
        && requested_chains.contains(resource_chain)
    {
        chains.insert(resource_chain.clone());
    }
    if !found_limited_chain && resource_chain.is_none() && requested_chains.contains(default_chain)
    {
        chains.insert(default_chain.clone());
    }

    chains
}

fn merge_chain_permissions<T: Ord>(
    target: &mut BTreeMap<Caip2ChainId, BTreeSet<T>>,
    source: BTreeMap<Caip2ChainId, BTreeSet<T>>,
) {
    for (chain_id, values) in source {
        target.entry(chain_id).or_default().extend(values);
    }
}

fn recap_resource_namespace(resource: &str) -> Option<CaipNamespace> {
    if let Ok(chain_id) = Caip2ChainId::parse(resource) {
        return CaipNamespace::parse(chain_id.namespace()).ok();
    }
    CaipNamespace::parse(resource).ok()
}

fn validate_namespace_chain_shape(
    namespace: &NamespaceKey,
    chain_id: &Caip2ChainId,
) -> Result<(), SessionAuthenticateApprovalError> {
    if chain_id.namespace() == namespace.namespace() {
        Ok(())
    } else {
        Err(
            SessionAuthenticateApprovalError::SessionNamespaceChainMismatch {
                namespace: namespace.clone(),
                chain_id: chain_id.clone(),
            },
        )
    }
}

fn validate_granted_chain(
    namespace: &NamespaceKey,
    grant: Option<&AuthNamespaceGrant>,
    chain_id: &Caip2ChainId,
) -> Result<(), SessionAuthenticateApprovalError> {
    if grant.is_some_and(|grant| grant.chains.contains(chain_id)) {
        Ok(())
    } else {
        Err(
            SessionAuthenticateApprovalError::SessionNamespaceChainUnauthorized {
                namespace: namespace.clone(),
                chain_id: chain_id.clone(),
            },
        )
    }
}

fn is_default_auth_session_event(event: &SessionEventName) -> bool {
    matches!(event.as_str(), "chainChanged" | "accountsChanged")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{SessionAuthenticateApprovalError, VerifyContextRisk};
    use wc_protocol::{
        caip::NamespaceKey,
        did::DidPkh,
        key::X25519PublicKey,
        relay::RelayTopic,
        session::{
            AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
            CacaoSignatureType, CacaoSignatureValue, CacaoValidationError, DappMetadata,
            JsonRpcRequest, SessionAuthenticateParams, SessionEventName, SessionMethod,
            SessionNamespace, SessionParticipant, SignMethod,
        },
    };

    use super::{
        SessionAuthenticateAccountStatus, SessionAuthenticateApproval, SessionAuthenticateReview,
        SessionAuthenticateReviewError,
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
        assert_eq!(
            review.verify_context().verified.origin,
            "https://example.com"
        );
        assert!(review.verify_jwt_attestation().is_none());
        assert_eq!(review.verify_risk(), VerifyContextRisk::Unknown);
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
    fn auth_payload_review_summarizes_chains_and_recap_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut request = authenticate_request(SignMethod::SessionAuthenticate)?;
        request.params.auth_payload.resources = vec![
            "urn:recap:eyJhdHQiOnt9fQ".to_owned(),
            "https://example.com/terms".to_owned(),
        ];
        let review = SessionAuthenticateReview::from_request(
            RelayTopic::from_bytes([3; 32]),
            1_779_954_250_000,
            &request,
        )?;

        let payload = review.auth_payload_review();

        assert_eq!(payload.chains()[0].as_str(), "eip155:1");
        assert_eq!(payload.audience(), "https://example.com/login");
        assert_eq!(payload.domain(), "example.com");
        assert_eq!(payload.nonce(), "1234567890");
        assert_eq!(payload.statement(), Some("Sign in to Example"));
        assert_eq!(payload.resources().len(), 2);
        assert_eq!(
            payload.recap_resources(),
            &["urn:recap:eyJhdHQiOnt9fQ".to_owned()]
        );

        Ok(())
    }

    #[test]
    fn auth_account_review_checks_wallet_selected_chain() -> Result<(), Box<dyn std::error::Error>>
    {
        let request = authenticate_request(SignMethod::SessionAuthenticate)?;
        let review = SessionAuthenticateReview::from_request(
            RelayTopic::from_bytes([3; 32]),
            1_779_954_250_000,
            &request,
        )?;

        let approved =
            review.account_review("eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".parse()?);
        let unrequested =
            review.account_review("eip155:137:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".parse()?);

        assert_eq!(
            approved.status(),
            SessionAuthenticateAccountStatus::RequestedChain
        );
        assert!(approved.is_requested_chain());
        assert_eq!(
            unrequested.status(),
            SessionAuthenticateAccountStatus::UnrequestedChain
        );
        assert!(!unrequested.is_requested_chain());

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

    #[test]
    fn approval_preserves_auth_session_namespaces() -> Result<(), Box<dyn std::error::Error>> {
        let namespaces = session_namespaces()?;
        let approval = SessionAuthenticateApproval::new(wallet_metadata(), vec![cacao()?])?
            .with_session_namespaces(namespaces.clone());

        assert_eq!(approval.session_namespaces(), Some(&namespaces));

        Ok(())
    }

    #[test]
    fn approval_validates_cacaos_against_auth_payload() -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request(SignMethod::SessionAuthenticate)?;
        let approval = SessionAuthenticateApproval::new(wallet_metadata(), vec![cacao()?])?;

        approval.validate_against_auth_payload(&request.params.auth_payload)?;

        Ok(())
    }

    #[test]
    fn approval_rejects_mismatched_cacao_auth_payload() -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request(SignMethod::SessionAuthenticate)?;
        let mut bad_cacao = cacao()?;
        bad_cacao.p.nonce = "stale-nonce".to_owned();
        let approval = SessionAuthenticateApproval::new(wallet_metadata(), vec![bad_cacao])?;

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("mismatched CACAO must not validate");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::CacaoAuthPayloadMismatch {
                index: 0,
                source: CacaoValidationError::NonceMismatch,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_accepts_auth_session_namespaces_bounded_by_recap()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_resources(vec![recap_personal_sign()]);
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign()])?],
        )?
        .with_session_namespaces(session_namespaces()?);

        approval.validate_against_auth_payload(&request.params.auth_payload)?;

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespaces_without_recap_methods()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request(SignMethod::SessionAuthenticate)?;
        let approval = SessionAuthenticateApproval::new(wallet_metadata(), vec![cacao()?])?
            .with_session_namespaces(session_namespaces()?);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("auth-created session methods must be signed in Recap");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceMethodUnauthorized {
                namespace: NamespaceKey::parse("eip155")?,
                chain_id: "eip155:1".parse()?,
                method: SessionMethod::parse("personal_sign")?,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespace_unsigned_account()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_resources(vec![recap_personal_sign()]);
        let mut namespaces = session_namespaces()?;
        namespaces
            .get_mut(&NamespaceKey::parse("eip155")?)
            .expect("test namespace exists")
            .accounts = vec!["eip155:1:0x9999999999999999999999999999999999999999".parse()?];
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign()])?],
        )?
        .with_session_namespaces(namespaces);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("auth-created session account must come from signed CACAO");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceAccountUnauthorized {
                namespace: NamespaceKey::parse("eip155")?,
                account: "eip155:1:0x9999999999999999999999999999999999999999".parse()?,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespace_unsigned_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_resources(vec![recap_personal_sign()]);
        let mut namespaces = session_namespaces()?;
        let namespace = namespaces
            .get_mut(&NamespaceKey::parse("eip155")?)
            .expect("test namespace exists");
        namespace.chains = Some(vec!["eip155:2".parse()?]);
        namespace.accounts = vec!["eip155:2:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".parse()?];
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign()])?],
        )?
        .with_session_namespaces(namespaces);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("auth-created session chain must be signed in Recap");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceChainUnauthorized {
                namespace: NamespaceKey::parse("eip155")?,
                chain_id: "eip155:2".parse()?,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_accepts_auth_session_namespace_recap_limited_additional_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_chains_and_resources(
            vec!["eip155:1".parse()?, "eip155:2".parse()?],
            vec![recap_personal_sign_eip155_2()],
        );
        let mut namespaces = session_namespaces()?;
        let namespace = namespaces
            .get_mut(&NamespaceKey::parse("eip155")?)
            .expect("test namespace exists");
        namespace.chains = Some(vec!["eip155:2".parse()?]);
        namespace.accounts = vec!["eip155:2:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".parse()?];
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign_eip155_2()])?],
        )?
        .with_session_namespaces(namespaces);

        approval.validate_against_auth_payload(&request.params.auth_payload)?;

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespace_without_methods()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_resources(vec![recap_personal_sign()]);
        let mut namespaces = session_namespaces()?;
        namespaces
            .get_mut(&NamespaceKey::parse("eip155")?)
            .expect("test namespace exists")
            .methods = Vec::new();
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign()])?],
        )?
        .with_session_namespaces(namespaces);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("auth-created session must not disclose accounts without methods");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceMethodsEmpty {
                namespace: NamespaceKey::parse("eip155")?,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespace_malformed_recap_chain_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let malformed_recap = recap_personal_sign_malformed_chain_limit();
        let request = authenticate_request_with_resources(vec![malformed_recap.clone()]);
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![malformed_recap])?],
        )?
        .with_session_namespaces(session_namespaces()?);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("malformed Recap chain limits must fail closed");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceMethodUnauthorized {
                namespace: NamespaceKey::parse("eip155")?,
                chain_id: "eip155:1".parse()?,
                method: SessionMethod::parse("personal_sign")?,
            }
        );

        Ok(())
    }

    #[test]
    fn approval_rejects_auth_session_namespace_non_default_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = authenticate_request_with_resources(vec![recap_personal_sign()]);
        let mut namespaces = session_namespaces()?;
        namespaces
            .get_mut(&NamespaceKey::parse("eip155")?)
            .expect("test namespace exists")
            .events
            .push(SessionEventName::parse("message")?);
        let approval = SessionAuthenticateApproval::new(
            wallet_metadata(),
            vec![cacao_with_resources(vec![recap_personal_sign()])?],
        )?
        .with_session_namespaces(namespaces);

        let error = approval
            .validate_against_auth_payload(&request.params.auth_payload)
            .expect_err("auth-created session event must be default or signed in Recap");

        assert_eq!(
            error,
            SessionAuthenticateApprovalError::SessionNamespaceEventUnauthorized {
                namespace: NamespaceKey::parse("eip155")?,
                chain_id: "eip155:1".parse()?,
                event: SessionEventName::parse("message")?,
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

    fn authenticate_request_with_resources(
        resources: Vec<String>,
    ) -> JsonRpcRequest<SessionAuthenticateParams> {
        authenticate_request_with_chains_and_resources(
            vec!["eip155:1".parse().expect("test chain is valid")],
            resources,
        )
    }

    fn authenticate_request_with_chains_and_resources(
        chains: Vec<wc_protocol::caip::Caip2ChainId>,
        resources: Vec<String>,
    ) -> JsonRpcRequest<SessionAuthenticateParams> {
        let mut request = authenticate_request(SignMethod::SessionAuthenticate)
            .expect("test auth request is valid");
        request.params.auth_payload.chains = chains;
        request.params.auth_payload.resources = resources;
        request
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
        cacao_with_resources(Vec::new())
    }

    fn cacao_with_resources(resources: Vec<String>) -> Result<Cacao, Box<dyn std::error::Error>> {
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
                resources,
            },
            s: CacaoSignature {
                kind: CacaoSignatureType::Eip191,
                signature: CacaoSignatureValue::from_wire("0x00"),
                meta: None,
            },
        })
    }

    fn recap_personal_sign() -> String {
        "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3t9XX19fQ".to_owned()
    }

    fn recap_personal_sign_eip155_2() -> String {
        "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3siY2hhaW5zIjpbImVpcDE1NToyIl19XX19fQ"
            .to_owned()
    }

    fn recap_personal_sign_malformed_chain_limit() -> String {
        "urn:recap:eyJhdHQiOnsiZWlwMTU1Ijp7InJlcXVlc3QvcGVyc29uYWxfc2lnbiI6W3siY2hhaW5zIjoiZWlwMTU1OjEifV19fX0"
            .to_owned()
    }

    fn session_namespaces()
    -> Result<wc_protocol::session::SessionNamespaces, Box<dyn std::error::Error>> {
        Ok(BTreeMap::from([(
            NamespaceKey::parse("eip155")?,
            SessionNamespace {
                chains: Some(vec!["eip155:1".parse()?]),
                accounts: vec!["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".parse()?],
                methods: vec![SessionMethod::parse("personal_sign")?],
                events: vec![
                    SessionEventName::parse("chainChanged")?,
                    SessionEventName::parse("accountsChanged")?,
                ],
            },
        )]))
    }
}
