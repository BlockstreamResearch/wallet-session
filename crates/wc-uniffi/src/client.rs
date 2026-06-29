use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use serde_json::json;
use tokio::runtime::{Builder, Runtime};
use wc_bitcoin::BitcoinRequestReview;
use wc_core::{
    DEFAULT_SESSION_EXPIRY_SECONDS, ExternalSessionRequestMethodReview,
    SessionAuthenticateApproval, SessionAuthenticateReview, SessionLifecycleResponsePayload,
    SessionRequestApproval, SingleSessionClient, SingleSessionClientEvent,
    SingleSessionPendingApproval, UnknownSessionRequestMethodPolicy,
};
use wc_protocol::{
    caip::Caip10AccountId,
    did::DidPkh,
    relay::RelayTopic,
    session::{
        CacaoSignature, CacaoSignatureType, CacaoSignatureValue, JsonRpcError, JsonRpcErrorCode,
        SessionDeleteParams,
    },
};

use crate::{
    bitcoin::{bitcoin_account_scope_from_session, validated_bitcoin_result},
    capabilities::{optional_session_namespaces, required_session_namespaces, wallet_capabilities},
    config::{WcClientConfig, single_session_config},
    error::WcUniFfiError,
    outcome::{session_authenticate_outcome, session_info, session_message_request_id},
    review::{
        active_session_review_json, authenticate_review_json, pending_approval_to_record,
        proposal_review_json, session_request_review_json, session_update_review_json,
    },
    types::{
        WcCapabilities, WcEvent, WcEventKind, WcJsonPayload, WcPendingApproval,
        WcSessionAuthenticateOutcome, WcSessionInfo, WcWalletMetadata,
    },
    util::{
        connection_state_label, i64_to_u64, invalid_input, json_string, now_unix_seconds,
        operation_error, parse_cacaos_json, parse_json_value, parse_redirect_origin,
        parse_session_event_params_json, parse_topic, remember_verify_context_if_present,
        state_error, u64_to_i64,
    },
};

/// `WalletConnect` single-session client for Kotlin.
#[derive(uniffi::Object)]
pub struct WcClient {
    runtime: Runtime,
    inner: Mutex<SingleSessionClient>,
    pending_messages: Mutex<PendingMessages>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PendingMessageKind {
    SessionRequest,
    SessionUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PendingMessageKey {
    kind: PendingMessageKind,
    topic: String,
    request_id: u64,
}

fn pending_key(
    kind: PendingMessageKind,
    topic: &str,
    request_id: i64,
) -> Result<PendingMessageKey, WcUniFfiError> {
    Ok(PendingMessageKey {
        kind,
        topic: parse_topic(topic)?.to_string(),
        request_id: i64_to_u64("request_id", request_id)?,
    })
}

fn parse_account_id(account_id: String) -> Result<Caip10AccountId, WcUniFfiError> {
    Caip10AccountId::parse(account_id).map_err(|error| invalid_input(error.to_string()))
}

fn pending_session_authenticate_review(
    client: &SingleSessionClient,
    topic: &RelayTopic,
    request_id: u64,
) -> Result<SessionAuthenticateReview, WcUniFfiError> {
    let authenticate = client
        .pending_approvals()
        .map_err(operation_error)?
        .into_iter()
        .find_map(|approval| match approval {
            SingleSessionPendingApproval::SessionAuthenticate(authenticate)
                if authenticate.pairing_topic() == topic
                    && authenticate.request_id() == request_id =>
            {
                Some(authenticate)
            }
            _ => None,
        })
        .ok_or_else(|| state_error("pending session authenticate not found"))?;
    client
        .session_authenticate_review(&authenticate)
        .map_err(operation_error)
}

fn requested_auth_issuer(
    review: &SessionAuthenticateReview,
    account: Caip10AccountId,
) -> Result<DidPkh, WcUniFfiError> {
    let account_review = review.account_review(account);
    if !account_review.is_requested_chain() {
        return Err(invalid_input(format!(
            "session authenticate account chain was not requested: {}",
            account_review.account().chain_id()
        )));
    }
    Ok(DidPkh::from_account_id(account_review.account()))
}

#[derive(Default)]
struct PendingMessages {
    session_requests: BTreeMap<PendingMessageKey, wc_core::SessionReceivedMessage>,
    session_updates: BTreeMap<PendingMessageKey, wc_core::SessionReceivedMessage>,
}

#[uniffi::export]
impl WcClient {
    /// Opens an authenticated relay connection.
    #[uniffi::constructor]
    pub fn connect(config: Arc<WcClientConfig>) -> Result<Self, WcUniFfiError> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name("wc-uniffi")
            .build()
            .map_err(operation_error)?;
        let config = single_session_config(&config)?;
        let client = runtime
            .block_on(SingleSessionClient::connect(&config))
            .map_err(operation_error)?;

        Ok(Self {
            runtime,
            inner: Mutex::new(client),
            pending_messages: Mutex::new(PendingMessages::default()),
        })
    }

    /// HTTP status returned by the relay WebSocket upgrade.
    pub fn status(&self) -> Result<i64, WcUniFfiError> {
        Ok(i64::from(self.client()?.status()))
    }

    /// Current relay connection state.
    pub fn connection_state(&self) -> Result<String, WcUniFfiError> {
        Ok(connection_state_label(self.client()?.connection_state()).to_owned())
    }

    /// Subscribes to a `WalletConnect` pairing URI.
    pub fn pair(&self, uri: String, origin: String) -> Result<String, WcUniFfiError> {
        let origin = parse_redirect_origin(&origin)?;
        let mut client = self.client()?;
        let topic = self
            .runtime
            .block_on(client.pair_with_origin(&uri, origin))
            .map_err(operation_error)?;
        Ok(topic.to_string())
    }

    /// Waits for the next event. Returns `WcEventKind.None` on relay receive timeout.
    pub fn next_event(&self) -> Result<WcEvent, WcUniFfiError> {
        let mut client = self.client()?;
        let event = self
            .runtime
            .block_on(client.next_event())
            .map_err(operation_error)?;
        let Some(event) = event else {
            return Ok(WcEvent {
                kind: WcEventKind::None,
                topic: None,
                request_id: None,
                review: None,
                message: None,
            });
        };
        let output = self.event_to_record(&client, event)?;
        Ok(output)
    }

    /// Returns currently pending wallet approvals.
    pub fn pending_approvals(&self) -> Result<Vec<WcPendingApproval>, WcUniFfiError> {
        let client = self.client()?;
        client
            .pending_approvals()
            .map_err(operation_error)?
            .iter()
            .map(|approval| pending_approval_to_record(&client, approval))
            .collect()
    }

    /// Returns the active session JSON, if any.
    pub fn active_session_json(&self) -> Result<Option<String>, WcUniFfiError> {
        self.client()?.active_session().map(json_string).transpose()
    }

    /// Returns a wallet-facing active session review JSON, if any.
    pub fn active_session_review_json(&self) -> Result<Option<String>, WcUniFfiError> {
        let client = self.client()?;
        client
            .active_session()
            .map(|session| {
                active_session_review_json(
                    session,
                    connection_state_label(client.connection_state()),
                )
            })
            .transpose()
    }

    /// Remembers a caller-resolved Verify context for a pending approval.
    pub fn remember_verify_context(
        &self,
        topic: String,
        request_id: i64,
        verify_context_json: String,
    ) -> Result<bool, WcUniFfiError> {
        let _ = (topic, request_id, verify_context_json);
        Err(invalid_input(
            "caller-supplied Verify context JSON is not accepted; use Rust-resolved pending approval context",
        ))
    }

    /// Approves a pending session proposal after wallet UI/policy approval.
    pub fn approve_session(
        &self,
        topic: String,
        request_id: i64,
        capabilities: WcCapabilities,
        wallet_metadata: WcWalletMetadata,
        expiry: Option<i64>,
        verify_context_json: Option<String>,
    ) -> Result<WcSessionInfo, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let capabilities = wallet_capabilities(capabilities)?;
        let wallet_metadata = wallet_metadata.try_into()?;
        let expiry = match expiry {
            Some(expiry) => i64_to_u64("expiry", expiry)?,
            None => now_unix_seconds()?
                .checked_add(DEFAULT_SESSION_EXPIRY_SECONDS)
                .ok_or_else(|| invalid_input("expiry overflow"))?,
        };
        let mut client = self.client()?;
        remember_verify_context_if_present(&client, &topic, request_id, verify_context_json)?;
        let proposal = client
            .pending_approvals()
            .map_err(operation_error)?
            .into_iter()
            .find_map(|approval| match approval {
                SingleSessionPendingApproval::SessionProposal(proposal)
                    if proposal.pairing_topic() == &topic
                        && proposal.proposal_id() == request_id =>
                {
                    Some(proposal)
                }
                _ => None,
            })
            .ok_or_else(|| state_error("pending session proposal not found"))?;
        let verify_review = proposal.verify_risk_review();
        let approval = capabilities
            .plan_session_approval(proposal.request(), wallet_metadata, expiry)
            .map_err(operation_error)?;
        let session = self
            .runtime
            .block_on(client.approve_session(&proposal, &verify_review, approval))
            .map_err(operation_error)?;
        session_info(&session)
    }

    /// Rejects a pending session proposal.
    pub fn reject_session(
        &self,
        topic: String,
        request_id: i64,
        error_code: i64,
        message: String,
    ) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let mut client = self.client()?;
        let proposal = client
            .pending_approvals()
            .map_err(operation_error)?
            .into_iter()
            .find_map(|approval| match approval {
                SingleSessionPendingApproval::SessionProposal(proposal)
                    if proposal.pairing_topic() == &topic
                        && proposal.proposal_id() == request_id =>
                {
                    Some(proposal)
                }
                _ => None,
            })
            .ok_or_else(|| state_error("pending session proposal not found"))?;
        let ack = self
            .runtime
            .block_on(client.reject_session(
                &proposal,
                JsonRpcError::new(JsonRpcErrorCode::from_i64(error_code), message),
            ))
            .map_err(operation_error)?;
        Ok(ack)
    }

    /// Approves a pending `wc_sessionAuthenticate` request with signed CACAO JSON.
    pub fn approve_session_authenticate(
        &self,
        topic: String,
        request_id: i64,
        wallet_metadata: WcWalletMetadata,
        cacaos_json: String,
        session_capabilities: Option<WcCapabilities>,
        verify_context_json: Option<String>,
    ) -> Result<WcSessionAuthenticateOutcome, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let wallet_metadata = wallet_metadata.try_into()?;
        let cacaos = parse_cacaos_json(&cacaos_json)?;
        let session_namespaces = optional_session_namespaces(session_capabilities)?;
        let mut client = self.client()?;
        remember_verify_context_if_present(&client, &topic, request_id, verify_context_json)?;
        let authenticate = client
            .pending_approvals()
            .map_err(operation_error)?
            .into_iter()
            .find_map(|approval| match approval {
                SingleSessionPendingApproval::SessionAuthenticate(authenticate)
                    if authenticate.pairing_topic() == &topic
                        && authenticate.request_id() == request_id =>
                {
                    Some(authenticate)
                }
                _ => None,
            })
            .ok_or_else(|| state_error("pending session authenticate not found"))?;
        let review = client
            .session_authenticate_review(&authenticate)
            .map_err(operation_error)?;
        let verify_review = review.verify_risk_review();
        let mut approval =
            SessionAuthenticateApproval::new(wallet_metadata, cacaos).map_err(operation_error)?;
        if let Some(namespaces) = session_namespaces {
            approval = approval.with_session_namespaces(namespaces);
        }
        let outcome = self
            .runtime
            .block_on(client.approve_session_authenticate(&authenticate, &verify_review, approval))
            .map_err(operation_error)?;
        session_authenticate_outcome(outcome)
    }

    /// Returns the exact CAIP-122 authentication message to sign for a selected account.
    pub fn session_authenticate_signing_json(
        &self,
        topic: String,
        request_id: i64,
        account_id: String,
    ) -> Result<String, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let account = parse_account_id(account_id)?;
        let client = self.client()?;
        let review = pending_session_authenticate_review(&client, &topic, request_id)?;
        let issuer = requested_auth_issuer(&review, account)?;
        let payload = review
            .auth_payload()
            .to_cacao_payload(&issuer)
            .map_err(operation_error)?;
        let message = review
            .auth_payload()
            .format_message(&issuer)
            .map_err(operation_error)?;
        let payload_review = review.auth_payload_review();

        json_string(&json!({
            "kind": "sessionAuthenticateSigning",
            "topic": topic.to_string(),
            "requestId": request_id,
            "account": issuer.account_id_str(),
            "issuer": issuer.as_str(),
            "message": message,
            "payload": payload,
            "display": {
                "intent": "Sign WalletConnect authentication",
                "warnings": [
                    "Approving signs the exact CAIP-122 message with the displayed Bitcoin account.",
                    "This proves account control to the displayed domain. Reject if the domain, URL, nonce, statement, account, or chain is unexpected."
                ],
                "details": [
                    {"label": "Signing account", "value": issuer.account_id_str()},
                    {"label": "Domain", "value": payload_review.domain()},
                    {"label": "Audience", "value": payload_review.audience()},
                    {"label": "Nonce", "value": payload_review.nonce()},
                    {"label": "Statement", "value": payload_review.statement().unwrap_or("")},
                    {"label": "Message", "value": message}
                ],
                "info": [
                    "The CACAO response is built from the same typed payload after this exact message is signed.",
                    "The wallet never signs a hidden replacement message; the returned CACAO must structurally match the pending WalletConnect auth payload."
                ]
            }
        }))
    }

    /// Builds signed CACAO JSON for a selected account and caller-produced signature.
    pub fn session_authenticate_cacaos_json(
        &self,
        topic: String,
        request_id: i64,
        account_id: String,
        signature: String,
        signature_type: Option<String>,
        signature_meta: Option<String>,
    ) -> Result<String, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let account = parse_account_id(account_id)?;
        let client = self.client()?;
        let review = pending_session_authenticate_review(&client, &topic, request_id)?;
        let issuer = requested_auth_issuer(&review, account)?;
        let signature = CacaoSignature {
            kind: CacaoSignatureType::from_wire(
                signature_type.unwrap_or_else(|| "eip191".to_owned()),
            ),
            signature: CacaoSignatureValue::from_wire(signature),
            meta: signature_meta,
        };
        let cacao = review
            .auth_payload()
            .to_cacao(&issuer, signature)
            .map_err(operation_error)?;
        cacao
            .validate_against_auth_payload(review.auth_payload())
            .map_err(operation_error)?;

        json_string(&vec![cacao])
    }

    /// Rejects a pending `wc_sessionAuthenticate` request.
    pub fn reject_session_authenticate(
        &self,
        topic: String,
        request_id: i64,
        error_code: i64,
        message: String,
    ) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let mut client = self.client()?;
        let authenticate = client
            .pending_approvals()
            .map_err(operation_error)?
            .into_iter()
            .find_map(|approval| match approval {
                SingleSessionPendingApproval::SessionAuthenticate(authenticate)
                    if authenticate.pairing_topic() == &topic
                        && authenticate.request_id() == request_id =>
                {
                    Some(authenticate)
                }
                _ => None,
            })
            .ok_or_else(|| state_error("pending session authenticate not found"))?;
        let ack = self
            .runtime
            .block_on(client.reject_session_authenticate(
                &authenticate,
                JsonRpcError::new(JsonRpcErrorCode::from_i64(error_code), message),
            ))
            .map_err(operation_error)?;
        Ok(ack)
    }

    /// Approves a pending session namespace update.
    pub fn approve_session_update(
        &self,
        topic: String,
        request_id: i64,
        capabilities: WcCapabilities,
    ) -> Result<bool, WcUniFfiError> {
        let key = pending_key(PendingMessageKind::SessionUpdate, &topic, request_id)?;
        let capabilities = wallet_capabilities(capabilities)?;
        let message = self.session_update_message(&key)?;
        let mut client = self.client()?;
        let ack = self
            .runtime
            .block_on(client.approve_session_update(&message, &capabilities))
            .map_err(operation_error)?;
        if ack {
            self.pending_messages()?.session_updates.remove(&key);
        }
        Ok(ack)
    }

    /// Rejects a pending session namespace update.
    pub fn reject_session_update(
        &self,
        topic: String,
        request_id: i64,
        error_code: i64,
        message: String,
    ) -> Result<bool, WcUniFfiError> {
        let key = pending_key(PendingMessageKind::SessionUpdate, &topic, request_id)?;
        let event = self.session_update_message(&key)?;
        let mut client = self.client()?;
        let ack = self
            .runtime
            .block_on(client.reject_session_update(
                &event,
                JsonRpcError::new(JsonRpcErrorCode::from_i64(error_code), message),
            ))
            .map_err(operation_error)?;
        if ack {
            self.pending_messages()?.session_updates.remove(&key);
        }
        Ok(ack)
    }

    /// Publishes a wallet-authored `wc_sessionUpdate` namespace replacement.
    pub fn update_session(
        &self,
        topic: String,
        capabilities: WcCapabilities,
    ) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let namespaces = required_session_namespaces(capabilities)?;
        let mut client = self.client()?;
        let response = self
            .runtime
            .block_on(client.update_session(&topic, &namespaces))
            .map_err(operation_error)?;
        Ok(matches!(
            response.payload(),
            SessionLifecycleResponsePayload::Success(_)
        ))
    }

    /// Publishes a wallet-authored `wc_sessionEvent`.
    pub fn emit_session_event(
        &self,
        topic: String,
        params_json: String,
    ) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let params = parse_session_event_params_json(&params_json)?;
        let mut client = self.client()?;
        let request = self
            .runtime
            .block_on(client.emit_session_event(&topic, &params))
            .map_err(operation_error)?;
        Ok(request.publish_ack())
    }

    /// Responds to a pending non-Bitcoin session request with caller-supplied JSON.
    pub fn respond_session_request_success_json(
        &self,
        topic: String,
        request_id: i64,
        result_json: String,
        verify_context_json: Option<String>,
    ) -> Result<bool, WcUniFfiError> {
        let key = pending_key(PendingMessageKind::SessionRequest, &topic, request_id)?;
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let message = self.session_request_message(&key)?;
        let result = parse_json_value(&result_json)?;
        let mut client = self.client()?;
        remember_verify_context_if_present(&client, &topic, request_id, verify_context_json)?;
        let review = client
            .session_request_review(&message)
            .map_err(operation_error)?;
        let approval =
            SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject)
                .map_err(operation_error)?;
        let ack = self
            .runtime
            .block_on(client.respond_session_request_success(&message, &approval, result))
            .map_err(operation_error)?;
        if ack {
            self.pending_messages()?.session_requests.remove(&key);
        }
        Ok(ack)
    }

    /// Responds to a pending Bitcoin session request after validating result shape.
    pub fn respond_bitcoin_request_success_json(
        &self,
        topic: String,
        request_id: i64,
        result_json: String,
        verify_context_json: Option<String>,
    ) -> Result<bool, WcUniFfiError> {
        let key = pending_key(PendingMessageKind::SessionRequest, &topic, request_id)?;
        let topic = parse_topic(&topic)?;
        let request_id = i64_to_u64("request_id", request_id)?;
        let message = self.session_request_message(&key)?;
        let mut client = self.client()?;
        remember_verify_context_if_present(&client, &topic, request_id, verify_context_json)?;
        let review = client
            .session_request_review(&message)
            .map_err(operation_error)?;
        let bitcoin_review = BitcoinRequestReview::from_session_request(&review)
            .map_err(|error| invalid_input(error.to_string()))?;
        let account_scope =
            bitcoin_account_scope_from_session(client.active_session(), bitcoin_review.request())?;
        let result = validated_bitcoin_result(
            bitcoin_review.request(),
            &result_json,
            account_scope.as_ref(),
        )?;
        let approval = SessionRequestApproval::from_external_typed_review(
            &review,
            ExternalSessionRequestMethodReview::new(&review, "wc-uniffi-bitcoin"),
        )
        .map_err(operation_error)?;
        let ack = self
            .runtime
            .block_on(client.respond_session_request_success(&message, &approval, result))
            .map_err(operation_error)?;
        if ack {
            self.pending_messages()?.session_requests.remove(&key);
        }
        Ok(ack)
    }

    /// Responds to a pending session request with a JSON-RPC error.
    pub fn respond_session_request_error(
        &self,
        topic: String,
        request_id: i64,
        error_code: i64,
        message: String,
    ) -> Result<bool, WcUniFfiError> {
        let key = pending_key(PendingMessageKind::SessionRequest, &topic, request_id)?;
        let event = self.session_request_message(&key)?;
        let mut client = self.client()?;
        let ack = self
            .runtime
            .block_on(client.respond_session_request_error(
                &event,
                JsonRpcError::new(JsonRpcErrorCode::from_i64(error_code), message),
            ))
            .map_err(operation_error)?;
        if ack {
            self.pending_messages()?.session_requests.remove(&key);
        }
        Ok(ack)
    }

    /// Publishes `wc_sessionExtend` for the active session topic.
    pub fn extend_session(&self, topic: String) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let mut client = self.client()?;
        let response = self
            .runtime
            .block_on(client.extend_session(&topic))
            .map_err(operation_error)?;
        Ok(matches!(
            response.payload(),
            SessionLifecycleResponsePayload::Success(_)
        ))
    }

    /// Disconnects an active session and clears local state after publish ack.
    pub fn disconnect(
        &self,
        topic: String,
        error_code: i64,
        message: String,
    ) -> Result<bool, WcUniFfiError> {
        let topic = parse_topic(&topic)?;
        let mut client = self.client()?;
        let request = self
            .runtime
            .block_on(client.disconnect(
                &topic,
                SessionDeleteParams {
                    code: error_code,
                    message,
                },
            ))
            .map_err(operation_error)?;
        if request.publish_ack() {
            self.clear_pending_messages()?;
        }
        Ok(request.publish_ack())
    }

    /// Closes the relay socket and clears current in-memory state.
    pub fn shutdown(&self) -> Result<(), WcUniFfiError> {
        let mut client = self.client()?;
        let result = self
            .runtime
            .block_on(client.shutdown())
            .map_err(operation_error);
        self.clear_pending_messages()?;
        result
    }
}

impl WcClient {
    fn client(&self) -> Result<MutexGuard<'_, SingleSessionClient>, WcUniFfiError> {
        self.inner
            .lock()
            .map_err(|_| state_error("client lock poisoned"))
    }

    fn pending_messages(&self) -> Result<MutexGuard<'_, PendingMessages>, WcUniFfiError> {
        self.pending_messages
            .lock()
            .map_err(|_| state_error("pending message lock poisoned"))
    }

    fn clear_pending_messages(&self) -> Result<(), WcUniFfiError> {
        let mut pending = self.pending_messages()?;
        pending.session_requests.clear();
        pending.session_updates.clear();
        Ok(())
    }

    fn session_request_message(
        &self,
        key: &PendingMessageKey,
    ) -> Result<wc_core::SessionReceivedMessage, WcUniFfiError> {
        self.pending_messages()?
            .session_requests
            .get(key)
            .cloned()
            .ok_or_else(|| state_error("pending session request message not found"))
    }

    fn session_update_message(
        &self,
        key: &PendingMessageKey,
    ) -> Result<wc_core::SessionReceivedMessage, WcUniFfiError> {
        self.pending_messages()?
            .session_updates
            .get(key)
            .cloned()
            .ok_or_else(|| state_error("pending session update message not found"))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "This dispatcher keeps the exported event mapping auditable in one place."
    )]
    fn event_to_record(
        &self,
        client: &SingleSessionClient,
        event: SingleSessionClientEvent,
    ) -> Result<WcEvent, WcUniFfiError> {
        match event {
            SingleSessionClientEvent::SessionProposal(proposal) => Ok(WcEvent {
                kind: WcEventKind::SessionProposal,
                topic: Some(proposal.pairing_topic().to_string()),
                request_id: Some(u64_to_i64(proposal.proposal_id())?),
                review: Some(WcJsonPayload::new(proposal_review_json(&proposal)?)),
                message: None,
            }),
            SingleSessionClientEvent::SessionAuthenticate(authenticate) => {
                let review = client
                    .session_authenticate_review(&authenticate)
                    .map_err(operation_error)?;
                Ok(WcEvent {
                    kind: WcEventKind::SessionAuthenticate,
                    topic: Some(authenticate.pairing_topic().to_string()),
                    request_id: Some(u64_to_i64(authenticate.request_id())?),
                    review: Some(WcJsonPayload::new(authenticate_review_json(&review)?)),
                    message: None,
                })
            }
            SingleSessionClientEvent::PairingMessage(message) => Ok(WcEvent {
                kind: WcEventKind::PairingMessage,
                topic: Some(message.topic().to_string()),
                request_id: None,
                review: None,
                message: Some("pairing message received".to_owned()),
            }),
            SingleSessionClientEvent::SessionProposalExpired(expired) => Ok(WcEvent {
                kind: WcEventKind::SessionProposalExpired,
                topic: Some(expired.pairing_topic().to_string()),
                request_id: Some(u64_to_i64(expired.proposal_id())?),
                review: None,
                message: Some(format!(
                    "proposal expired at {} before {}",
                    expired.expiry(),
                    expired.now_unix_seconds()
                )),
            }),
            SingleSessionClientEvent::SessionAuthenticateExpired(expired) => Ok(WcEvent {
                kind: WcEventKind::SessionAuthenticateExpired,
                topic: Some(expired.pairing_topic().to_string()),
                request_id: Some(u64_to_i64(expired.request_id())?),
                review: None,
                message: Some(format!(
                    "authenticate request expired at {} before {}",
                    expired.expiry(),
                    expired.now_unix_seconds()
                )),
            }),
            SingleSessionClientEvent::Session(session_event) => {
                let topic = session_event.topic().to_string();
                match session_event {
                    wc_core::SessionClientEvent::SessionRequest(message) => {
                        let review = client
                            .session_request_review(&message)
                            .map_err(operation_error)?;
                        let key = PendingMessageKey {
                            kind: PendingMessageKind::SessionRequest,
                            topic: topic.clone(),
                            request_id: review.request_id(),
                        };
                        self.pending_messages()?
                            .session_requests
                            .insert(key, message);
                        Ok(WcEvent {
                            kind: WcEventKind::SessionRequest,
                            topic: Some(topic),
                            request_id: Some(u64_to_i64(review.request_id())?),
                            review: Some(WcJsonPayload::new(session_request_review_json(&review)?)),
                            message: None,
                        })
                    }
                    wc_core::SessionClientEvent::SessionUpdate(message) => {
                        let review = client
                            .session_update_review(&message)
                            .map_err(operation_error)?;
                        let key = PendingMessageKey {
                            kind: PendingMessageKind::SessionUpdate,
                            topic: topic.clone(),
                            request_id: review.request_id(),
                        };
                        self.pending_messages()?
                            .session_updates
                            .insert(key, message);
                        Ok(WcEvent {
                            kind: WcEventKind::SessionUpdate,
                            topic: Some(topic),
                            request_id: Some(u64_to_i64(review.request_id())?),
                            review: Some(WcJsonPayload::new(session_update_review_json(&review)?)),
                            message: None,
                        })
                    }
                    wc_core::SessionClientEvent::SessionEvent(message) => Ok(WcEvent {
                        kind: WcEventKind::SessionEvent,
                        topic: Some(topic),
                        request_id: session_message_request_id(&message).transpose()?,
                        review: None,
                        message: Some("session event received".to_owned()),
                    }),
                    wc_core::SessionClientEvent::SessionPing(message) => Ok(WcEvent {
                        kind: WcEventKind::SessionPing,
                        topic: Some(topic),
                        request_id: session_message_request_id(&message).transpose()?,
                        review: None,
                        message: Some("session ping acknowledged".to_owned()),
                    }),
                    wc_core::SessionClientEvent::SessionExtend(message) => Ok(WcEvent {
                        kind: WcEventKind::SessionExtend,
                        topic: Some(topic),
                        request_id: session_message_request_id(&message).transpose()?,
                        review: None,
                        message: Some("session extend acknowledged".to_owned()),
                    }),
                    wc_core::SessionClientEvent::SessionDelete(message) => {
                        self.clear_pending_messages()?;
                        Ok(WcEvent {
                            kind: WcEventKind::SessionDelete,
                            topic: Some(topic),
                            request_id: session_message_request_id(&message).transpose()?,
                            review: None,
                            message: Some("session delete acknowledged".to_owned()),
                        })
                    }
                    wc_core::SessionClientEvent::Unsupported(message) => Ok(WcEvent {
                        kind: WcEventKind::UnsupportedSessionMessage,
                        topic: Some(topic),
                        request_id: session_message_request_id(&message).transpose()?,
                        review: None,
                        message: Some("unsupported session message received".to_owned()),
                    }),
                    wc_core::SessionClientEvent::RejectedSessionRequest(rejection) => Ok(WcEvent {
                        kind: WcEventKind::RejectedSessionRequest,
                        topic: Some(rejection.topic().to_string()),
                        request_id: Some(u64_to_i64(rejection.request_id())?),
                        review: Some(WcJsonPayload::new(json_string(&json!({
                            "topic": rejection.topic().to_string(),
                            "requestId": rejection.request_id(),
                            "error": rejection.error(),
                            "responseAck": rejection.response_ack(),
                        }))?)),
                        message: Some("invalid session request rejected automatically".to_owned()),
                    }),
                }
            }
            SingleSessionClientEvent::SessionExpired(expired) => {
                self.clear_pending_messages()?;
                Ok(WcEvent {
                    kind: WcEventKind::SessionExpired,
                    topic: Some(expired.topic().to_string()),
                    request_id: None,
                    review: None,
                    message: Some(format!("session expired at {}", expired.expiry())),
                })
            }
        }
    }
}
