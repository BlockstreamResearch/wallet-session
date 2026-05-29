use std::{
    sync::atomic::{AtomicU32, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use wc_protocol::{
    key::{X25519KeyPair, derive_shared_sym_key, derive_topic_from_sym_key},
    namespaces::validate_approved_namespaces,
    pairing::PairingSymKey,
    relay::{IrnPublish, RelayTopic},
    session::{
        JsonRpcError, JsonRpcRequest, JsonRpcResponse, Session, SessionParticipant,
        SessionProposeParams, SessionProposeResult, SessionSettleParams, SessionTransportType,
        SignMethod, session_propose_error_response,
    },
};

use super::{
    SESSION_PROPOSE_REJECT_TAG, SESSION_PROPOSE_REJECT_TTL_SECONDS, SESSION_PROPOSE_RESPONSE_TAG,
    SESSION_PROPOSE_RESPONSE_TTL_SECONDS, SESSION_SETTLE_REQUEST_TAG,
    SESSION_SETTLE_REQUEST_TTL_SECONDS,
    error::{PairingClientError, SignRpcIdError},
    publish::encrypted_json_publish,
    types::{PairingSubscription, SessionProposalApproval},
};

static SIGN_RPC_ID_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Returns unix milliseconds for Sign JSON-RPC ID generation.
fn now_unix_millis() -> Result<u64, SignRpcIdError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|source| SignRpcIdError::Clock { source })?
        .as_millis()
        .try_into()
        .map_err(|_| SignRpcIdError::Overflow)
}

/// Builds a Sign JSON-RPC ID using the same timestamp-plus-entropy layout as JS.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L5-L8>
///
/// > const date = Date.now() * Math.pow(10, entropy);
/// > const extra = Math.floor(Math.random() * Math.pow(10, entropy));
pub(super) fn next_sign_rpc_id() -> Result<u64, PairingClientError> {
    let entropy = u64::from(SIGN_RPC_ID_COUNTER.fetch_add(1, Ordering::Relaxed) % 1_000);
    now_unix_millis()
        .map_err(|source| PairingClientError::SignRpcId { source })?
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(entropy))
        .ok_or(SignRpcIdError::Overflow)
        .map_err(|source| PairingClientError::SignRpcId { source })
}

pub(super) struct SessionProposalApprovalPublishes {
    pub(super) session_topic: RelayTopic,
    pub(super) session_sym_key: PairingSymKey,
    pub(super) session: Session,
    pub(super) proposal_response: IrnPublish,
    pub(super) session_settle: IrnPublish,
}

/// Builds the encrypted relay publish payloads for proposal approval.
///
/// The maintained Sign Client formats one JSON-RPC result on the pairing topic
/// and one `wc_sessionSettle` request on the derived session topic.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1746-L1786>
///
/// > const pairingPayload = formatJsonRpcResult(proposal.id, pairingProposalResponse);
/// > const sessionSettlePayload = formatJsonRpcRequest(
/// > "wc_sessionSettle",
pub(super) fn session_proposal_approval_publishes(
    subscription: &PairingSubscription,
    proposal: &JsonRpcRequest<SessionProposeParams>,
    approval: SessionProposalApproval,
    responder: &X25519KeyPair,
    settle_request_id: u64,
) -> Result<SessionProposalApprovalPublishes, PairingClientError> {
    validate_session_proposal_approval(subscription, proposal, &approval)?;

    let session_sym_key = derive_shared_sym_key(
        responder.private_key(),
        &proposal.params.proposer.public_key,
    );
    let session_topic = derive_topic_from_sym_key(&session_sym_key);
    let controller = SessionParticipant {
        public_key: responder.public_key().clone(),
        metadata: approval.wallet_metadata.clone(),
    };
    let proposal_requests_responses = approval.proposal_requests_responses.clone();
    let session = Session {
        topic: session_topic.clone(),
        pairing_topic: subscription.topic.clone(),
        relay: approval.relay.clone(),
        expiry: approval.expiry,
        acknowledged: false,
        controller: responder.public_key().clone(),
        namespaces: approval.namespaces.clone(),
        required_namespaces: proposal.params.required_namespaces.clone(),
        optional_namespaces: proposal.params.optional_namespaces.clone(),
        session_properties: approval.session_properties.clone(),
        scoped_properties: approval.scoped_properties.clone(),
        session_config: approval.session_config.clone(),
        self_participant: controller.clone(),
        peer: SessionParticipant {
            public_key: proposal.params.proposer.public_key.clone(),
            metadata: proposal.params.proposer.metadata.clone(),
        },
        authentication: proposal_requests_responses
            .as_ref()
            .and_then(|responses| responses.authentication.clone()),
        wallet_pay_result: proposal_requests_responses
            .as_ref()
            .and_then(|responses| responses.wallet_pay.clone()),
        transport_type: Some(SessionTransportType::Relay),
    };

    let proposal_response = JsonRpcResponse::new(
        proposal.id,
        SessionProposeResult {
            relay: approval.relay.clone(),
            responder_public_key: responder.public_key().clone(),
        },
    );
    let proposal_response = encrypted_json_publish(
        subscription.topic.clone(),
        &subscription.sym_key,
        &proposal_response,
        SESSION_PROPOSE_RESPONSE_TTL_SECONDS,
        SESSION_PROPOSE_RESPONSE_TAG,
    )?;

    let session_settle = JsonRpcRequest::new(
        settle_request_id,
        SignMethod::SessionSettle,
        SessionSettleParams {
            relay: approval.relay,
            namespaces: approval.namespaces,
            controller,
            expiry: approval.expiry,
            session_properties: approval.session_properties,
            scoped_properties: approval.scoped_properties,
            session_config: approval.session_config,
            special_namespaces: None,
            proposal_requests_responses: approval.proposal_requests_responses,
        },
    );
    let session_settle = encrypted_json_publish(
        session_topic.clone(),
        &session_sym_key,
        &session_settle,
        SESSION_SETTLE_REQUEST_TTL_SECONDS,
        SESSION_SETTLE_REQUEST_TAG,
    )?;

    Ok(SessionProposalApprovalPublishes {
        session_topic,
        session_sym_key,
        session,
        proposal_response,
        session_settle,
    })
}

/// Checks proposal-level invariants before encrypting approval messages.
fn validate_session_proposal_approval(
    subscription: &PairingSubscription,
    proposal: &JsonRpcRequest<SessionProposeParams>,
    approval: &SessionProposalApproval,
) -> Result<(), PairingClientError> {
    if let Some(pairing_topic) = &proposal.params.pairing_topic {
        if pairing_topic != &subscription.topic {
            return Err(PairingClientError::ProposalPairingTopicMismatch {
                expected: subscription.topic.clone(),
                actual: pairing_topic.clone(),
            });
        }
    }

    validate_approved_namespaces(&proposal.params.required_namespaces, &approval.namespaces)
        .map_err(|source| PairingClientError::Namespace { source })
}

/// Builds the encrypted relay publish payload for proposal rejection.
///
/// This helper keeps outbound encoding deterministic enough for unit tests:
/// tests can decrypt the produced relay message without opening a WebSocket.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1852-L1884>
///
/// > const payload = formatJsonRpcError(id, error);
/// > message = await this.client.core.crypto.encode(topic, payload, {
/// > this.client.core.relayer.publish(topic, message, opts);
pub(super) fn session_proposal_reject_publish(
    subscription: &PairingSubscription,
    proposal_id: u64,
    error: JsonRpcError,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_propose_error_response(proposal_id, error);
    encrypted_json_publish(
        subscription.topic.clone(),
        &subscription.sym_key,
        &response,
        SESSION_PROPOSE_REJECT_TTL_SECONDS,
        SESSION_PROPOSE_REJECT_TAG,
    )
}
