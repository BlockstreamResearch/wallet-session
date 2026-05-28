use wc_protocol::{
    namespaces::{is_chain_authorized, is_event_authorized},
    relay::IrnPublish,
    session::{
        JsonRpcError, JsonRpcErrorResponse, JsonRpcRequest, Session, SessionAckResponse,
        SessionDeleteParams, SessionEventParams, SessionExtendParams, SessionNamespaces,
        SessionUpdateParams, SignMethod, session_ack_response,
    },
};

use super::{
    SESSION_DELETE_REQUEST_TAG, SESSION_DELETE_REQUEST_TTL_SECONDS, SESSION_DELETE_RESPONSE_TAG,
    SESSION_DELETE_RESPONSE_TTL_SECONDS, SESSION_EVENT_REQUEST_TAG,
    SESSION_EVENT_REQUEST_TTL_SECONDS, SESSION_EXTEND_REQUEST_TAG,
    SESSION_EXTEND_REQUEST_TTL_SECONDS, SESSION_EXTEND_RESPONSE_TAG,
    SESSION_EXTEND_RESPONSE_TTL_SECONDS, SESSION_PING_RESPONSE_TAG,
    SESSION_PING_RESPONSE_TTL_SECONDS, SESSION_UPDATE_REQUEST_TAG,
    SESSION_UPDATE_REQUEST_TTL_SECONDS, SESSION_UPDATE_RESPONSE_TAG,
    SESSION_UPDATE_RESPONSE_TTL_SECONDS,
    error::PairingClientError,
    publish::encrypted_json_publish,
    types::{SessionPayload, SessionReceivedMessage, SessionSubscription},
};

/// Builds an encrypted `wc_sessionUpdate` request publish.
///
/// The maintained Sign Client sends the replacement namespace map in the request
/// params before applying the same namespace update locally.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L638-L650>
///
/// > method: "wc_sessionUpdate",
/// > params: { namespaces },
/// > await this.client.session.update(topic, { namespaces });
pub(super) fn session_update_request_publish(
    subscription: &SessionSubscription,
    session: &Session,
    namespaces: &SessionNamespaces,
    request_id: u64,
    now_unix_seconds: u64,
) -> Result<IrnPublish, PairingClientError> {
    ensure_outbound_session_ready(subscription, session, now_unix_seconds)?;
    let request = JsonRpcRequest::new(
        request_id,
        SignMethod::SessionUpdate,
        SessionUpdateParams {
            namespaces: namespaces.clone(),
        },
    );

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &request,
        SESSION_UPDATE_REQUEST_TTL_SECONDS,
        SESSION_UPDATE_REQUEST_TAG,
    )
}

/// Builds an encrypted `wc_sessionExtend` request publish.
///
/// Current Sign Client traffic sends empty params and extends local expiry from
/// session state rather than carrying `expiry` in the request body.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L678-L685>
///
/// > await this.setExpiry(topic, calcExpiry(SESSION_EXPIRY));
/// > method: "wc_sessionExtend",
/// > params: {},
pub(super) fn session_extend_request_publish(
    subscription: &SessionSubscription,
    session: &Session,
    request_id: u64,
    now_unix_seconds: u64,
) -> Result<IrnPublish, PairingClientError> {
    ensure_outbound_session_ready(subscription, session, now_unix_seconds)?;
    let request = JsonRpcRequest::new(
        request_id,
        SignMethod::SessionExtend,
        SessionExtendParams::default(),
    );

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &request,
        SESSION_EXTEND_REQUEST_TTL_SECONDS,
        SESSION_EXTEND_REQUEST_TAG,
    )
}

/// Builds an encrypted `wc_sessionEvent` request publish.
///
/// The maintained Sign Client emits the event to application listeners after
/// validating the session topic, chain, and event name.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L881-L896>
///
/// > method: "wc_sessionEvent",
/// > params: { event, chainId },
/// > throwOnFailedPublish: true,
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2537-L2539>
///
/// > this.isValidEmit({ topic, ...params });
/// > this.client.events.emit("session_event", { id, topic, params });
pub(super) fn session_event_request_publish(
    subscription: &SessionSubscription,
    session: &Session,
    params: &SessionEventParams,
    request_id: u64,
    now_unix_seconds: u64,
) -> Result<IrnPublish, PairingClientError> {
    ensure_outbound_session_ready(subscription, session, now_unix_seconds)?;
    ensure_session_event_authorized(session, params)?;
    let request = JsonRpcRequest::new(request_id, SignMethod::SessionEvent, params.clone());

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &request,
        SESSION_EVENT_REQUEST_TTL_SECONDS,
        SESSION_EVENT_REQUEST_TAG,
    )
}

/// Builds an encrypted `wc_sessionDelete` request publish.
///
/// The maintained Sign Client validates the topic, publishes
/// `wc_sessionDelete`, then deletes the local session after the relay publish
/// acknowledgement.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L897-L909>
///
/// > method: "wc_sessionDelete",
/// > params: getSdkError("USER_DISCONNECTED"),
/// > throwOnFailedPublish: true,
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L904-L907>
///
/// > // await an ack to ensure the relay has received the disconnect request
/// > await this.sendRequest({
pub(super) fn session_delete_request_publish(
    subscription: &SessionSubscription,
    session: &Session,
    params: SessionDeleteParams,
    request_id: u64,
    now_unix_seconds: u64,
) -> Result<IrnPublish, PairingClientError> {
    ensure_outbound_session_ready(subscription, session, now_unix_seconds)?;
    let request = JsonRpcRequest::new(request_id, SignMethod::SessionDelete, params);

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &request,
        SESSION_DELETE_REQUEST_TTL_SECONDS,
        SESSION_DELETE_REQUEST_TAG,
    )
}

/// Builds an encrypted `wc_sessionPing` acknowledgement publish.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionping>
///
/// > // Success result
/// > true
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2401-L2411>
///
/// > await this.sendResult<"wc_sessionPing">({
/// > id,
/// > topic,
/// > result: true,
pub(super) fn session_ping_response_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_ack_response(session_ping_request_id(subscription, message)?);
    session_ack_publish(
        subscription,
        &response,
        SESSION_PING_RESPONSE_TTL_SECONDS,
        SESSION_PING_RESPONSE_TAG,
    )
}

/// Builds an encrypted `wc_sessionDelete` acknowledgement publish.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessiondelete>
///
/// > // Success result
/// > true
///
/// The maintained Sign Client deletes the local session after validating the
/// received disconnect request. Store mutation belongs to a higher orchestration
/// layer; this helper only builds the protocol response.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2442-L2454>
///
/// > await this.isValidDisconnect({ topic, reason: payload.params });
/// > await this.deleteSession({ topic, id });
pub(super) fn session_delete_response_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_ack_response(session_delete_request_id(subscription, message)?);
    session_ack_publish(
        subscription,
        &response,
        SESSION_DELETE_RESPONSE_TTL_SECONDS,
        SESSION_DELETE_RESPONSE_TAG,
    )
}

/// Builds an encrypted `wc_sessionUpdate` acknowledgement publish.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2302-L2327>
///
/// > await this.sendResult<"wc_sessionUpdate">({
/// > id,
/// > result: true,
pub(super) fn session_update_response_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_ack_response(session_update_request_id(subscription, message)?);
    session_ack_publish(
        subscription,
        &response,
        SESSION_UPDATE_RESPONSE_TTL_SECONDS,
        SESSION_UPDATE_RESPONSE_TAG,
    )
}

/// Builds an encrypted `wc_sessionUpdate` error publish.
///
/// A namespace update changes session permissions, so higher layers can reject
/// it instead of sending the `result: true` acknowledgement.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2327-L2333>
///
/// > } catch (e) {
/// > MemoryStore.delete(memoryKey);
/// > await this.sendError({
pub(super) fn session_update_error_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
    error: JsonRpcError,
) -> Result<IrnPublish, PairingClientError> {
    let response =
        JsonRpcErrorResponse::new(session_update_request_id(subscription, message)?, error);
    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &response,
        SESSION_UPDATE_RESPONSE_TTL_SECONDS,
        SESSION_UPDATE_RESPONSE_TAG,
    )
}

/// Builds an encrypted `wc_sessionExtend` acknowledgement publish.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2363-L2375>
///
/// > await this.sendResult<"wc_sessionExtend">({
/// > id,
/// > result: true,
pub(super) fn session_extend_response_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<IrnPublish, PairingClientError> {
    let response = session_extend_request_id(subscription, message).map(session_ack_response)?;
    session_ack_publish(
        subscription,
        &response,
        SESSION_EXTEND_RESPONSE_TTL_SECONDS,
        SESSION_EXTEND_RESPONSE_TAG,
    )
}

fn session_ack_publish(
    subscription: &SessionSubscription,
    response: &SessionAckResponse,
    ttl: u64,
    tag: u64,
) -> Result<IrnPublish, PairingClientError> {
    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        response,
        ttl,
        tag,
    )
}

/// Checks the session record before publishing controller-side lifecycle requests.
///
/// This mirrors the same topic/acknowledged/expiry guard used before decoding
/// inbound session-topic messages, but runs before encryption so invalid local
/// state cannot produce relay traffic.
fn ensure_outbound_session_ready(
    subscription: &SessionSubscription,
    session: &Session,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    if &session.topic != subscription.topic() {
        return Err(PairingClientError::SessionSubscriptionTopicMismatch {
            session_topic: session.topic.clone(),
            subscription_topic: subscription.topic().clone(),
        });
    }

    if !session.acknowledged {
        return Err(PairingClientError::SessionNotAcknowledged {
            topic: session.topic.clone(),
        });
    }

    if session.is_expired_at(now_unix_seconds) {
        return Err(PairingClientError::SessionExpired {
            expiry_timestamp: session.expiry,
            now_unix_seconds,
        });
    }

    Ok(())
}

/// Applies outbound chain/event checks before publishing `wc_sessionEvent`.
///
/// This mirrors the maintained Sign Client validation boundary before an
/// incoming event is emitted to application listeners.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2537-L2539>
///
/// > this.isValidEmit({ topic, ...params });
/// > this.client.events.emit("session_event", { id, topic, params });
fn ensure_session_event_authorized(
    session: &Session,
    params: &SessionEventParams,
) -> Result<(), PairingClientError> {
    if !is_chain_authorized(&session.namespaces, &params.chain_id) {
        return Err(PairingClientError::SessionUnauthorizedChain {
            chain_id: params.chain_id.clone(),
        });
    }

    if !is_event_authorized(
        &session.namespaces,
        &params.chain_id,
        params.event.name.as_str(),
    ) {
        return Err(PairingClientError::SessionUnauthorizedEvent {
            chain_id: params.chain_id.clone(),
            event: params.event.name.clone(),
        });
    }

    Ok(())
}

fn session_ping_request_id(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<u64, PairingClientError> {
    ensure_session_topic(subscription, message)?;
    let SessionPayload::SessionPing(request) = message.payload() else {
        return Err(PairingClientError::SessionResponseTargetNotPing);
    };

    Ok(request.id)
}

fn session_update_request_id(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<u64, PairingClientError> {
    ensure_session_topic(subscription, message)?;
    let SessionPayload::SessionUpdate(request) = message.payload() else {
        return Err(PairingClientError::SessionResponseTargetNotUpdate);
    };

    Ok(request.id)
}

fn session_extend_request_id(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<u64, PairingClientError> {
    ensure_session_topic(subscription, message)?;
    let SessionPayload::SessionExtend(request) = message.payload() else {
        return Err(PairingClientError::SessionResponseTargetNotExtend);
    };

    Ok(request.id)
}

fn session_delete_request_id(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<u64, PairingClientError> {
    ensure_session_topic(subscription, message)?;
    let SessionPayload::SessionDelete(request) = message.payload() else {
        return Err(PairingClientError::SessionResponseTargetNotDelete);
    };

    Ok(request.id)
}

fn ensure_session_topic(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
) -> Result<(), PairingClientError> {
    if message.topic() != subscription.topic() {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic().clone(),
            actual: message.topic().clone(),
        });
    }

    Ok(())
}
