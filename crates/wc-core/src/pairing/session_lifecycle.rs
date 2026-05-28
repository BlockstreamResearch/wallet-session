use wc_protocol::{
    relay::IrnPublish,
    session::{SessionAckResponse, session_ack_response},
};

use super::{
    SESSION_DELETE_RESPONSE_TAG, SESSION_DELETE_RESPONSE_TTL_SECONDS, SESSION_PING_RESPONSE_TAG,
    SESSION_PING_RESPONSE_TTL_SECONDS,
    error::PairingClientError,
    publish::encrypted_json_publish,
    types::{SessionPayload, SessionReceivedMessage, SessionSubscription},
};

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
