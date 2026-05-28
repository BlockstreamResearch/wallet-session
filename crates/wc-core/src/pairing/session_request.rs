use serde_json::Value;
use wc_protocol::{
    relay::IrnPublish,
    session::{
        JsonRpcError, SessionRequestParams, session_request_error_response,
        session_request_success_response,
    },
};

use super::{
    SESSION_REQUEST_RESPONSE_TAG, SESSION_REQUEST_RESPONSE_TTL_SECONDS,
    error::PairingClientError,
    publish::encrypted_json_publish,
    types::{SessionPayload, SessionReceivedMessage, SessionSubscription},
};

/// Builds an encrypted `wc_sessionRequest` success response publish.
///
/// The response uses the request ID and the same session topic as the incoming
/// request, mirroring Sign Client `respond`: validate response, then send
/// either `sendResult` or `sendError`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3646-L3715>
///
/// > if (isJsonRpcResult(response)) {
/// > await this.sendResult({
/// > id,
/// > topic,
pub(super) fn session_request_success_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
    result: Value,
) -> Result<IrnPublish, PairingClientError> {
    let request = session_request_from_message(subscription, message)?;
    let response = session_request_success_response(request.id, result);

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &response,
        SESSION_REQUEST_RESPONSE_TTL_SECONDS,
        SESSION_REQUEST_RESPONSE_TAG,
    )
}

/// Builds an encrypted `wc_sessionRequest` error response publish.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
///
/// > The client should immediately reject the request and respond an error if
/// > the target session permissions doesn't include the requested method or
/// > chain ID.
pub(super) fn session_request_error_publish(
    subscription: &SessionSubscription,
    message: &SessionReceivedMessage,
    error: JsonRpcError,
) -> Result<IrnPublish, PairingClientError> {
    let request = session_request_from_message(subscription, message)?;
    let response = session_request_error_response(request.id, error);

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &response,
        SESSION_REQUEST_RESPONSE_TTL_SECONDS,
        SESSION_REQUEST_RESPONSE_TAG,
    )
}

/// Extracts the typed request and checks that it belongs to the active topic.
///
/// A response publish must not be built from a queued message for another
/// session topic. The relay client routes by topic, but this check keeps the
/// response helper correct when called directly in tests or later orchestration.
fn session_request_from_message<'a>(
    subscription: &SessionSubscription,
    message: &'a SessionReceivedMessage,
) -> Result<&'a wc_protocol::session::JsonRpcRequest<SessionRequestParams>, PairingClientError> {
    if message.topic() != subscription.topic() {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic().clone(),
            actual: message.topic().clone(),
        });
    }

    let SessionPayload::SessionRequest(request) = message.payload() else {
        return Err(PairingClientError::SessionResponseTargetNotRequest);
    };

    Ok(request)
}
