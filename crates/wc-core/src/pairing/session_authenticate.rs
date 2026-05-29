use wc_protocol::{
    key::{X25519KeyPair, derive_shared_sym_key, derive_topic_from_x25519_public_key},
    relay::IrnPublish,
    session::{
        Cacao, DappMetadata, JsonRpcError, JsonRpcErrorResponse, JsonRpcResponse,
        SessionAuthenticateParams, SessionAuthenticateResult, SessionParticipant,
    },
};

use super::{
    SESSION_AUTHENTICATE_REJECT_TAG, SESSION_AUTHENTICATE_REJECT_TTL_SECONDS,
    SESSION_AUTHENTICATE_RESPONSE_TAG, SESSION_AUTHENTICATE_RESPONSE_TTL_SECONDS,
    error::PairingClientError,
    publish::encrypted_json_publish_type_1,
    types::{PairingPayload, PairingReceivedMessage, PairingSubscription},
};

/// Builds an encrypted `wc_sessionAuthenticate` rejection publish.
///
/// Session-authenticate responses are not sent on the pairing topic. The
/// maintained Sign Client derives a response topic from the requester public
/// key and sends the error with a type-1 envelope.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1448-L1465>
///
/// > const receiverPublicKey = pendingRequest.requester.publicKey;
/// > const responseTopic = hashKey(receiverPublicKey);
/// > await this.sendError({
pub(super) fn session_authenticate_error_publish(
    subscription: &PairingSubscription,
    message: &PairingReceivedMessage,
    error: JsonRpcError,
    responder: &X25519KeyPair,
) -> Result<IrnPublish, PairingClientError> {
    let request = session_authenticate_from_message(subscription, message)?;
    let sym_key = derive_shared_sym_key(
        responder.private_key(),
        &request.params.requester.public_key,
    );
    let response_topic = derive_topic_from_x25519_public_key(&request.params.requester.public_key);
    let response = JsonRpcErrorResponse::new(request.id, error);

    encrypted_json_publish_type_1(
        response_topic,
        &sym_key,
        responder.public_key(),
        &response,
        SESSION_AUTHENTICATE_REJECT_TTL_SECONDS,
        SESSION_AUTHENTICATE_REJECT_TAG,
    )
}

/// Builds an encrypted `wc_sessionAuthenticate` approval publish.
///
/// Session-authenticate approvals follow the same response topic and type-1
/// envelope routing as rejections, but carry the current SDK result object with
/// responder metadata and caller-provided signed CACAOs.
///
/// <https://docs.walletconnect.network/wallet-sdk/web/one-click-auth#approving-authentication-requests>
///
/// > auths: [auth],
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1405-L1415>
///
/// > result: {
/// > cacaos: auths,
pub(super) fn session_authenticate_success_publish(
    subscription: &PairingSubscription,
    message: &PairingReceivedMessage,
    wallet_metadata: DappMetadata,
    cacaos: Vec<Cacao>,
    responder: &X25519KeyPair,
) -> Result<IrnPublish, PairingClientError> {
    let request = session_authenticate_from_message(subscription, message)?;
    let sym_key = derive_shared_sym_key(
        responder.private_key(),
        &request.params.requester.public_key,
    );
    let response_topic = derive_topic_from_x25519_public_key(&request.params.requester.public_key);
    let response = JsonRpcResponse::new(
        request.id,
        SessionAuthenticateResult {
            responder: SessionParticipant {
                public_key: responder.public_key().clone(),
                metadata: wallet_metadata,
            },
            cacaos,
        },
    );

    encrypted_json_publish_type_1(
        response_topic,
        &sym_key,
        responder.public_key(),
        &response,
        SESSION_AUTHENTICATE_RESPONSE_TTL_SECONDS,
        SESSION_AUTHENTICATE_RESPONSE_TAG,
    )
}

/// Extracts the typed authenticate request and checks the active pairing topic.
///
/// The relay delivers the authenticate request on the pairing topic, but the
/// response is routed through a derived public-key topic. Checking the source
/// topic here prevents tests or later orchestration from answering an unrelated
/// pairing message.
fn session_authenticate_from_message<'a>(
    subscription: &PairingSubscription,
    message: &'a PairingReceivedMessage,
) -> Result<&'a wc_protocol::session::JsonRpcRequest<SessionAuthenticateParams>, PairingClientError>
{
    if message.topic() != subscription.topic() {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic().clone(),
            actual: message.topic().clone(),
        });
    }

    let PairingPayload::SessionAuthenticate(request) = message.payload() else {
        return Err(PairingClientError::SessionAuthenticateResponseTargetNotAuthenticate);
    };

    Ok(request)
}
