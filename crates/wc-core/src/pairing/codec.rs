use wc_protocol::{
    dto::pairing::PairingMethod,
    envelope::{Envelope, EnvelopeEncoding},
    namespaces::{is_chain_authorized, is_method_authorized},
    pairing::PairingSymKey,
    pairing_message::{PairingMessage, PairingMessageMethod},
    relay::{IrnSubscriptionData, RelayTopic},
    session::{
        JsonRpcErrorResponse, Session, SessionAckResponse, SessionSettleResponse, SignMethod,
    },
};

use super::{
    error::PairingClientError,
    types::{
        PairingPayload, PairingReceivedMessage, SessionLifecycleResponseMessage,
        SessionLifecycleResponsePayload, SessionPayload, SessionReceivedMessage,
        SessionSettleResponseMessage, SessionSettleResponsePayload, SessionSubscription,
    },
};

/// Converts one relay delivery record into a decrypted pairing message.
///
/// The relay only forwards an opaque string. Pairing-specific decoding starts
/// after topic routing has succeeded.
pub(super) fn decode_subscription_data(
    data: IrnSubscriptionData,
    sym_key: &PairingSymKey,
) -> Result<PairingReceivedMessage, PairingClientError> {
    let encoded_message_len = data.message.len();
    let message = PairingMessage::decode_relay_message(&data.message, sym_key)
        .map_err(|source| PairingClientError::PairingMessage { source })?;
    let payload = parse_pairing_payload(&message)?;

    Ok(PairingReceivedMessage {
        topic: data.topic,
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        message,
        payload,
    })
}

/// Converts one relay delivery record into a typed `wc_sessionSettle` response.
pub(super) fn decode_session_settle_response_data(
    data: IrnSubscriptionData,
    subscription: &SessionSubscription,
    expected_id: u64,
) -> Result<SessionSettleResponseMessage, PairingClientError> {
    let encoded_message_len = data.message.len();

    if data.topic != subscription.topic {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic.clone(),
            actual: data.topic,
        });
    }

    let envelope = Envelope::decode(&data.message, EnvelopeEncoding::Base64)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let plaintext = envelope
        .decrypt(&subscription.sym_key)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let json = serde_json::from_str::<serde_json::Value>(&plaintext)
        .map_err(|source| PairingClientError::SessionPayload { source })?;
    let payload = parse_session_settle_response_payload(json, expected_id)?;

    Ok(SessionSettleResponseMessage {
        topic: subscription.topic.clone(),
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        payload,
    })
}

/// Converts one relay delivery record into a lifecycle acknowledgement response.
pub(super) fn decode_session_lifecycle_response_data(
    data: IrnSubscriptionData,
    subscription: &SessionSubscription,
    expected_id: u64,
) -> Result<SessionLifecycleResponseMessage, PairingClientError> {
    let encoded_message_len = data.message.len();

    if data.topic != subscription.topic {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic.clone(),
            actual: data.topic,
        });
    }

    let envelope = Envelope::decode(&data.message, EnvelopeEncoding::Base64)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let plaintext = envelope
        .decrypt(&subscription.sym_key)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let json = serde_json::from_str::<serde_json::Value>(&plaintext)
        .map_err(|source| PairingClientError::SessionPayload { source })?;
    let payload = parse_session_lifecycle_response_payload(json, expected_id)?;

    Ok(SessionLifecycleResponseMessage {
        topic: subscription.topic.clone(),
        encoded_message_len,
        published_at: data.published_at,
        tag: data.tag,
        payload,
    })
}

/// Converts one relay delivery record into a typed session-topic message.
///
/// Session messages are encrypted with the symmetric key derived during
/// proposal approval. Topic and session-state checks happen before the payload
/// is exposed to higher layers.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2456-L2461>
///
/// > const { topic, payload, attestation, encryptedId, transportType } = args;
/// > const { id, params } = payload;
/// > await this.isValidRequest({ topic, ...params });
pub(super) fn decode_session_message_data(
    data: IrnSubscriptionData,
    subscription: &SessionSubscription,
    session: &Session,
    now_unix_seconds: u64,
) -> Result<SessionReceivedMessage, PairingClientError> {
    let message =
        decode_session_message_data_unchecked(data, subscription, session, now_unix_seconds)?;
    validate_session_message_payload(session, &message, now_unix_seconds)?;
    Ok(message)
}

/// Converts one relay delivery record into a session-topic message before
/// request permission checks.
///
/// This is used by the auto-reject path: it needs the JSON-RPC request ID to
/// respond with an error when the request is unauthorized or expired.
pub(super) fn decode_session_message_data_unchecked(
    data: IrnSubscriptionData,
    subscription: &SessionSubscription,
    session: &Session,
    now_unix_seconds: u64,
) -> Result<SessionReceivedMessage, PairingClientError> {
    let encoded_message_len = data.message.len();
    let topic = data.topic;
    let published_at = data.published_at;
    let tag = data.tag;

    validate_session_message_route(&topic, subscription, session, now_unix_seconds)?;

    let envelope = Envelope::decode(&data.message, EnvelopeEncoding::Base64)
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let plaintext = envelope
        .decrypt(subscription.sym_key())
        .map_err(|source| PairingClientError::SessionEnvelope { source })?;
    let plaintext_len = plaintext.len();
    let json = serde_json::from_str::<serde_json::Value>(&plaintext)
        .map_err(|source| PairingClientError::SessionPayload { source })?;
    let payload = parse_session_payload(json)?;

    Ok(SessionReceivedMessage {
        topic,
        encoded_message_len,
        plaintext_len,
        published_at,
        tag,
        payload,
    })
}

/// Applies session request validation to an already decoded session message.
pub(super) fn validate_session_message_payload(
    session: &Session,
    message: &SessionReceivedMessage,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    validate_session_payload(session, message.payload(), now_unix_seconds)
}

/// Checks routing and lifecycle state before decrypting a session message.
fn validate_session_message_route(
    message_topic: &RelayTopic,
    subscription: &SessionSubscription,
    session: &Session,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    if message_topic != subscription.topic() {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic().clone(),
            actual: message_topic.clone(),
        });
    }

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

/// Parses the classified decrypted JSON into the DTO used by that method.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2013-L2029>
///
/// > switch (reqMethod) {
/// > case "wc_sessionRequest":
/// > return await this.onSessionRequest({
fn parse_session_payload(json: serde_json::Value) -> Result<SessionPayload, PairingClientError> {
    let Some(method) = json.get("method").and_then(serde_json::Value::as_str) else {
        return Ok(SessionPayload::Missing);
    };

    match SignMethod::from_wire(method) {
        Some(SignMethod::SessionRequest) => serde_json::from_value(json)
            .map(|request| SessionPayload::SessionRequest(Box::new(request)))
            .map_err(|source| PairingClientError::SessionPayload { source }),
        Some(SignMethod::SessionUpdate) => serde_json::from_value(json)
            .map(SessionPayload::SessionUpdate)
            .map_err(|source| PairingClientError::SessionPayload { source }),
        Some(SignMethod::SessionExtend) => serde_json::from_value(json)
            .map(SessionPayload::SessionExtend)
            .map_err(|source| PairingClientError::SessionPayload { source }),
        Some(SignMethod::SessionPing) => serde_json::from_value(json)
            .map(SessionPayload::SessionPing)
            .map_err(|source| PairingClientError::SessionPayload { source }),
        Some(SignMethod::SessionDelete) => serde_json::from_value(json)
            .map(SessionPayload::SessionDelete)
            .map_err(|source| PairingClientError::SessionPayload { source }),
        Some(method) => Ok(SessionPayload::Sign(method)),
        None => Ok(SessionPayload::Unknown(method.to_owned())),
    }
}

/// Applies session-permission checks to parsed session requests.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionrequest>
///
/// > The client should immediately reject the request and respond an error if
/// > the target session permissions doesn't include the requested method or
/// > chain ID.
///
/// The maintained Sign Client performs the same chain and method checks when
/// receiving a session request.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3138-L3154>
///
/// > if (!isValidNamespacesChainId(namespaces, chainId)) {
/// > if (!isValidNamespacesRequest(namespaces, chainId, request.method)) {
fn validate_session_payload(
    session: &Session,
    payload: &SessionPayload,
    now_unix_seconds: u64,
) -> Result<(), PairingClientError> {
    let SessionPayload::SessionRequest(request) = payload else {
        return Ok(());
    };

    if let Some(expiry_timestamp) = request.params.request.expiry_timestamp
        && expiry_timestamp <= now_unix_seconds
    {
        return Err(PairingClientError::SessionRequestExpired {
            expiry_timestamp,
            now_unix_seconds,
        });
    }

    if !is_chain_authorized(&session.namespaces, &request.params.chain_id) {
        return Err(PairingClientError::SessionUnauthorizedChain {
            chain_id: request.params.chain_id.clone(),
        });
    }

    if !is_method_authorized(
        &session.namespaces,
        &request.params.chain_id,
        request.params.request.method.as_str(),
    ) {
        return Err(PairingClientError::SessionUnauthorizedMethod {
            chain_id: request.params.chain_id.clone(),
            method: request.params.request.method.clone(),
        });
    }

    Ok(())
}

/// Parses and correlates the JSON-RPC response to `wc_sessionSettle`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2288-L2299>
///
/// > const { id } = payload;
/// > if (isJsonRpcResult(payload)) {
/// > } else if (isJsonRpcError(payload)) {
fn parse_session_settle_response_payload(
    json: serde_json::Value,
    expected_id: u64,
) -> Result<SessionSettleResponsePayload, PairingClientError> {
    let actual_id = json
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PairingClientError::SessionResponseMissingId)?;

    if actual_id != expected_id {
        return Err(PairingClientError::SessionResponseIdMismatch {
            expected: expected_id,
            actual: actual_id,
        });
    }

    if json.get("result").is_some() {
        return serde_json::from_value::<SessionSettleResponse>(json)
            .map(SessionSettleResponsePayload::Success)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    if json.get("error").is_some() {
        return serde_json::from_value::<JsonRpcErrorResponse>(json)
            .map(SessionSettleResponsePayload::Error)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    Err(PairingClientError::SessionSettleUnsupportedPayload)
}

fn parse_session_lifecycle_response_payload(
    json: serde_json::Value,
    expected_id: u64,
) -> Result<SessionLifecycleResponsePayload, PairingClientError> {
    validate_response_id(&json, expected_id)?;

    if json.get("result").is_some() {
        return serde_json::from_value::<SessionAckResponse>(json)
            .map(SessionLifecycleResponsePayload::Success)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    if json.get("error").is_some() {
        return serde_json::from_value::<JsonRpcErrorResponse>(json)
            .map(SessionLifecycleResponsePayload::Error)
            .map_err(|source| PairingClientError::SessionPayload { source });
    }

    Err(PairingClientError::SessionLifecycleUnsupportedPayload)
}

fn validate_response_id(
    json: &serde_json::Value,
    expected_id: u64,
) -> Result<(), PairingClientError> {
    let actual_id = json
        .get("id")
        .and_then(serde_json::Value::as_u64)
        .ok_or(PairingClientError::SessionResponseMissingId)?;

    if actual_id != expected_id {
        return Err(PairingClientError::SessionResponseIdMismatch {
            expected: expected_id,
            actual: actual_id,
        });
    }

    Ok(())
}

/// Parses the classified decrypted JSON into the DTO used by that method.
fn parse_pairing_payload(message: &PairingMessage) -> Result<PairingPayload, PairingClientError> {
    match message.method() {
        PairingMessageMethod::Sign(SignMethod::SessionPropose) => parse_json_rpc(message)
            .map(|request| PairingPayload::SessionProposal(Box::new(request))),
        PairingMessageMethod::Sign(method) => Ok(PairingPayload::Sign(*method)),
        PairingMessageMethod::Pairing(PairingMethod::Ping) => {
            parse_json_rpc(message).map(PairingPayload::PairingPing)
        }
        PairingMessageMethod::Pairing(PairingMethod::Delete) => {
            parse_json_rpc(message).map(PairingPayload::PairingDelete)
        }
        PairingMessageMethod::Unknown(method) => Ok(PairingPayload::Unknown(method.clone())),
        PairingMessageMethod::Missing => Ok(PairingPayload::Missing),
    }
}

/// Clones the already parsed JSON into a method-specific DTO.
fn parse_json_rpc<T>(message: &PairingMessage) -> Result<T, PairingClientError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_value(message.json().clone())
        .map_err(|source| PairingClientError::PairingPayload { source })
}
