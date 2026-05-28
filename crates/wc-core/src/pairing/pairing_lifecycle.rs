use wc_protocol::{dto::pairing::PairingJsonRpcResponse, relay::IrnPublish};

use super::{
    PAIRING_PING_RESPONSE_TAG, PAIRING_PING_RESPONSE_TTL_SECONDS,
    error::PairingClientError,
    publish::encrypted_json_publish,
    types::{PairingPayload, PairingReceivedMessage, PairingSubscription},
};

/// Builds an encrypted `wc_pairingPing` acknowledgement publish.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/pairing.ts#L377-L385>
///
/// > await this.sendResult<"wc_pairingPing">(id, topic, true);
/// > this.events.emit(PAIRING_EVENTS.ping, { id, topic });
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/pairing.ts#L45-L49>
///
/// > interface Results {
/// > wc_pairingPing: true;
pub(super) fn pairing_ping_response_publish(
    subscription: &PairingSubscription,
    message: &PairingReceivedMessage,
) -> Result<IrnPublish, PairingClientError> {
    ensure_pairing_topic(subscription, message)?;
    let PairingPayload::PairingPing(request) = message.payload() else {
        return Err(PairingClientError::PairingResponseTargetNotPing);
    };
    let response = PairingJsonRpcResponse::new(request.id, true);

    encrypted_json_publish(
        subscription.topic().clone(),
        subscription.sym_key(),
        &response,
        PAIRING_PING_RESPONSE_TTL_SECONDS,
        PAIRING_PING_RESPONSE_TAG,
    )
}

fn ensure_pairing_topic(
    subscription: &PairingSubscription,
    message: &PairingReceivedMessage,
) -> Result<(), PairingClientError> {
    if message.topic() != subscription.topic() {
        return Err(PairingClientError::UnexpectedTopic {
            expected: subscription.topic().clone(),
            actual: message.topic().clone(),
        });
    }

    Ok(())
}
