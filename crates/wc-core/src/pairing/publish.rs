use wc_protocol::{
    envelope::{Envelope, EnvelopeEncoding},
    key::X25519PublicKey,
    pairing::PairingSymKey,
    relay::{IrnPublish, RelayTopic},
};

use super::error::PairingClientError;

/// Serializes a Sign JSON-RPC payload and encrypts it as a relay publish message.
///
/// This is shared by pairing-topic and session-topic replies because the relay
/// sees the same opaque `message` string in both cases; only topic, symmetric
/// key, TTL, and tag differ.
///
/// <https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc#publish>
///
/// > Used when a client publishes a message to a server.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods#wc_sessionrequest>
///
/// > Response
/// > // Success result
/// > any
pub(super) fn encrypted_json_publish<T>(
    topic: RelayTopic,
    sym_key: &PairingSymKey,
    payload: &T,
    ttl: u64,
    tag: u64,
) -> Result<IrnPublish, PairingClientError>
where
    T: serde::Serialize,
{
    let plaintext = serde_json::to_string(payload)
        .map_err(|source| PairingClientError::OutboundPayload { source })?;
    let envelope = Envelope::encrypt_type_0(&plaintext, sym_key)
        .map_err(|source| PairingClientError::Envelope { source })?;
    let message = envelope.encode(EnvelopeEncoding::Base64);

    Ok(IrnPublish::new(topic, message, ttl, tag))
}

/// Serializes a Sign JSON-RPC payload and encrypts it as a type-1 relay message.
///
/// `wc_sessionAuthenticate` responses use type-1 envelopes because the response
/// symmetric key is derived from requester/responder X25519 keys, and the
/// responder public key has to travel with the envelope.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/crypto.ts#L134-L141>
///
/// > senderPublicKey: encodeOpts.senderPublicKey,
/// > type: encodeOpts.type,
pub(super) fn encrypted_json_publish_type_1<T>(
    topic: RelayTopic,
    sym_key: &PairingSymKey,
    sender_public_key: &X25519PublicKey,
    payload: &T,
    ttl: u64,
    tag: u64,
) -> Result<IrnPublish, PairingClientError>
where
    T: serde::Serialize,
{
    let plaintext = serde_json::to_string(payload)
        .map_err(|source| PairingClientError::OutboundPayload { source })?;
    let envelope = Envelope::encrypt_type_1(&plaintext, sym_key, sender_public_key)
        .map_err(|source| PairingClientError::Envelope { source })?;
    let message = envelope.encode(EnvelopeEncoding::Base64);

    Ok(IrnPublish::new(topic, message, ttl, tag))
}
