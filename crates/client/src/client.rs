use std::time::Duration;

use serde_json::Value;
use wallet_session_core::{
    crypto::MessageCipher,
    frame::{RelayFrame, RelayFrameBody},
    message::Topic,
    payload::{ApprovePayload, Opaque, ProposalPayload},
};

use crate::{
    config::ClientConfig,
    crypto::{Aad, CipherError, SealedPayload, WireEnvelope},
    error::{ClientError, Result},
    handshake::{EphemeralKeyPair, SessionKey, SessionTopic, decode_public_key},
    identity::{IdentityKey, unix_now},
    messages::{ClientMessage, RequestId},
    random,
    relay::RelayClient,
    session::{Role, Session, SessionState},
};

/// Default session lifetime.
const SESSION_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// Local side of the session handshake.
enum Handshake {
    /// No handshake activity yet.
    Idle,

    /// We sent a proposal and hold its ephemeral keypair.
    Proposed { keypair: EphemeralKeyPair },

    /// We received a proposal and know the peer's ephemeral public key.
    PeerProposed { peer_public: [u8; 32] },

    /// Session key established; traffic uses the session key.
    Established,
}

pub struct Client<C> {
    transport: RelayClient,
    session: Session,
    cipher: C,
    handshake: Handshake,
}

impl<C> Client<C>
where
    C: MessageCipher<Sealed = SealedPayload, Error = CipherError>,
{
    pub async fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
        cipher: C,
    ) -> Result<Self> {
        let transport = RelayClient::connect(&config, &identity, role, &topic).await?;
        Ok(Self {
            transport,
            session: Session::new(topic, role),
            cipher,
            handshake: Handshake::Idle,
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn is_ready(&self) -> bool {
        self.session.state != SessionState::Idle
    }

    pub async fn wait_session_ready(&mut self) -> Result<()> {
        while !self.is_ready() {
            let frame = self.transport.recv().await?;
            match frame.body {
                RelayFrameBody::SessionReady => {
                    self.session.state = SessionState::Active;
                }
                RelayFrameBody::PeerDisconnected => {
                    self.session.state = SessionState::Disconnected;
                    return Err(ClientError::PeerDisconnected);
                }
                RelayFrameBody::Message { payload } => {
                    log::debug!("dropping message received before session_ready: {payload}");
                }
            }
        }
        Ok(())
    }

    pub async fn send(&mut self, message: &ClientMessage) -> Result<()> {
        let id = random::id()?;
        let topic = self.transport.topic().clone();
        let kind = message.message_type();
        let aad = Aad::new(&id, kind, &topic).to_bytes();
        let sealed = self.cipher.seal(&aad, &message.to_bytes()?)?;
        let wire = WireEnvelope::new(kind, sealed);

        let frame = RelayFrame {
            v: 1,
            id,
            topic,
            body: RelayFrameBody::Message {
                payload: serde_json::to_string(&wire)?,
            },
        };
        self.transport.send(frame).await
    }

    pub async fn recv(&mut self) -> Result<ClientMessage> {
        loop {
            let frame = self.transport.recv().await?;
            match frame.body {
                RelayFrameBody::Message { payload } => {
                    let wire: WireEnvelope = serde_json::from_str(&payload)?;
                    let (kind, sealed) = wire.into_parts();
                    let aad = Aad::new(&frame.id, kind, &frame.topic).to_bytes();
                    let bytes = self.cipher.open(&aad, &sealed)?;
                    let message = ClientMessage::from_bytes(&bytes)?;
                    self.observe(&message)?;
                    return Ok(message);
                }
                RelayFrameBody::PeerDisconnected => {
                    self.session.state = SessionState::Disconnected;
                    return Err(ClientError::PeerDisconnected);
                }
                RelayFrameBody::SessionReady => {}
            }
        }
    }

    /// Update handshake state from an inbound message.
    fn observe(&mut self, message: &ClientMessage) -> Result<()> {
        match message {
            ClientMessage::Proposal(proposal) => {
                let peer_public = decode_public_key(&proposal.ephemeral_public_key)?;
                self.handshake = Handshake::PeerProposed { peer_public };
            }
            ClientMessage::Approve(approve) => {
                let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
                let Handshake::Proposed { keypair } =
                    std::mem::replace(&mut self.handshake, Handshake::Idle)
                else {
                    return Err(ClientError::UnexpectedHandshake);
                };
                let (key, topic) = keypair.derive(&peer_public)?;
                self.rekey(key, topic);
            }
            _ => {}
        }
        Ok(())
    }

    /// Replace the cipher with one keyed by the derived session key.
    fn rekey(&mut self, key: SessionKey, _topic: SessionTopic) {
        self.cipher.rekey(key.as_bytes());
        self.handshake = Handshake::Established;
        self.session.state = SessionState::Active;
    }

    /// Send a `proposal` carrying ephemeral public key.
    pub async fn propose(&mut self, proposal: Value) -> Result<()> {
        let keypair = EphemeralKeyPair::generate();
        let payload = ProposalPayload {
            ephemeral_public_key: keypair.public_key_encoded(),
            session_expiry: session_expiry(),
            proposal: Opaque(serde_json::to_vec(&proposal)?),
        };
        self.send(&ClientMessage::Proposal(payload)).await?;
        self.handshake = Handshake::Proposed { keypair };
        self.session.state = SessionState::ProposalSent;
        Ok(())
    }

    /// Send an `approve` carrying ephemeral public key and switch to the session key.
    pub async fn approve(&mut self, approval: Value) -> Result<()> {
        let Handshake::PeerProposed { peer_public } = self.handshake else {
            return Err(ClientError::UnexpectedHandshake);
        };
        let keypair = EphemeralKeyPair::generate();
        let payload = ApprovePayload {
            ephemeral_public_key: keypair.public_key_encoded(),
            approval: Opaque(serde_json::to_vec(&approval)?),
        };
        let (key, topic) = keypair.derive(&peer_public)?;
        self.send(&ClientMessage::Approve(payload)).await?;
        self.rekey(key, topic);
        Ok(())
    }

    /// Send a `reject` and move to `Rejected`.
    pub async fn reject(&mut self, code: u32, message: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Reject {
            code,
            message: message.into(),
        })
        .await?;
        self.session.state = SessionState::Rejected;
        Ok(())
    }

    /// Send a `request` and return its correlation id.
    pub async fn request(&mut self, request: Value) -> Result<RequestId> {
        let request_id = random::id()?;
        self.send(&ClientMessage::Request {
            request_id: request_id.clone(),
            request,
        })
        .await?;
        Ok(request_id)
    }

    /// Send a `response` (or error) for a request.
    pub async fn respond(
        &mut self,
        request_id: impl Into<String>,
        response: Option<Value>,
        error: Option<Value>,
    ) -> Result<()> {
        self.send(&ClientMessage::Response {
            request_id: request_id.into(),
            response,
            error,
        })
        .await
    }

    /// Acknowledge a received message.
    pub async fn ack(&mut self, ack_id: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Ack {
            ack_id: ack_id.into(),
        })
        .await
    }

    /// Gracefully disconnect.
    pub async fn disconnect(&mut self, reason: impl Into<String>, code: u32) -> Result<()> {
        self.send(&ClientMessage::Disconnect {
            reason: reason.into(),
            code,
            message: String::new(),
        })
        .await?;
        self.session.state = SessionState::Disconnected;
        Ok(())
    }
}

/// Session expiry timestamp for a fresh proposal.
fn session_expiry() -> u64 {
    unix_now().saturating_add(SESSION_EXPIRY.as_secs())
}
