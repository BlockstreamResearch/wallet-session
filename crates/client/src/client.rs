use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;
use wallet_session_core::{
    crypto::MessageCipher,
    did::DidKey,
    frame::{RelayFrame, RelayFrameBody},
    message::Topic,
    payload::{ApprovePayload, Opaque, ProposalPayload},
};

use crate::{
    config::ClientConfig,
    crypto::{Aad, CipherError, ENVELOPE_VERSION, SealedPayload, WireEnvelope},
    error::{ClientError, Result},
    handshake::{EphemeralKeyPair, SessionKey, SessionTopic, decode_public_key},
    identity::{IdentityKey, unix_now},
    messages::{ClientMessage, RequestId},
    random,
    relay::{Inbox, Transport},
    reliability::{ClientEvent, NonceGuard, Reliability, requires_ack},
    session::{Role, Session, SessionState},
};

/// Default session lifetime.
const SESSION_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum accepted clock skew between envelope `ts` and local time.
const MAX_TS_SKEW_SECS: u64 = 300;

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
    transport: Transport,
    session: Session,
    cipher: C,
    handshake: Handshake,
    reliability: Reliability,
    events: mpsc::UnboundedReceiver<ClientEvent>,
    did: DidKey,
    nonce_guard: NonceGuard,
    saw_disconnect: bool,
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
        let did = identity.did();
        let transport = Transport::connect(config.clone(), identity, role, topic.clone());
        let (reliability, events) = Reliability::spawn(
            transport.outbound(),
            config.ack_base_delay,
            config.ack_max_attempts,
            config.seen_ttl,
        );

        Ok(Self {
            transport,
            session: Session::new(topic, role),
            cipher,
            handshake: Handshake::Idle,
            reliability,
            events,
            did,
            nonce_guard: NonceGuard::new(),
            saw_disconnect: false,
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn is_ready(&self) -> bool {
        self.session.state != SessionState::Idle
    }

    /// Await the next relay frame, folding in transport lifecycle events.
    async fn next_frame(&mut self) -> Result<RelayFrame> {
        loop {
            match self.transport.recv().await {
                Some(Inbox::Frame(frame)) => return Ok(frame),
                Some(Inbox::Connected) => {
                    self.reliability.set_connected(true);
                    if self.saw_disconnect {
                        self.reliability.emit(ClientEvent::Reconnected);
                        self.saw_disconnect = false;
                    }
                }
                Some(Inbox::Disconnected) => {
                    self.reliability.set_connected(false);
                    if !self.saw_disconnect {
                        self.reliability.emit(ClientEvent::Reconnecting);
                        self.saw_disconnect = true;
                    }
                }
                Some(Inbox::Closed) | None => return Err(ClientError::Closed),
            }
        }
    }

    pub async fn wait_session_ready(&mut self) -> Result<()> {
        while !self.is_ready() {
            let frame = self.next_frame().await?;
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

    /// Seal and send a message, returning its envelope id.
    pub async fn send(&mut self, message: &ClientMessage) -> Result<String> {
        let id = random::id()?;
        self.send_with_id(id.clone(), message).await?;
        Ok(id)
    }

    /// Seal and send a message with a caller-chosen envelope id.
    async fn send_with_id(&mut self, id: String, message: &ClientMessage) -> Result<()> {
        let topic = self.transport.topic().clone();
        let kind = message.message_type();
        let aad = Aad::new(&id, kind, &topic, &self.did).to_bytes();
        let sealed = self.cipher.seal(&aad, &message.to_bytes()?)?;
        let wire = WireEnvelope {
            version: ENVELOPE_VERSION,
            kind,
            from: self.did.clone(),
            ts: unix_now(),
            nonce: sealed.nonce,
            data: sealed.data,
        };

        let frame = RelayFrame {
            v: 1,
            id,
            topic,
            body: RelayFrameBody::Message {
                payload: serde_json::to_string(&wire)?,
            },
        };
        self.reliability.dispatch(frame, requires_ack(kind))
    }

    pub async fn recv(&mut self) -> Result<ClientMessage> {
        loop {
            let frame = self.next_frame().await?;
            let RelayFrame { id, topic, body, .. } = frame;

            match body {
                RelayFrameBody::Message { payload } => {
                    if topic != self.session.topic {
                        log::warn!("dropping frame for unsubscribed topic {topic}");
                        continue;
                    }
                    if self.reliability.is_duplicate(&id) {
                        log::debug!("dropping duplicate frame {id}");
                        continue;
                    }

                    let wire: WireEnvelope = serde_json::from_str(&payload)?;

                    if wire.version != ENVELOPE_VERSION {
                        log::warn!("dropping frame with unsupported version {}", wire.version);
                        continue;
                    }
                    let now = unix_now();
                    if now.abs_diff(wire.ts) > MAX_TS_SKEW_SECS {
                        log::warn!("dropping frame with stale timestamp ts={}", wire.ts);
                        continue;
                    }

                    let aad = Aad::new(&id, wire.kind, &topic, &wire.from).to_bytes();
                    let sealed = SealedPayload {
                        nonce: wire.nonce.clone(),
                        data: wire.data.clone(),
                    };
                    let bytes = self.cipher.open(&aad, &sealed)?;

                    if self.nonce_guard.is_reused(wire.nonce.as_bytes()) {
                        log::warn!("dropping frame with reused nonce {id}");
                        continue;
                    }

                    let message = ClientMessage::from_bytes(&bytes)?;

                    // acks are consumed by reliability
                    if let ClientMessage::Ack { ack_id } = &message {
                        self.reliability.mark_delivered(ack_id);
                        continue;
                    }

                    self.observe(&message)?;

                    if requires_ack(message.message_type()) {
                        self.send_ack(&id).await?;
                    }

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

    /// Acknowledge a received envelope by id.
    async fn send_ack(&mut self, ack_id: &str) -> Result<()> {
        self.send(&ClientMessage::Ack {
            ack_id: ack_id.to_owned(),
        })
        .await?;
        Ok(())
    }

    /// Non-blocking read of the next reliability event, if any.
    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.try_recv().ok()
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
        self.nonce_guard.clear();
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
        self.send_with_id(
            request_id.clone(),
            &ClientMessage::Request {
                request_id: request_id.clone(),
                request,
            },
        )
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
        .await?;
        Ok(())
    }

    /// Acknowledge a received message.
    pub async fn ack(&mut self, ack_id: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Ack {
            ack_id: ack_id.into(),
        })
        .await?;
        Ok(())
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
