use std::{collections::VecDeque, time::Duration};

use serde_json::Value;
use tokio::sync::mpsc;
use wallet_session_core::{
    crypto::MessageCipher,
    did::DidKey,
    frame::{RelayFrame, RelayFrameBody},
    message::{Message, MessageId, MessageType, Topic},
    payload::{
        AckPayload, ApprovePayload, DisconnectPayload, Opaque, ProposalPayload, RejectPayload,
        RequestPayload, ResponsePayload,
    },
};

use crate::{
    config::ClientConfig,
    crypto::{Aad, CipherError, SealedPayload},
    error::{ClientError, Result},
    handshake::{EphemeralKeyPair, SessionKey, SessionTopic, decode_public_key},
    identity::{IdentityKey, unix_now},
    messages::{ClientMessage, RequestId},
    random,
    relay::{Inbox, Transport},
    reliability::{ClientEvent, Reliability, requires_ack},
    replay::{Observation, ReplayMemory},
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

    /// Session key established; traffic uses the session topic and key.
    Established,
}

/// One relay connection, its outbound reliability and its inbound replay
/// memory.
struct Link<C> {
    topic: Topic,
    _transport: Transport,
    reliability: Reliability,
    events: mpsc::UnboundedReceiver<ClientEvent>,
    cipher: C,
    replay: ReplayMemory,
    ready: bool,
    saw_disconnect: bool,
}

impl<C> Link<C>
where
    C: MessageCipher<Sealed = SealedPayload, Error = CipherError>,
{
    fn new(
        config: &ClientConfig,
        identity: &IdentityKey,
        role: Role,
        topic: Topic,
        cipher: C,
        inbox: &mpsc::UnboundedSender<Inbox>,
    ) -> Self {
        let transport = Transport::connect(
            config.clone(),
            identity.clone(),
            role,
            topic.clone(),
            inbox.clone(),
        );
        let (reliability, events) = Reliability::spawn(
            transport.outbound(),
            config.ack_base_delay,
            config.ack_max_attempts,
        );

        Self {
            topic,
            _transport: transport,
            reliability,
            events,
            cipher,
            replay: ReplayMemory::new(Duration::from_secs(MAX_TS_SKEW_SECS)),
            ready: false,
            saw_disconnect: false,
        }
    }
}

pub struct Client<C> {
    config: ClientConfig,
    identity: IdentityKey,
    inbox: mpsc::UnboundedReceiver<Inbox>,
    inbox_tx: mpsc::UnboundedSender<Inbox>,
    pairing: Option<Link<C>>,
    session_link: Option<Link<C>>,
    session: Session,
    handshake: Handshake,
    did: DidKey,
    pending: VecDeque<ClientMessage>,
    pending_events: VecDeque<ClientEvent>,
    pairing_approval: Option<MessageId>,
}

impl<C> Client<C>
where
    C: MessageCipher<Sealed = SealedPayload, Error = CipherError> + Clone,
{
    /// Connect to the relay for the pairing topic.
    ///
    /// The cipher must be cloneable: the pairing topic keeps its cipher while
    /// the derived session topic gets a rekeyed copy.
    pub async fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
        cipher: C,
    ) -> Result<Self> {
        let did = identity.did();
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let pairing = Link::new(&config, &identity, role, topic.clone(), cipher, &inbox_tx);
        let session = Session::new(topic, role);

        Ok(Self {
            config,
            identity,
            inbox,
            inbox_tx,
            pairing: Some(pairing),
            session_link: None,
            session,
            handshake: Handshake::Idle,
            did,
            pending: VecDeque::new(),
            pending_events: VecDeque::new(),
            pairing_approval: None,
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Whether the relay session on the active topic is ready.
    pub fn is_ready(&self) -> bool {
        self.active_link().ready
    }

    fn active_link(&self) -> &Link<C> {
        self.session_link
            .as_ref()
            .or(self.pairing.as_ref())
            .expect("the client always has a pairing or session link")
    }

    fn active_topic(&self) -> &Topic {
        &self.session.topic
    }

    fn link_mut(&mut self, topic: &Topic) -> Option<&mut Link<C>> {
        if self
            .pairing
            .as_ref()
            .is_some_and(|link| link.topic == *topic)
        {
            return self.pairing.as_mut();
        }
        self.session_link
            .as_mut()
            .filter(|link| link.topic == *topic)
    }

    /// Await the next relay frame, folding in transport lifecycle events.
    async fn next_frame(&mut self) -> Result<RelayFrame> {
        loop {
            match self.inbox.recv().await {
                Some(Inbox::Frame(frame)) => {
                    if matches!(&frame.body, RelayFrameBody::SessionReady)
                        && let Some(link) = self.link_mut(&frame.topic)
                    {
                        link.ready = true;
                    }
                    return Ok(frame);
                }
                Some(Inbox::Connected(topic)) => self.set_connected(&topic, true),
                Some(Inbox::Disconnected(topic)) => self.set_connected(&topic, false),
                Some(Inbox::Closed(topic)) => {
                    self.set_connected(&topic, false);
                    if topic == *self.active_topic() {
                        return Err(ClientError::Closed);
                    }
                    log::debug!("relay link closed for inactive topic {topic}");
                }
                Some(Inbox::Retire(topic)) => {
                    if self
                        .pairing
                        .as_ref()
                        .is_some_and(|link| link.topic == topic)
                    {
                        log::debug!("retiring pairing link {}", topic.log_tag());
                        self.retire_pairing();
                    }
                }
                None => return Err(ClientError::Closed),
            }
        }
    }

    fn set_connected(&mut self, topic: &Topic, connected: bool) {
        let active = *topic == *self.active_topic();
        let Some(link) = self.link_mut(topic) else {
            return;
        };
        link.reliability.set_connected(connected);
        if connected {
            if link.saw_disconnect {
                link.saw_disconnect = false;
                if active {
                    link.reliability.emit(ClientEvent::Reconnected);
                }
            }
        } else {
            link.ready = false;
            if !link.saw_disconnect {
                link.saw_disconnect = true;
                if active {
                    link.reliability.emit(ClientEvent::Reconnecting);
                }
            }
        }
    }

    /// Wait until the relay reports the active topic ready.
    ///
    /// Before the handshake this waits on the pairing topic. After the
    /// handshake it waits on the derived session topic. Messages received
    /// while waiting are queued for the next [`Client::recv`].
    pub async fn wait_session_ready(&mut self) -> Result<()> {
        while !self.is_ready() {
            let frame = self.next_frame().await?;
            match frame.body {
                RelayFrameBody::SessionReady => {}
                RelayFrameBody::PeerDisconnected => {
                    if frame.topic == *self.active_topic() {
                        self.session.state = SessionState::Disconnected;
                        return Err(ClientError::PeerDisconnected);
                    }
                }
                RelayFrameBody::Message { .. } => {
                    // Consume acknowledgements and retransmissions that
                    // arrive while waiting. Application messages are queued
                    // for the next `recv`.
                    if let Some(message) = self.handle_message_frame(frame).await? {
                        self.pending.push_back(message);
                    }
                }
            }
        }
        if matches!(self.handshake, Handshake::Established) {
            self.session.state = SessionState::Active;
        }
        Ok(())
    }

    /// Seal and send a message, returning its envelope id.
    ///
    /// Handshake messages use [`Client::propose`], [`Client::approve`] and
    /// [`Client::reject`] and stay on the pairing topic. Application messages
    /// are refused until the handshake is established, then use the derived
    /// session topic.
    pub async fn send(&mut self, message: &ClientMessage) -> Result<MessageId> {
        let topic = match message {
            ClientMessage::Proposal(_) | ClientMessage::Approve(_) | ClientMessage::Reject(_) => {
                if matches!(self.handshake, Handshake::Established) {
                    return Err(ClientError::UnexpectedHandshake);
                }
                self.session.pairing_topic.clone()
            }
            _ => {
                self.ensure_session_active()?;
                self.active_topic().clone()
            }
        };
        self.send_on(&topic, message).await
    }

    /// Whether application messages may be sent.
    fn ensure_session_active(&self) -> Result<()> {
        if matches!(self.handshake, Handshake::Established) {
            Ok(())
        } else {
            Err(ClientError::SessionNotActive)
        }
    }

    async fn send_on(&mut self, topic: &Topic, message: &ClientMessage) -> Result<MessageId> {
        let id = random::id()?;
        self.send_with_id_on(topic, id.clone(), message).await?;
        Ok(id)
    }

    /// Seal and send a message with a caller-chosen envelope id.
    async fn send_with_id_on(
        &mut self,
        topic: &Topic,
        id: MessageId,
        message: &ClientMessage,
    ) -> Result<()> {
        let did = self.did.clone();
        let role = self.session.role;
        let kind = message.message_type();
        let plaintext = message.to_bytes()?;
        let ts = unix_now();
        let aad = Aad::new(&id, kind, topic, &did, ts, role).to_bytes();

        let link = self.link_mut(topic).ok_or(ClientError::Closed)?;
        let sealed = link.cipher.seal(&aad, &plaintext)?;
        let wire = Message::new(kind, did, ts, sealed.nonce, sealed.data);
        let frame = RelayFrame {
            v: 1,
            id,
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: serde_json::to_string(&wire)?,
            },
        };
        link.reliability.dispatch(frame, requires_ack(kind))
    }

    pub async fn recv(&mut self) -> Result<ClientMessage> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }

        loop {
            let frame = self.next_frame().await?;
            match frame.body {
                RelayFrameBody::Message { .. } => {
                    if let Some(message) = self.handle_message_frame(frame).await? {
                        return Ok(message);
                    }
                }
                RelayFrameBody::SessionReady => {}
                RelayFrameBody::PeerDisconnected => {
                    if frame.topic == *self.active_topic() {
                        self.session.state = SessionState::Disconnected;
                        return Err(ClientError::PeerDisconnected);
                    }
                }
            }
        }
    }

    /// Process one `message` frame. Returns the message to deliver, or `None`
    /// for acknowledgements, retransmissions and envelopes for inactive
    /// handshake state.
    async fn handle_message_frame(&mut self, frame: RelayFrame) -> Result<Option<ClientMessage>> {
        let RelayFrame {
            id, topic, body, ..
        } = frame;
        let RelayFrameBody::Message { payload } = body else {
            return Ok(None);
        };

        if self.link_mut(&topic).is_none() {
            log::warn!("dropping frame for unknown topic {topic}");
            return Ok(None);
        }

        let wire: Message = serde_json::from_str(&payload)?;

        if wire.from == self.did {
            log::warn!("dropping frame from own identity {}", wire.from);
            return Ok(None);
        }
        if let Some(counterpart) = &self.session.peer_did {
            if wire.from != *counterpart {
                log::warn!(
                    "dropping frame from {}; established counterpart is {}",
                    wire.from,
                    counterpart
                );
                return Ok(None);
            }
        } else if topic != self.session.pairing_topic {
            log::warn!("dropping session-topic frame before the counterpart is established");
            return Ok(None);
        }

        if wire.version != Message::VERSION {
            log::warn!("dropping frame with unsupported version {}", wire.version);
            return Ok(None);
        }
        let now = unix_now();
        if now.abs_diff(wire.ts) > MAX_TS_SKEW_SECS {
            log::warn!("dropping frame with stale timestamp ts={}", wire.ts);
            return Ok(None);
        }
        let stale = self
            .link_mut(&topic)
            .expect("topic was checked")
            .replay
            .is_stale(wire.ts);
        if stale {
            log::warn!("dropping frame with discarded timestamp ts={}", wire.ts);
            return Ok(None);
        }

        let role = self.session.role;
        let aad = Aad::new(
            &id,
            wire.kind,
            &topic,
            &wire.from,
            wire.ts,
            role.counterpart(),
        )
        .to_bytes();
        let sealed = SealedPayload {
            nonce: wire.nonce.clone(),
            data: wire.data.clone(),
        };
        let bytes = self
            .link_mut(&topic)
            .expect("topic was checked")
            .cipher
            .open(&aad, &sealed)?;

        // The pairing key is for the handshake only. Application kinds on the
        // pairing topic are dropped even after the session is established, so
        // a leaked pairing key cannot bypass the session key. Conversely, the
        // session topic carries application traffic only.
        let allowed = if topic == self.session.pairing_topic {
            wire.kind.is_handshake() || wire.kind == MessageType::Ack
        } else {
            wire.kind.is_application()
        };
        if !allowed {
            log::warn!(
                "dropping {} on topic {}",
                wire.kind.as_str(),
                topic.log_tag()
            );
            return Ok(None);
        }

        // The counterpart is the sender of the first envelope that passes the
        // version, topic, identity, timestamp and authentication checks on the
        // pairing topic. It stays the counterpart for the session topic and
        // across reconnects.
        if topic == self.session.pairing_topic && self.session.peer_did.is_none() {
            self.session.peer_did = Some(wire.from.clone());
            log::debug!("established counterpart {}", wire.from);
        }

        let observation = self
            .link_mut(&topic)
            .expect("topic was checked")
            .replay
            .classify(&id, &wire, now);
        match observation {
            Observation::Retransmission => {
                if requires_ack(wire.kind) {
                    self.send_ack(&id, &topic).await?;
                }
                log::debug!("re-acknowledged retransmission {id}");
                return Ok(None);
            }
            Observation::Conflict => {
                return Err(ClientError::ProtocolViolation(
                    "envelope reuses a frame id or nonce with different content",
                ));
            }
            Observation::New => {}
        }

        let message = ClientMessage::from_bytes(&bytes)?;
        if message.message_type() != wire.kind {
            log::warn!(
                "dropping envelope: plaintext type does not match kind {}",
                wire.kind.as_str()
            );
            return Ok(None);
        }

        // acks are consumed by reliability
        if let ClientMessage::Ack(ack) = &message {
            let ack_id = ack.ack_id.clone();
            let retires_pairing = topic == self.session.pairing_topic
                && self.pairing_approval.as_ref() == Some(&ack_id);
            let link = self.link_mut(&topic).expect("topic was checked");
            link.replay.record(&id, &wire);
            link.reliability.mark_delivered(&ack_id);
            if retires_pairing {
                self.retire_pairing();
            }
            return Ok(None);
        }

        // Once established, the pairing key may no longer create new handshake
        // state. Retransmissions of the handshake were re-acked above.
        if matches!(self.handshake, Handshake::Established)
            && matches!(
                &message,
                ClientMessage::Proposal(_) | ClientMessage::Approve(_) | ClientMessage::Reject(_)
            )
        {
            log::warn!("dropping handshake message after establishment");
            return Ok(None);
        }

        // An `approve` establishes the session while `observe` runs. Record it
        // before that so the pairing replay memory keeps the envelope.
        let rekeys = matches!(&message, ClientMessage::Approve(_));
        if rekeys {
            let link = self.link_mut(&topic).expect("topic was checked");
            link.replay.record(&id, &wire);
        }

        if topic == self.session.pairing_topic
            && let Err(error) = self.observe(&message)
        {
            if let Some(link) = self.link_mut(&topic) {
                link.replay.forget(&id);
            }
            return Err(error);
        }

        if requires_ack(message.message_type()) {
            self.send_ack(&id, &topic).await?;
        }

        if !rekeys {
            let link = self.link_mut(&topic).expect("topic was checked");
            link.replay.record(&id, &wire);
        }

        Ok(Some(message))
    }

    /// Acknowledge a received envelope by id, on the topic it arrived on.
    async fn send_ack(&mut self, ack_id: &MessageId, topic: &Topic) -> Result<()> {
        self.send_on(
            topic,
            &ClientMessage::Ack(AckPayload {
                ack_id: ack_id.clone(),
            }),
        )
        .await?;
        Ok(())
    }

    /// Non-blocking read of the next reliability event, if any.
    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }
        if let Some(link) = self.session_link.as_mut()
            && let Ok(event) = link.events.try_recv()
        {
            return Some(event);
        }

        let event = self.pairing.as_mut()?.events.try_recv().ok()?;
        let approval_failed = matches!(
            &event,
            ClientEvent::Failed { id, .. } if self.pairing_approval.as_ref() == Some(id)
        );
        if approval_failed {
            self.pending_events.push_back(event);
            self.retire_pairing();
            return self.pending_events.pop_front();
        }
        Some(event)
    }

    /// Drop the pairing connection once the handshake no longer needs it.
    ///
    /// Events already queued by the link are kept for [`Client::poll_event`].
    fn retire_pairing(&mut self) {
        let Some(mut link) = self.pairing.take() else {
            return;
        };
        log::debug!("retiring pairing link {}", link.topic.log_tag());
        while let Ok(event) = link.events.try_recv() {
            self.pending_events.push_back(event);
        }
    }

    /// Update handshake state from an inbound pairing message.
    fn observe(&mut self, message: &ClientMessage) -> Result<()> {
        match message {
            ClientMessage::Proposal(proposal) => {
                if !matches!(self.handshake, Handshake::Idle) {
                    return Err(ClientError::UnexpectedHandshake);
                }
                let peer_public = decode_public_key(&proposal.ephemeral_public_key)?;
                self.handshake = Handshake::PeerProposed { peer_public };
                self.session.state = SessionState::ProposalReceived;
            }
            ClientMessage::Approve(approve) => {
                let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
                let Handshake::Proposed { keypair } =
                    std::mem::replace(&mut self.handshake, Handshake::Idle)
                else {
                    return Err(ClientError::UnexpectedHandshake);
                };
                let (key, topic) = keypair.derive(&peer_public)?;
                self.establish_session(key, topic)?;
            }
            ClientMessage::Reject(_) => {
                self.session.state = SessionState::Rejected;
            }
            _ => {}
        }
        Ok(())
    }

    /// Start the session-topic connection and keep the pairing link alive
    /// until its handshake acknowledgements have had their retry window.
    fn establish_session(&mut self, key: SessionKey, topic: SessionTopic) -> Result<()> {
        if self.session_link.is_some() {
            return Err(ClientError::UnexpectedHandshake);
        }

        let session_topic = topic.as_topic().clone();
        let mut cipher = self
            .pairing
            .as_ref()
            .ok_or(ClientError::Closed)?
            .cipher
            .clone();
        cipher.rekey(key.as_bytes());
        let link = Link::new(
            &self.config,
            &self.identity,
            self.session.role,
            session_topic.clone(),
            cipher,
            &self.inbox_tx,
        );

        self.session_link = Some(link);
        self.session.topic = session_topic;
        self.handshake = Handshake::Established;
        self.session.state = SessionState::Active;
        self.schedule_pairing_retirement();
        Ok(())
    }

    /// Retire the pairing connection after the handshake ack retry window.
    fn schedule_pairing_retirement(&self) {
        let window = self.pairing_retirement_window();
        let inbox = self.inbox_tx.clone();
        let topic = self.session.pairing_topic.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            let _ = inbox.send(Inbox::Retire(topic));
        });
    }

    /// Upper bound on how long handshake retransmissions can still arrive.
    fn pairing_retirement_window(&self) -> Duration {
        let attempts = self.config.ack_max_attempts.min(31) as u32;
        let factor = 2u32.saturating_pow(attempts.saturating_add(1));
        self.config
            .ack_base_delay
            .saturating_mul(factor.saturating_sub(1))
            .saturating_add(Duration::from_secs(1))
            .max(Duration::from_secs(1))
    }

    /// Send a `proposal` carrying ephemeral public key.
    pub async fn propose(&mut self, proposal: Value) -> Result<()> {
        if !matches!(self.handshake, Handshake::Idle) {
            return Err(ClientError::UnexpectedHandshake);
        }
        let keypair = EphemeralKeyPair::generate();
        let payload = ProposalPayload {
            ephemeral_public_key: keypair.public_key_encoded(),
            session_expiry: session_expiry(),
            proposal: Opaque(serde_json::to_vec(&proposal)?),
        };
        let topic = self.session.pairing_topic.clone();
        self.send_on(&topic, &ClientMessage::Proposal(payload))
            .await?;
        self.handshake = Handshake::Proposed { keypair };
        self.session.state = SessionState::ProposalSent;
        Ok(())
    }

    /// Send an `approve` carrying ephemeral public key and switch to the
    /// session topic and key.
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
        let pairing_topic = self.session.pairing_topic.clone();
        let approve_id = self
            .send_on(&pairing_topic, &ClientMessage::Approve(payload))
            .await?;
        self.pairing_approval = Some(approve_id);
        self.establish_session(key, topic)?;
        Ok(())
    }

    /// Send a `reject` and move to `Rejected`.
    pub async fn reject(&mut self, code: u32, message: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Reject(RejectPayload {
            code,
            message: message.into(),
        }))
        .await?;
        self.session.state = SessionState::Rejected;
        Ok(())
    }

    /// Send a `request` and return its correlation id.
    ///
    /// The JSON value is encoded into the protocol's opaque `request` field.
    pub async fn request(&mut self, request: Value) -> Result<RequestId> {
        self.ensure_session_active()?;
        let id = random::id()?;
        let request_id = id.to_string();
        let payload = RequestPayload {
            request_id: request_id.clone(),
            request: opaque(request)?,
        };
        let topic = self.active_topic().clone();
        self.send_with_id_on(&topic, id, &ClientMessage::Request(payload))
            .await?;
        Ok(request_id)
    }

    /// Send a `response` (or error) for a request.
    ///
    /// Each JSON value is encoded into its opaque `response` or `error` field.
    pub async fn respond(
        &mut self,
        request_id: impl Into<String>,
        response: Option<Value>,
        error: Option<Value>,
    ) -> Result<()> {
        self.send(&ClientMessage::Response(ResponsePayload {
            request_id: request_id.into(),
            response: response.map(opaque).transpose()?,
            error: error.map(opaque).transpose()?,
        }))
        .await?;
        Ok(())
    }

    /// Acknowledge a received message.
    pub async fn ack(&mut self, ack_id: MessageId) -> Result<()> {
        self.send(&ClientMessage::Ack(AckPayload { ack_id }))
            .await?;
        Ok(())
    }

    /// Gracefully disconnect.
    pub async fn disconnect(&mut self, reason: impl Into<String>, code: u32) -> Result<()> {
        self.send(&ClientMessage::Disconnect(DisconnectPayload {
            reason: reason.into(),
            code,
            message: String::new(),
        }))
        .await?;
        self.session.state = SessionState::Disconnected;
        Ok(())
    }
}

/// Encode a JSON application value as the protocol's opaque payload.
fn opaque(value: Value) -> Result<Opaque> {
    Ok(Opaque(serde_json::to_vec(&value)?))
}

/// Session expiry timestamp for a fresh proposal.
fn session_expiry() -> u64 {
    unix_now().saturating_add(SESSION_EXPIRY.as_secs())
}
