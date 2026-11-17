use std::{
    collections::VecDeque,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

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
    handshake::{
        EphemeralKeyPair, SessionKey, SessionTopic, decode_public_key, validate_peer_public,
    },
    identity::{IdentityKey, unix_now},
    messages::{ClientMessage, RequestId},
    random,
    relay::{INBOX_CAPACITY, Inbox, Transport},
    reliability::{ClientEvent, DeliveryEvent, EVENT_CAPACITY, Reliability, requires_ack},
    replay::{self, Observation, ReplayMemory},
    session::{Role, Session, SessionState},
};

/// Default session lifetime.
const SESSION_EXPIRY: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum accepted clock skew between envelope `ts` and local time.
const MAX_TS_SKEW_SECS: u64 = 300;

/// Maximum application messages buffered while waiting for `session_ready`.
const MAX_PENDING_MESSAGES: usize = 256;

/// A terminal client state that no later operation can leave.
#[derive(Clone, Copy)]
enum Terminal {
    Closed,
    Transport(&'static str),
}

impl Terminal {
    fn error(self) -> ClientError {
        match self {
            Terminal::Closed => ClientError::Closed,
            Terminal::Transport(reason) => ClientError::Transport(reason),
        }
    }
}

/// Local side of the session handshake.
enum Handshake {
    /// No handshake activity yet.
    Idle,

    /// We sent a proposal and hold its ephemeral keypair.
    Proposed { keypair: EphemeralKeyPair },

    /// We received a valid proposal and already derived the session material
    /// from our own ephemeral keypair and the peer's public key.
    PeerProposed {
        public_key: String,
        key: SessionKey,
        topic: SessionTopic,
    },

    /// Session key established; traffic uses the session topic and key.
    Established,
}

/// A message frame that passed wire validation, sender policy, topic/kind
/// policy, capacity checks and authentication.
struct InboundEnvelope {
    id: MessageId,
    topic: Topic,
    wire: Message,
    plaintext: Vec<u8>,
    now: u64,
}

/// One relay connection, its outbound reliability and its inbound replay
/// memory.
struct Link<C> {
    topic: Topic,
    _transport: Transport,
    reliability: Reliability,
    cipher: C,
    replay: ReplayMemory,
    ready: bool,
    saw_disconnect: bool,
}

impl<C> Link<C>
where
    C: MessageCipher<Sealed = SealedPayload, Error = CipherError>,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &ClientConfig,
        identity: &IdentityKey,
        role: Role,
        topic: Topic,
        cipher: C,
        lifecycle: mpsc::Sender<ClientEvent>,
        outcomes: mpsc::UnboundedSender<DeliveryEvent>,
        inbox: &mpsc::Sender<Inbox>,
    ) -> Self {
        let ready = Arc::new(AtomicBool::new(false));
        let transport = Transport::connect(
            config.clone(),
            identity.clone(),
            role,
            topic.clone(),
            Arc::clone(&ready),
            inbox.clone(),
        );
        let reliability = Reliability::spawn(
            transport.outbound(),
            Arc::clone(&ready),
            lifecycle,
            outcomes,
            config.ack_base_delay,
            config.ack_max_attempts,
            config.retransmit_spacing,
            config.retransmit_bytes_per_second,
        );

        Self {
            topic,
            _transport: transport,
            reliability,
            cipher,
            replay: ReplayMemory::new(Duration::from_secs(MAX_TS_SKEW_SECS), replay::CAPACITY),
            ready: false,
            saw_disconnect: false,
        }
    }
}

/// A paired client.
///
/// Inbound work, including acknowledgements, retransmissions and relay
/// lifecycle events, is driven by [`Client::recv`], [`Client::next_event`] and
/// [`Client::wait_session_ready`]. Applications must keep one of those futures
/// pending; [`Client::send`] and [`Client::poll_event`] do not drive the receive
/// path. Cancelling a receive future after it has dequeued a frame may lose
/// that frame, but the peer retransmits anything left unacknowledged.
///
/// Counterpart, replay memory, and reliability state are owned by this
/// instance and are not persisted. Constructing a new client for the same
/// pairing key starts with an empty replay memory and no counterpart, so
/// long-lived applications should keep one client alive rather than recreate
/// it from the pairing key. Restart recovery requires persisting and restoring
/// that state, which this crate does not implement.
///
/// Delivery outcomes reserve pending capacity until the application consumes
/// them. With 256 pending messages or unconsumed outcomes per link, further
/// sends return [`ClientError::Busy`] instead of dropping an outcome.
pub struct Client<C> {
    config: ClientConfig,
    identity: IdentityKey,
    inbox: mpsc::Receiver<Inbox>,
    inbox_tx: mpsc::Sender<Inbox>,
    lifecycle: mpsc::Receiver<ClientEvent>,
    lifecycle_tx: mpsc::Sender<ClientEvent>,
    outcomes: mpsc::UnboundedReceiver<DeliveryEvent>,
    outcomes_tx: mpsc::UnboundedSender<DeliveryEvent>,
    pairing: Option<Link<C>>,
    session_link: Option<Link<C>>,
    session: Session,
    handshake: Handshake,
    did: DidKey,
    pending: VecDeque<ClientMessage>,
    pairing_proposal: Option<MessageId>,
    pairing_approval: Option<MessageId>,
    terminal: Option<Terminal>,
}

impl<C> Client<C>
where
    C: MessageCipher<Sealed = SealedPayload, Error = CipherError>,
{
    /// Connect to the relay for the pairing topic.
    ///
    /// The cipher must provide a fresh cipher for the derived session key so
    /// the session starts with a new nonce prefix and counter.
    pub async fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
        cipher: C,
    ) -> Result<Self> {
        config.validate()?;
        let did = identity.did();
        let (inbox_tx, inbox) = mpsc::channel(INBOX_CAPACITY);
        let (lifecycle_tx, lifecycle) = mpsc::channel(EVENT_CAPACITY);
        let (outcomes_tx, outcomes) = mpsc::unbounded_channel();
        let pairing = Link::new(
            &config,
            &identity,
            role,
            topic.clone(),
            cipher,
            lifecycle_tx.clone(),
            outcomes_tx.clone(),
            &inbox_tx,
        );
        let session = Session::new(topic, role);

        Ok(Self {
            config,
            identity,
            inbox,
            inbox_tx,
            lifecycle,
            lifecycle_tx,
            outcomes,
            outcomes_tx,
            pairing: Some(pairing),
            session_link: None,
            session,
            handshake: Handshake::Idle,
            did,
            pending: VecDeque::new(),
            pairing_proposal: None,
            pairing_approval: None,
            terminal: None,
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    /// Whether the relay session on the active topic is ready.
    pub fn is_ready(&self) -> bool {
        self.active_link().is_some_and(|link| link.ready)
    }

    fn active_link(&self) -> Option<&Link<C>> {
        self.session_link.as_ref().or(self.pairing.as_ref())
    }

    fn terminal_error(&self) -> Option<ClientError> {
        self.terminal.map(Terminal::error)
    }

    /// Stop all traffic, report outstanding sends, and release both links.
    fn close(&mut self, terminal: Terminal) {
        self.terminal = Some(terminal);
        if let Some(mut link) = self.pairing.take() {
            link.reliability.fail_all();
        }
        if let Some(mut link) = self.session_link.take() {
            link.reliability.fail_all();
        }
    }

    fn active_topic(&self) -> &Topic {
        &self.session.topic
    }

    fn link(&self, topic: &Topic) -> Option<&Link<C>> {
        if self
            .pairing
            .as_ref()
            .is_some_and(|link| link.topic == *topic)
        {
            return self.pairing.as_ref();
        }
        self.session_link
            .as_ref()
            .filter(|link| link.topic == *topic)
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

    /// Apply one transport lifecycle item, returning a relay frame if present.
    fn handle_inbox_item(&mut self, item: Inbox) -> Result<Option<RelayFrame>> {
        match item {
            Inbox::Frame(frame) => {
                if matches!(&frame.body, RelayFrameBody::SessionReady) {
                    self.set_ready(&frame.topic);
                }
                Ok(Some(frame))
            }
            Inbox::Connected(topic) => {
                self.set_connected(&topic, true);
                Ok(None)
            }
            Inbox::Ready(topic) => {
                self.set_ready(&topic);
                Ok(None)
            }
            Inbox::Disconnected(topic) => {
                self.set_connected(&topic, false);
                Ok(None)
            }
            Inbox::Closed { topic, reason } => {
                let active = topic == *self.active_topic();
                if let Some(link) = self.link_mut(&topic) {
                    link.reliability.fail_all();
                }
                self.set_connected(&topic, false);
                if active {
                    self.close(Terminal::Transport(reason));
                    return Err(ClientError::Transport(reason));
                }
                log::debug!("relay link closed for inactive topic {}", topic.log_tag());
                Ok(None)
            }
            Inbox::Retire(topic) => {
                if self
                    .pairing
                    .as_ref()
                    .is_some_and(|link| link.topic == topic)
                {
                    log::debug!("retiring pairing link {}", topic.log_tag());
                    self.retire_pairing();
                }
                Ok(None)
            }
            Inbox::SessionTimeout(topic) => {
                let expired = self
                    .session_link
                    .as_ref()
                    .is_some_and(|link| link.topic == topic && !link.ready);
                if expired {
                    log::warn!(
                        "session link {} did not become ready; dropping it",
                        topic.log_tag()
                    );
                    self.session_link = None;
                    if self.session.state == SessionState::Active {
                        self.session.state = SessionState::Disconnected;
                    }
                }
                Ok(None)
            }
        }
    }

    /// Await the next relay frame, folding in transport lifecycle events.
    async fn next_frame(&mut self) -> Result<RelayFrame> {
        loop {
            let item = self.inbox.recv().await.ok_or(ClientError::Closed)?;
            if let Some(frame) = self.handle_inbox_item(item)? {
                return Ok(frame);
            }
        }
    }

    /// Process one relay frame's body.
    async fn handle_frame(
        &mut self,
        frame: RelayFrame,
        deliver: bool,
    ) -> Result<Option<ClientMessage>> {
        if matches!(&frame.body, RelayFrameBody::Message { .. }) {
            return self.handle_message_frame(frame, deliver).await;
        }

        match frame.body {
            RelayFrameBody::SessionReady => Ok(None),
            RelayFrameBody::PeerDisconnected => {
                if frame.topic == *self.active_topic() {
                    self.mark_not_ready(&frame.topic);
                    self.session.state = SessionState::Disconnected;
                    return Err(ClientError::PeerDisconnected);
                }
                Ok(None)
            }
            RelayFrameBody::Message { .. } => unreachable!("handled above"),
        }
    }

    fn set_connected(&mut self, topic: &Topic, connected: bool) {
        let active = *topic == *self.active_topic();
        let Some(link) = self.link_mut(topic) else {
            return;
        };

        // A socket is not ready until the relay reports `session_ready`.
        link.ready = false;

        if connected {
            if link.saw_disconnect {
                link.saw_disconnect = false;
                if active {
                    link.reliability.emit(ClientEvent::Reconnected);
                }
            }
        } else if !link.saw_disconnect {
            link.saw_disconnect = true;
            if active {
                link.reliability.emit(ClientEvent::Reconnecting);
            }
        }
    }

    fn set_ready(&mut self, topic: &Topic) {
        let Some(link) = self.link_mut(topic) else {
            return;
        };
        link.ready = true;
    }

    fn mark_not_ready(&mut self, topic: &Topic) {
        let Some(link) = self.link_mut(topic) else {
            return;
        };
        link.ready = false;
    }

    /// Wait until the relay reports the active topic ready.
    ///
    /// Before the handshake this waits on the pairing topic. After the
    /// handshake it waits on the derived session topic. Messages received
    /// while waiting are queued for the next [`Client::recv`].
    pub async fn wait_session_ready(&mut self) -> Result<()> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        while !self.is_ready() {
            let frame = self.next_frame().await?;
            // Consume acknowledgements and retransmissions that arrive while
            // waiting. Application messages are queued for the next `recv`
            // while there is room; otherwise they are left unacknowledged so
            // the peer retries later.
            let deliver = self.pending.len() < MAX_PENDING_MESSAGES;
            if let Some(message) = self.handle_frame(frame, deliver).await? {
                self.pending.push_back(message);
            }
        }
        if matches!(self.handshake, Handshake::Established) {
            self.session.state = SessionState::Active;
        }
        Ok(())
    }

    /// Seal and send an application message, returning its envelope id.
    ///
    /// Handshake messages must use [`Client::propose`], [`Client::approve`]
    /// and [`Client::reject`], which also update the handshake state.
    /// Acknowledgements are sent automatically after a message passes the
    /// receive checks; [`ClientMessage::Ack`] is therefore rejected here.
    ///
    /// Application messages are refused until the handshake is established,
    /// then use the derived session topic.
    ///
    /// A tracked send reserves pending/outcome capacity until its delivery
    /// event is consumed. Applications that only call `send`/`recv` must
    /// still drain [`Client::poll_event`] or [`Client::next_event`]; once 256
    /// sends are pending or their outcomes are unconsumed, sends return
    /// [`ClientError::Busy`].
    pub async fn send(&mut self, message: &ClientMessage) -> Result<MessageId> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        match message {
            ClientMessage::Proposal(_) | ClientMessage::Approve(_) | ClientMessage::Reject(_) => {
                return Err(ClientError::UnexpectedHandshake);
            }
            ClientMessage::Ack(_) => {
                return Err(ClientError::ProtocolViolation(
                    "acknowledgements are sent automatically",
                ));
            }
            _ => {}
        }
        self.ensure_session_ready()?;
        let topic = self.active_topic().clone();
        self.send_on(&topic, message).await
    }

    /// Whether application messages may be sent.
    fn ensure_session_ready(&self) -> Result<()> {
        if !matches!(self.handshake, Handshake::Established) {
            return Err(ClientError::SessionNotActive);
        }
        if !self.active_link().is_some_and(|link| link.ready) {
            return Err(ClientError::NotReady);
        }
        Ok(())
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
        link.reliability.dispatch(frame, requires_ack(kind), ts)
    }

    /// Receive the next application message, processing acknowledgements and
    /// lifecycle traffic while waiting.
    pub async fn recv(&mut self) -> Result<ClientMessage> {
        // Messages queued and already acknowledged before the link became
        // terminal are still owed to the application.
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }

        loop {
            let frame = self.next_frame().await?;
            if let Some(message) = self.handle_frame(frame, true).await? {
                return Ok(message);
            }
        }
    }

    /// Process one `message` frame. Returns the message to deliver, or `None`
    /// for acknowledgements, retransmissions and envelopes for inactive
    /// handshake state.
    async fn handle_message_frame(
        &mut self,
        frame: RelayFrame,
        deliver: bool,
    ) -> Result<Option<ClientMessage>> {
        let Some(envelope) = self.authenticate_frame(frame, deliver) else {
            return Ok(None);
        };
        self.process_envelope(envelope).await
    }

    /// Apply wire, sender, topic and cryptographic checks to a frame.
    ///
    /// This does not mutate client state. The plaintext is returned unparsed
    /// so the caller can preserve replay-classification ordering before
    /// interpreting it.
    fn authenticate_frame(&self, frame: RelayFrame, deliver: bool) -> Option<InboundEnvelope> {
        let RelayFrame {
            id, topic, body, ..
        } = frame;
        let RelayFrameBody::Message { payload } = body else {
            return None;
        };

        let Some(link) = self.link(&topic) else {
            log::warn!("dropping frame for unknown topic {}", topic.log_tag());
            return None;
        };

        let wire: Message = match serde_json::from_str(&payload) {
            Ok(wire) => wire,
            Err(error) => {
                log::warn!(
                    "dropping malformed envelope on topic {}: {error}",
                    topic.log_tag()
                );
                return None;
            }
        };

        if wire.from == self.did {
            log::warn!("dropping frame from own identity {}", wire.from);
            return None;
        }
        if let Some(counterpart) = &self.session.peer_did {
            if wire.from != *counterpart {
                log::warn!(
                    "dropping frame from {}; established counterpart is {}",
                    wire.from,
                    counterpart
                );
                return None;
            }
        } else if topic != self.session.pairing_topic {
            log::warn!("dropping session-topic frame before the counterpart is established");
            return None;
        }

        if wire.version != Message::VERSION {
            log::warn!("dropping frame with unsupported version {}", wire.version);
            return None;
        }
        let now = unix_now();
        if now.abs_diff(wire.ts) > MAX_TS_SKEW_SECS {
            log::warn!("dropping frame with stale timestamp ts={}", wire.ts);
            return None;
        }
        if link.replay.is_stale(wire.ts) {
            log::warn!("dropping frame with discarded timestamp ts={}", wire.ts);
            return None;
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
        let plaintext = match link.cipher.open(&aad, &sealed) {
            Ok(bytes) => bytes,
            Err(error) => {
                log::warn!(
                    "dropping unauthenticated envelope on topic {}: {error}",
                    topic.log_tag()
                );
                return None;
            }
        };

        // The pairing key is for the handshake only. Application kinds on the
        // pairing topic are dropped even after the session is established, so
        // a leaked pairing key cannot bypass the session key. Conversely, the
        // session topic carries application traffic only.
        if !self.allowed_on_topic(&topic, wire.kind) {
            log::warn!(
                "dropping {} on topic {}",
                wire.kind.as_str(),
                topic.log_tag()
            );
            return None;
        }

        // While `wait_session_ready`/`next_event` has no room to queue a
        // message, drop it without recording or acknowledging it, so the peer
        // retransmits it later instead of the application silently losing it.
        // Acks are not delivered and must still be processed.
        if !deliver && wire.kind != MessageType::Ack {
            log::warn!("dropping message: pending queue is full");
            return None;
        }

        Some(InboundEnvelope {
            id,
            topic,
            wire,
            plaintext,
            now,
        })
    }

    /// Whether `kind` may travel on `topic`.
    fn allowed_on_topic(&self, topic: &Topic, kind: MessageType) -> bool {
        if *topic == self.session.pairing_topic {
            kind.is_handshake() || kind == MessageType::Ack
        } else {
            kind.is_application()
        }
    }

    /// Whether a handshake message arrived after the handshake completed.
    fn is_late_handshake(&self, message: &ClientMessage) -> bool {
        matches!(self.handshake, Handshake::Established)
            && matches!(
                message,
                ClientMessage::Proposal(_) | ClientMessage::Approve(_) | ClientMessage::Reject(_)
            )
    }

    /// Apply replay and handshake semantics to an authenticated frame.
    async fn process_envelope(
        &mut self,
        envelope: InboundEnvelope,
    ) -> Result<Option<ClientMessage>> {
        let InboundEnvelope {
            id,
            topic,
            wire,
            plaintext,
            now,
        } = envelope;

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
            Observation::Full => {
                log::warn!("dropping envelope: replay memory is full");
                return Ok(None);
            }
            Observation::New => {}
        }

        let message = match ClientMessage::from_bytes(&plaintext) {
            Ok(message) => message,
            Err(error) => {
                log::warn!(
                    "dropping malformed plaintext on topic {}: {error}",
                    topic.log_tag()
                );
                return Ok(None);
            }
        };
        if message.message_type() != wire.kind {
            log::warn!(
                "dropping envelope: plaintext type does not match kind {}",
                wire.kind.as_str()
            );
            return Ok(None);
        }

        if let ClientMessage::Response(response) = &message
            && !response.is_valid()
        {
            log::warn!("dropping response without exactly one of response or error");
            return Ok(None);
        }

        let terminates = matches!(
            &message,
            ClientMessage::Disconnect(_) | ClientMessage::SessionDelete(_)
        );
        if terminates {
            self.session.state = SessionState::Disconnected;
        }

        // acks are consumed by reliability
        if let ClientMessage::Ack(ack) = &message {
            self.commit_ack(&id, &topic, &wire, ack);
            return Ok(None);
        }

        // Once established, the pairing key may no longer create new handshake
        // state. Retransmissions of the handshake were re-acked above.
        if self.is_late_handshake(&message) {
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

        if terminates {
            // The peer ended the session. Deliver this final message, then
            // make every later operation observe a terminal client.
            self.close(Terminal::Closed);
        }

        Ok(Some(message))
    }

    /// Record an inbound ack and report delivery.
    fn commit_ack(&mut self, id: &MessageId, topic: &Topic, wire: &Message, ack: &AckPayload) {
        let ack_id = ack.ack_id.clone();
        let retires_pairing =
            *topic == self.session.pairing_topic && self.pairing_approval.as_ref() == Some(&ack_id);
        let link = self.link_mut(topic).expect("topic was checked");
        link.replay.record(id, wire);
        link.reliability.mark_delivered(&ack_id);
        if retires_pairing {
            self.retire_pairing();
        }
    }

    /// Acknowledge a received envelope by id, on the topic it arrived on.
    async fn send_ack(&mut self, ack_id: &MessageId, topic: &Topic) -> Result<()> {
        let result = self
            .send_on(
                topic,
                &ClientMessage::Ack(AckPayload {
                    ack_id: ack_id.clone(),
                }),
            )
            .await;
        match result {
            Ok(_) => Ok(()),
            Err(ClientError::Busy) => {
                // The peer retransmits unacknowledged messages; dropping this
                // ack under local backpressure is recoverable.
                log::warn!("dropping ack: outbound queue is full");
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Non-blocking read of the next reliability event, if any.
    ///
    /// This does not process inbound frames. Call [`Client::recv`] or
    /// [`Client::next_event`] to drive acknowledgements and delivery.
    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        let event = self
            .outcomes
            .try_recv()
            .ok()
            .map(|(event, _permit)| event)
            .or_else(|| self.lifecycle.try_recv().ok())?;
        Some(self.received_event(event))
    }

    fn received_event(&mut self, event: ClientEvent) -> ClientEvent {
        match &event {
            ClientEvent::Delivered { id } => {
                if self.pairing_proposal.as_ref() == Some(id) {
                    self.pairing_proposal = None;
                }
            }
            ClientEvent::Failed { id, .. } => {
                if self.pairing_approval.as_ref() == Some(id) {
                    self.retire_pairing();
                    self.schedule_session_timeout();
                }
                if self.pairing_proposal.as_ref() == Some(id) {
                    self.pairing_proposal = None;
                    if matches!(self.handshake, Handshake::Proposed { .. }) {
                        self.handshake = Handshake::Idle;
                        if self.session.state == SessionState::ProposalSent {
                            self.session.state = SessionState::Idle;
                        }
                    }
                }
            }
            ClientEvent::Reconnecting | ClientEvent::Reconnected => {}
        }
        event
    }

    /// Await the next reliability event while processing inbound frames.
    ///
    /// Use this instead of polling [`Client::poll_event`] when acknowledgements
    /// or lifecycle traffic may arrive while the application waits.
    pub async fn next_event(&mut self) -> Result<ClientEvent> {
        loop {
            // Outcomes are still owed after a terminal transition; drain them
            // before surfacing the terminal error.
            if let Ok((event, _permit)) = self.outcomes.try_recv() {
                return Ok(self.received_event(event));
            }
            if let Ok(event) = self.lifecycle.try_recv() {
                return Ok(self.received_event(event));
            }
            if let Some(error) = self.terminal_error() {
                return Err(error);
            }

            tokio::select! {
                item = self.inbox.recv() => {
                    let item = item.ok_or(ClientError::Closed)?;
                    if let Some(frame) = self.handle_inbox_item(item)? {
                        let deliver = self.pending.len() < MAX_PENDING_MESSAGES;
                        if let Some(message) = self.handle_frame(frame, deliver).await? {
                            self.pending.push_back(message);
                        }
                    }
                }
                event = self.outcomes.recv() => {
                    let (event, _permit) = event.ok_or(ClientError::Closed)?;
                    return Ok(self.received_event(event));
                }
                event = self.lifecycle.recv() => {
                    let event = event.ok_or(ClientError::Closed)?;
                    return Ok(self.received_event(event));
                }
            }
        }
    }

    /// Drop the pairing connection once the handshake no longer needs it.
    fn retire_pairing(&mut self) {
        let Some(mut link) = self.pairing.take() else {
            return;
        };
        log::debug!("retiring pairing link {}", link.topic.log_tag());
        link.reliability.fail_all();
    }

    /// Update handshake state from an inbound pairing message.
    fn observe(&mut self, message: &ClientMessage) -> Result<()> {
        match message {
            ClientMessage::Proposal(proposal) => {
                if !matches!(self.handshake, Handshake::Idle) {
                    return Err(ClientError::UnexpectedHandshake);
                }
                let peer_public = decode_public_key(&proposal.ephemeral_public_key)?;
                // Derive now, while the proposal is being accepted, so a
                // low-order peer key is rejected before this proposal is
                // acknowledged or changes the handshake state.
                let keypair = EphemeralKeyPair::generate();
                let public_key = keypair.public_key_encoded();
                let (key, topic) = keypair.derive(&peer_public)?;
                self.handshake = Handshake::PeerProposed {
                    public_key,
                    key,
                    topic,
                };
                self.session.state = SessionState::ProposalReceived;
            }
            ClientMessage::Approve(approve) => {
                if !matches!(self.handshake, Handshake::Proposed { .. }) {
                    return Err(ClientError::UnexpectedHandshake);
                }
                let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
                // Keep the proposal keypair until the peer's key is known to
                // produce a usable shared secret, so a weak approve cannot
                // strand the proposer in `Idle`.
                validate_peer_public(&peer_public)?;
                let Handshake::Proposed { keypair } =
                    std::mem::replace(&mut self.handshake, Handshake::Idle)
                else {
                    unreachable!("state checked above");
                };
                let (key, topic) = keypair.derive(&peer_public)?;
                self.establish_session(key, topic)?;
                // A valid approve proves the peer received the proposal, even
                // when its explicit proposal ack was lost.
                if let Some(proposal_id) = self.pairing_proposal.take()
                    && let Some(link) = self.pairing.as_mut()
                {
                    link.reliability.mark_delivered(&proposal_id);
                }
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
        let cipher = self
            .pairing
            .as_ref()
            .ok_or(ClientError::Closed)?
            .cipher
            .for_key(key.as_bytes())?;
        let link = Link::new(
            &self.config,
            &self.identity,
            self.session.role,
            session_topic.clone(),
            cipher,
            self.lifecycle_tx.clone(),
            self.outcomes_tx.clone(),
            &self.inbox_tx,
        );

        self.session_link = Some(link);
        self.session.topic = session_topic;
        self.handshake = Handshake::Established;
        self.session.state = SessionState::Active;
        self.schedule_pairing_retirement();
        Ok(())
    }

    /// Drop a session link that never became ready after a failed approve.
    fn schedule_session_timeout(&self) {
        let Some(topic) = self.session_link.as_ref().map(|link| link.topic.clone()) else {
            return;
        };
        let window = self.config.connection_stability;
        let inbox = self.inbox_tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            let _ = inbox.send(Inbox::SessionTimeout(topic)).await;
        });
    }

    /// Retire the pairing connection after the handshake ack retry window.
    fn schedule_pairing_retirement(&self) {
        let window = self.pairing_retirement_window();
        let inbox = self.inbox_tx.clone();
        let topic = self.session.pairing_topic.clone();
        tokio::spawn(async move {
            tokio::time::sleep(window).await;
            // Wait for inbox capacity instead of dropping the only retirement
            // signal. The send fails once the client and its receiver are gone.
            let _ = inbox.send(Inbox::Retire(topic)).await;
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
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if self.session.role != Role::Proposer {
            return Err(ClientError::ProtocolViolation(
                "only the proposer may propose",
            ));
        }
        if !matches!(self.handshake, Handshake::Idle) {
            return Err(ClientError::UnexpectedHandshake);
        }
        if !self.pairing.as_ref().is_some_and(|link| link.ready) {
            return Err(ClientError::NotReady);
        }
        let keypair = EphemeralKeyPair::generate();
        let payload = ProposalPayload {
            ephemeral_public_key: keypair.public_key_encoded(),
            session_expiry: session_expiry(),
            proposal: Opaque(serde_json::to_vec(&proposal)?),
        };
        let topic = self.session.pairing_topic.clone();
        let proposal_id = self
            .send_on(&topic, &ClientMessage::Proposal(payload))
            .await?;
        self.pairing_proposal = Some(proposal_id);
        self.handshake = Handshake::Proposed { keypair };
        self.session.state = SessionState::ProposalSent;
        Ok(())
    }

    /// Send an `approve` carrying ephemeral public key and switch to the
    /// session topic and key.
    pub async fn approve(&mut self, approval: Value) -> Result<()> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if self.session.role != Role::Responder {
            return Err(ClientError::ProtocolViolation(
                "only the responder may approve",
            ));
        }
        let (public_key, key, topic) = match &self.handshake {
            Handshake::PeerProposed {
                public_key,
                key,
                topic,
            } => (public_key.clone(), key.clone(), topic.clone()),
            _ => return Err(ClientError::UnexpectedHandshake),
        };
        if !self.pairing.as_ref().is_some_and(|link| link.ready) {
            return Err(ClientError::NotReady);
        }
        let payload = ApprovePayload {
            ephemeral_public_key: public_key,
            approval: Opaque(serde_json::to_vec(&approval)?),
        };
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
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if matches!(self.handshake, Handshake::Established) {
            return Err(ClientError::UnexpectedHandshake);
        }
        if !self.pairing.as_ref().is_some_and(|link| link.ready) {
            return Err(ClientError::NotReady);
        }
        let topic = self.session.pairing_topic.clone();
        self.send_on(
            &topic,
            &ClientMessage::Reject(RejectPayload {
                code,
                message: message.into(),
            }),
        )
        .await?;
        self.session.state = SessionState::Rejected;
        Ok(())
    }

    /// Send a `request` and return its correlation id.
    ///
    /// The JSON value is encoded into the protocol's opaque `request` field.
    pub async fn request(&mut self, request: Value) -> Result<RequestId> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        self.ensure_session_ready()?;
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
        let payload = ResponsePayload {
            request_id: request_id.into(),
            response: response.map(opaque).transpose()?,
            error: error.map(opaque).transpose()?,
        };
        if !payload.is_valid() {
            return Err(ClientError::ProtocolViolation(
                "response must carry exactly one of response or error",
            ));
        }
        self.send(&ClientMessage::Response(payload)).await?;
        Ok(())
    }

    /// Gracefully disconnect.
    ///
    /// The local client is closed even when the peer cannot be notified, for
    /// example because the link is not ready. The notification error is
    /// returned after the local teardown.
    pub async fn disconnect(&mut self, reason: impl Into<String>, code: u32) -> Result<()> {
        let result = self
            .send(&ClientMessage::Disconnect(DisconnectPayload {
                reason: reason.into(),
                code,
                message: String::new(),
            }))
            .await;
        self.session.state = SessionState::Disconnected;
        self.close(Terminal::Closed);
        result?;
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
