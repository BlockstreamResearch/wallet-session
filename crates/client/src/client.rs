use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
        RequestPayload, ResponsePayload, SessionDeletePayload,
    },
};

use crate::{
    config::{ClientConfig, MAX_RETRY_DELAY},
    crypto::{Aad, CipherError, SealedPayload},
    error::{ClientError, JsonErrorSummary, Result},
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
    NotEstablished,
}

impl Terminal {
    fn error(self) -> ClientError {
        match self {
            Terminal::Closed => ClientError::Closed,
            Terminal::Transport(reason) => ClientError::Transport(reason),
            Terminal::NotEstablished => ClientError::SessionNotEstablished,
        }
    }
}

/// Local side of the session handshake.
enum Handshake {
    /// No handshake activity yet.
    Idle,

    /// We sent the proposal carried by frame `proposal_id` and hold its
    /// ephemeral keypair.
    Proposed {
        proposal_id: MessageId,
        keypair: EphemeralKeyPair,
    },

    /// We received the proposal carried by frame `proposal_id` and already
    /// derived the session material from our own ephemeral keypair and the
    /// peer's public key.
    PeerProposed {
        proposal_id: MessageId,
        proposal: ProposalPayload,
        public_key: String,
        key: SessionKey,
        topic: SessionTopic,
    },

    /// Session key established; traffic uses the session topic and key.
    Established,
}

/// A message frame that passed wire validation, sender policy, topic/kind
/// policy and authentication.
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
    shared_ready: Arc<AtomicBool>,
    joined: Arc<AtomicBool>,
    saw_disconnect: bool,
}

impl<C> Link<C> {
    fn is_ready(&self) -> bool {
        self.shared_ready.load(Ordering::Relaxed)
    }

    /// Whether the relay ever reported both peers on this topic.
    fn has_joined(&self) -> bool {
        self.joined.load(Ordering::Relaxed)
    }
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
        let joined = Arc::new(AtomicBool::new(false));
        let transport = Transport::connect(
            config.clone(),
            identity.clone(),
            role,
            topic.clone(),
            Arc::clone(&ready),
            Arc::clone(&joined),
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
            shared_ready: ready,
            joined,
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
///
/// # Logging
///
/// The relay connection token and the topic travel in the WebSocket URL.
/// This crate logs neither, but `tungstenite` logs the whole request at
/// `trace` level. Do not enable `trace` for `tungstenite` wherever logs are
/// kept or shared: the token is valid for `token_ttl`, and a pairing topic
/// lets whoever reads it take the free role on it.
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
        self.active_link().is_some_and(Link::is_ready)
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
            Inbox::Frame(frame) => Ok(Some(frame)),
            Inbox::Connected(topic) => {
                self.set_connected(&topic, true);
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
                // Only a link the proposer never joined is abandoned. A peer
                // that joined and is briefly away is handled like any other
                // disconnect. That includes one that joined after the timer
                // fired but before we got to this item: the session works,
                // and closing it would only be for the timer's sake.
                let abandoned = self
                    .session_link
                    .as_ref()
                    .is_some_and(|link| link.topic == topic && !link.has_joined());
                if abandoned {
                    log::warn!("session link {} was never joined; closing", topic.log_tag());
                    self.session.state = SessionState::Disconnected;
                    self.close(Terminal::NotEstablished);
                    return Err(ClientError::SessionNotEstablished);
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
                    // The transport clears the shared readiness flag before
                    // forwarding this frame.
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
            ClientMessage::Disconnect(_) | ClientMessage::SessionDelete(_) => {
                return Err(ClientError::ProtocolViolation(
                    "end the session with disconnect() or session_delete()",
                ));
            }
            // The receiver drops these without an ack, so sending one would
            // only end in `Failed` after the whole retry budget.
            ClientMessage::Response(response) if !response.is_valid() => {
                return Err(ClientError::ProtocolViolation(
                    "response must carry exactly one of response or error",
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
        if !self.active_link().is_some_and(Link::is_ready) {
            return Err(ClientError::NotReady);
        }
        Ok(())
    }

    async fn send_on(&mut self, topic: &Topic, message: &ClientMessage) -> Result<MessageId> {
        let id = random::id()?;
        let track = requires_ack(message.message_type());
        self.send_with_id_on(topic, id.clone(), message, track)
            .await?;
        Ok(id)
    }

    /// Seal and send a message with a caller-chosen envelope id, tracking it
    /// for retransmission when `track` is set.
    async fn send_with_id_on(
        &mut self,
        topic: &Topic,
        id: MessageId,
        message: &ClientMessage,
        track: bool,
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
            v: RelayFrame::VERSION,
            id,
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: serde_json::to_string(&wire)?,
            },
        };
        link.reliability.dispatch(frame, track, ts)
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
        let Some(envelope) = self.authenticate_frame(frame) else {
            return Ok(None);
        };
        self.process_envelope(envelope, deliver).await
    }

    /// Apply wire, sender, topic and cryptographic checks to a frame.
    ///
    /// This does not mutate client state. The plaintext is returned unparsed
    /// so the caller can preserve replay-classification ordering before
    /// interpreting it.
    fn authenticate_frame(&self, frame: RelayFrame) -> Option<InboundEnvelope> {
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
                    "dropping malformed envelope on topic {}: {}",
                    topic.log_tag(),
                    JsonErrorSummary(&error)
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
    ///
    /// When `deliver` is false there is no room to queue a new message for
    /// the application.
    async fn process_envelope(
        &mut self,
        envelope: InboundEnvelope,
        deliver: bool,
    ) -> Result<Option<ClientMessage>> {
        let InboundEnvelope {
            id,
            topic,
            wire,
            plaintext,
            now,
        } = envelope;

        // A `disconnect` or `session_delete` is sent once: its sender closes
        // straight after sending it and never retransmits it, so dropping one
        // for lack of room would lose it for good. It ends the session, so
        // letting it through grows the replay memory and the pending queue by
        // one at most.
        let one_shot = matches!(
            wire.kind,
            MessageType::Disconnect | MessageType::SessionDelete
        );

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
            // Dropping an ack would report a delivered message as `Failed`,
            // so let it through; `commit_ack` decides whether to record it.
            Observation::Full if wire.kind != MessageType::Ack && !one_shot => {
                log::warn!("dropping envelope: replay memory is full");
                return Ok(None);
            }
            Observation::Full | Observation::New => {}
        }
        let has_room = observation == Observation::New;

        // While `wait_session_ready`/`next_event` has no room to queue a new
        // message, drop it without recording or acknowledging it, so the peer
        // retransmits it later instead of the application silently losing it.
        // This comes after replay classification so that a retransmission of
        // something we already accepted is still re-acknowledged above.
        if !deliver && wire.kind != MessageType::Ack && !one_shot {
            log::warn!("dropping message: pending queue is full");
            return Ok(None);
        }

        let message = match serde_json::from_slice::<ClientMessage>(&plaintext) {
            Ok(message) => message,
            Err(error) => {
                log::warn!(
                    "dropping malformed plaintext on topic {}: {}",
                    topic.log_tag(),
                    JsonErrorSummary(&error)
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
            self.commit_ack(&id, &topic, &wire, ack, has_room);
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
            && let Err(error) = self.observe(&id, &message)
        {
            if let Some(link) = self.link_mut(&topic) {
                link.replay.forget(&id);
            }
            return Err(error);
        }
        self.pin_counterpart(&topic, &wire.from);

        if requires_ack(message.message_type()) {
            let acked = self.send_ack(&id, &topic).await;
            // Act on a disconnect even if we could not ack it, for the same
            // reason as above; only the peer's bookkeeping misses the ack.
            // A handshake message has already changed our state in `observe`,
            // and its retransmission would be refused or only re-acked, so it
            // too must reach the application now or it never will.
            let committed = terminates || topic == self.session.pairing_topic;
            if !committed {
                acked?;
            }
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

    /// Pin the sender of the first envelope we accept on the pairing topic as
    /// the counterpart. It stays the counterpart for the session topic and
    /// across reconnects.
    ///
    /// This happens only once the envelope is accepted, not as soon as it
    /// authenticates. Otherwise a pairing-key holder could get itself pinned
    /// with a single message we then refuse (a proposal to a proposer, say),
    /// and every frame from the real peer would be dropped from then on.
    fn pin_counterpart(&mut self, topic: &Topic, from: &DidKey) {
        if *topic == self.session.pairing_topic && self.session.peer_did.is_none() {
            self.session.peer_did = Some(from.clone());
            log::debug!("established counterpart {from}");
        }
    }

    /// Process an inbound ack and report delivery.
    ///
    /// `has_room` says whether the replay memory has room for a new record.
    /// An ack that completes one of our sends is recorded even when it does
    /// not, up to a fixed headroom, so a conflicting copy of it is still
    /// caught. An ack that completes nothing has no effect, so it is neither
    /// recorded nor allowed to establish the counterpart: otherwise a
    /// pairing-key holder could fill the replay memory, or get itself
    /// pinned, by acking made-up ids.
    fn commit_ack(
        &mut self,
        id: &MessageId,
        topic: &Topic,
        wire: &Message,
        ack: &AckPayload,
        has_room: bool,
    ) {
        let ack_id = ack.ack_id.clone();
        let retires_pairing =
            *topic == self.session.pairing_topic && self.pairing_approval.as_ref() == Some(&ack_id);
        let link = self.link_mut(topic).expect("topic was checked");
        let completed = link.reliability.mark_delivered(&ack_id);
        if completed && (has_room || link.replay.has_ack_headroom()) {
            link.replay.record(id, wire);
        }
        if completed {
            self.pin_counterpart(topic, &wire.from);
        }
        // A late ack for an approve we already gave up on completes nothing,
        // and like any such ack it must have no effect.
        if retires_pairing && completed {
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

    /// Update handshake state from an inbound pairing message carried by
    /// frame `id`.
    fn observe(&mut self, id: &MessageId, message: &ClientMessage) -> Result<()> {
        // Proposals come from the proposer; approves and rejects come from
        // the responder. Without this a pairing-key holder could, say, push
        // an idle proposer into `PeerProposed`, after which it could neither
        // propose (wrong state) nor approve (wrong role).
        let sender = match message {
            ClientMessage::Proposal(_) => Some(Role::Proposer),
            ClientMessage::Approve(_) | ClientMessage::Reject(_) => Some(Role::Responder),
            _ => None,
        };
        if sender.is_some_and(|sender| sender != self.session.role.counterpart()) {
            return Err(ClientError::UnexpectedHandshake);
        }

        match message {
            ClientMessage::Proposal(proposal) => {
                // The proposer starts over with a fresh keypair when its
                // proposal fails to be acknowledged. Until we approve, the
                // newest proposal replaces the pending one, so our approve
                // answers the proposal the proposer is still waiting on.
                if !matches!(
                    self.handshake,
                    Handshake::Idle | Handshake::PeerProposed { .. }
                ) {
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
                    proposal_id: id.clone(),
                    proposal: proposal.clone(),
                    public_key,
                    key,
                    topic,
                };
                self.session.state = SessionState::ProposalReceived;
            }
            ClientMessage::Approve(approve) => {
                let Handshake::Proposed { proposal_id, .. } = &self.handshake else {
                    return Err(ClientError::UnexpectedHandshake);
                };
                // An approve for an earlier proposal carries a key derived
                // from that proposal's keypair, which we no longer hold.
                // Accepting it would put us on a different session topic
                // from the responder, with neither side ever noticing.
                if approve.proposal_id != *proposal_id {
                    return Err(ClientError::UnexpectedHandshake);
                }
                let peer_public = decode_public_key(&approve.ephemeral_public_key)?;
                // Keep the proposal keypair until the peer's key is known to
                // produce a usable shared secret, so a weak approve cannot
                // strand the proposer in `Idle`.
                validate_peer_public(&peer_public)?;
                let Handshake::Proposed { keypair, .. } =
                    std::mem::replace(&mut self.handshake, Handshake::Idle)
                else {
                    unreachable!("state checked above");
                };
                let (key, topic) = keypair.derive(&peer_public)?;
                // A valid approve proves the peer received the proposal, even
                // when its explicit proposal ack was lost.
                if let Some(proposal_id) = self.pairing_proposal.take()
                    && let Some(link) = self.pairing.as_mut()
                {
                    link.reliability.mark_delivered(&proposal_id);
                }
                let cipher = match self.session_cipher(&key) {
                    Ok(cipher) => cipher,
                    Err(error) => {
                        // The keypair is spent, so this proposal can never
                        // be completed. Leave the proposer where a failed
                        // proposal leaves it, free to propose again.
                        self.session.state = SessionState::Idle;
                        return Err(error);
                    }
                };
                self.establish_session(cipher, topic);
            }
            ClientMessage::Reject(reject) => {
                // A reject answers our outstanding proposal. Drop its keypair
                // so a late approve for it cannot establish anything; the
                // application may propose again.
                let Handshake::Proposed { proposal_id, .. } = &self.handshake else {
                    return Err(ClientError::UnexpectedHandshake);
                };
                // Like an approve, it names that proposal. A retransmitted
                // reject of an earlier proposal must not end the current one
                // or count as its delivery.
                if reject.proposal_id != *proposal_id {
                    return Err(ClientError::UnexpectedHandshake);
                }
                self.handshake = Handshake::Idle;
                // Like an approve, a reject proves the proposal arrived.
                if let Some(proposal_id) = self.pairing_proposal.take()
                    && let Some(link) = self.pairing.as_mut()
                {
                    link.reliability.mark_delivered(&proposal_id);
                }
                self.session.state = SessionState::Rejected;
            }
            _ => {}
        }
        Ok(())
    }

    /// Start the session-topic connection and keep the pairing link alive
    /// until its handshake acknowledgements have had their retry window.
    fn establish_session(&mut self, cipher: C, topic: SessionTopic) {
        let session_topic = topic.as_topic().clone();
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
    }

    /// A fresh cipher for the derived session key.
    fn session_cipher(&self, key: &SessionKey) -> Result<C> {
        Ok(self
            .pairing
            .as_ref()
            .ok_or(ClientError::Closed)?
            .cipher
            .for_key(key.as_bytes())?)
    }

    /// Close the client if the proposer has not joined the session link by
    /// the join timeout after the handshake retry window.
    ///
    /// This is armed when the approve goes out, whatever happens to it. Its
    /// ack proves nothing, since anyone holding the pairing key can send one,
    /// and its `Failed` proves nothing either (§9.1). Only `session_ready` on
    /// the session link shows the proposer derived the same session topic.
    fn schedule_session_timeout(&self) {
        let Some(topic) = self.session_link.as_ref().map(|link| link.topic.clone()) else {
            return;
        };
        let window = self
            .pairing_retirement_window()
            .saturating_add(self.config.session_join_timeout);
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
            .clamp(Duration::from_secs(1), MAX_RETRY_DELAY)
    }

    /// Send a `proposal` carrying ephemeral public key.
    ///
    /// Returns the proposal's envelope id, which its `Delivered` or `Failed`
    /// event carries.
    pub async fn propose(&mut self, proposal: Value) -> Result<MessageId> {
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
        if !self.pairing.as_ref().is_some_and(Link::is_ready) {
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
        self.pairing_proposal = Some(proposal_id.clone());
        self.handshake = Handshake::Proposed {
            proposal_id: proposal_id.clone(),
            keypair,
        };
        self.session.state = SessionState::ProposalSent;
        Ok(proposal_id)
    }

    /// Approve `proposal`, sending an `approve` carrying our ephemeral public
    /// key, and switch to the session topic and key.
    ///
    /// `proposal` is the one the application showed the user. A newer
    /// proposal from the counterpart replaces the pending one, and is
    /// delivered through [`Client::recv`] like the first; if that happened in
    /// the meantime this returns [`ClientError::ProposalSuperseded`] rather
    /// than approve terms the user never saw. A newer proposal identical to
    /// `proposal` in every field has the same terms, so it is approved.
    ///
    /// Returns the approve's envelope id, which its `Delivered` or `Failed`
    /// event carries.
    pub async fn approve(
        &mut self,
        proposal: &ProposalPayload,
        approval: Value,
    ) -> Result<MessageId> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if self.session.role != Role::Responder {
            return Err(ClientError::ProtocolViolation(
                "only the responder may approve",
            ));
        }
        let (proposal_id, public_key, key, topic) = match &self.handshake {
            Handshake::PeerProposed {
                proposal_id,
                proposal: pending,
                public_key,
                key,
                topic,
            } => {
                if pending != proposal {
                    return Err(ClientError::ProposalSuperseded);
                }
                (
                    proposal_id.clone(),
                    public_key.clone(),
                    key.clone(),
                    topic.clone(),
                )
            }
            _ => return Err(ClientError::UnexpectedHandshake),
        };
        if !self.pairing.as_ref().is_some_and(Link::is_ready) {
            return Err(ClientError::NotReady);
        }
        // Everything that can fail happens before the approve goes out. Once
        // it is on the wire the proposer may establish the session, and we
        // must then be able to as well.
        let cipher = self.session_cipher(&key)?;
        let payload = ApprovePayload {
            proposal_id,
            ephemeral_public_key: public_key,
            approval: Opaque(serde_json::to_vec(&approval)?),
        };
        let pairing_topic = self.session.pairing_topic.clone();
        let approve_id = self
            .send_on(&pairing_topic, &ClientMessage::Approve(payload))
            .await?;
        self.pairing_approval = Some(approve_id.clone());
        self.establish_session(cipher, topic);
        self.schedule_session_timeout();
        Ok(approve_id)
    }

    /// Reject `proposal` and move to `Rejected`.
    ///
    /// As with [`Client::approve`], `proposal` is the one the application
    /// showed the user, and this returns [`ClientError::ProposalSuperseded`]
    /// if a newer one has replaced it. Rejecting also forgets the session key
    /// derived for the proposal, so a later `approve` fails until a new
    /// proposal arrives.
    pub async fn reject(
        &mut self,
        proposal: &ProposalPayload,
        code: u32,
        message: impl Into<String>,
    ) -> Result<()> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        if self.session.role != Role::Responder {
            return Err(ClientError::ProtocolViolation(
                "only the responder may reject",
            ));
        }
        let Handshake::PeerProposed {
            proposal_id,
            proposal: pending,
            ..
        } = &self.handshake
        else {
            return Err(ClientError::UnexpectedHandshake);
        };
        if pending != proposal {
            return Err(ClientError::ProposalSuperseded);
        }
        let proposal_id = proposal_id.clone();
        if !self.pairing.as_ref().is_some_and(Link::is_ready) {
            return Err(ClientError::NotReady);
        }
        let topic = self.session.pairing_topic.clone();
        self.send_on(
            &topic,
            &ClientMessage::Reject(RejectPayload {
                proposal_id,
                code,
                message: message.into(),
            }),
        )
        .await?;
        self.handshake = Handshake::Idle;
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
        self.send_with_id_on(&topic, id, &ClientMessage::Request(payload), true)
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
        self.send(&ClientMessage::Response(payload)).await?;
        Ok(())
    }

    /// Gracefully disconnect.
    ///
    /// See [`Client::session_delete`] for how the peer is notified.
    pub async fn disconnect(&mut self, reason: impl Into<String>, code: u32) -> Result<()> {
        self.end_session(ClientMessage::Disconnect(DisconnectPayload {
            reason: reason.into(),
            code,
            message: String::new(),
        }))
        .await
    }

    /// Tell the peer the session was deleted, then close.
    ///
    /// The local client is closed even when the peer cannot be notified, for
    /// example because the link is not ready; the notification error is
    /// returned after the teardown. The notification is written once and not
    /// retransmitted, since nothing is left to retransmit it once the client
    /// is closed, so it produces no `Delivered` or `Failed` event.
    pub async fn session_delete(&mut self, code: u32, message: impl Into<String>) -> Result<()> {
        self.end_session(ClientMessage::SessionDelete(SessionDeletePayload {
            code,
            message: message.into(),
        }))
        .await
    }

    /// Send a final, untracked message and close the client.
    async fn end_session(&mut self, message: ClientMessage) -> Result<()> {
        let result = self.send_final(&message).await;
        self.session.state = SessionState::Disconnected;
        self.close(Terminal::Closed);
        result
    }

    async fn send_final(&mut self, message: &ClientMessage) -> Result<()> {
        if let Some(error) = self.terminal_error() {
            return Err(error);
        }
        self.ensure_session_ready()?;
        let topic = self.active_topic().clone();
        let id = random::id()?;
        self.send_with_id_on(&topic, id, message, false).await
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
