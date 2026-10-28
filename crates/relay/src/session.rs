use crate::limits::{ConnectionPermit, OutboundBudget, OutboundCharge};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use wallet_session_core::{did::DidKey, frame::RelayFrame};

pub use wallet_session_core::connection::Role;

/// A connected peer's outbound channel.
#[derive(Clone)]
pub struct PeerHandle {
    /// `did:key` of the peer.
    pub identity: DidKey,

    /// Channel to the peer's writer task.
    pub tx: mpsc::Sender<Outbound>,

    /// Bytes this connection may hold in its queue and backlog. It belongs
    /// to the connection: frames a reconnect or a replacement inherits are
    /// charged to the new connection's budget instead.
    pub budget: Arc<OutboundBudget>,
}

/// A frame in a peer's outbound queue.
#[derive(Debug)]
pub struct Outbound {
    /// The frame to write.
    pub frame: RelayFrame,

    /// When the frame entered the queue.
    pub queued_at: Instant,

    /// The frame's share of its peer's outbound budget, given back once the
    /// writer is done with it. Relay control frames carry none: they are
    /// small, the queue capacity bounds their number, and a full budget must
    /// not drop a `session_ready` or `peer_disconnected`.
    _charge: Option<OutboundCharge>,
}

impl Outbound {
    /// A frame entering the queue now, holding `charge`.
    pub(crate) fn new(frame: RelayFrame, charge: Option<OutboundCharge>) -> Self {
        Self {
            frame,
            queued_at: Instant::now(),
            _charge: charge,
        }
    }
}

/// Bytes of `frame`'s JSON text, which is what the writer sends, or `None`
/// if it cannot be encoded.
fn encoded_len(frame: &RelayFrame) -> Option<usize> {
    /// Counts the bytes written to it.
    struct Counter(usize);

    impl std::io::Write for Counter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, frame).ok()?;
    Some(counter.0)
}

/// Outcome of binding a connection to a topic slot.
#[derive(Debug)]
pub enum Registration {
    /// Slot filled; counterpart not connected yet.
    Waiting,

    /// Slot filled and counterpart present.
    BothReady,

    /// Slot already occupied by another connection.
    RoleTaken(Role),
}

/// Session operation failures.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session lock poisoned")]
    LockPoisoned,

    #[error("counterpart not connected")]
    NoCounterpart,

    #[error("identity connection limit reached")]
    IdentityLimit,
}

/// The two peer slots bound to one topic, shared by both peers' connections.
#[derive(Default)]
pub struct Session {
    slots: Mutex<Slots>,
}

/// A role slot: either a live peer or a disconnected peer's reservation.
enum Slot {
    Connected {
        peer: PeerHandle,

        /// The connection's per-identity permit, released when the slot stops
        /// being a live connection. A same-identity replacement inherits it,
        /// so the per-identity cap cannot refuse a documented takeover (§3).
        permit: Option<ConnectionPermit>,

        /// Frames not yet handed to the outbound queue. They keep the expiry
        /// they were buffered with, and are charged to the peer's budget.
        backlog: VecDeque<BufferedFrame>,
    },
    Disconnected {
        identity: DidKey,
        deadline: Instant,
        buffered: VecDeque<BufferedFrame>,

        /// What `buffered` holds, as large as a connection's budget.
        budget: Arc<OutboundBudget>,
    },
}

impl Slot {
    /// Frames held for this slot's peer: its backlog while connected, its
    /// buffer while disconnected.
    fn held_frames(&mut self) -> &mut VecDeque<BufferedFrame> {
        match self {
            Slot::Connected { backlog, .. } => backlog,
            Slot::Disconnected { buffered, .. } => buffered,
        }
    }
}

/// A frame held for a peer, with its expiry time.
struct BufferedFrame {
    frame: RelayFrame,
    expires_at: Instant,

    /// Its encoded size, charged to the budget of the slot holding it.
    charge: OutboundCharge,
}

/// Drop the frames whose TTL has passed.
fn prune_expired(frames: &mut VecDeque<BufferedFrame>, now: Instant) {
    frames.retain(|entry| entry.expires_at > now);
}

/// Charge `bytes` to `budget` for a frame joining `frames`, dropping the
/// oldest of them if that makes room (spec §3: on overflow the oldest frame
/// is discarded).
///
/// Every frame in `frames` is charged to `budget`. When the frame would not
/// fit even with all of them gone, because the rest of the budget is held by
/// the outbound queue, nothing is dropped and `None` is returned.
fn make_room(
    frames: &mut VecDeque<BufferedFrame>,
    budget: &Arc<OutboundBudget>,
    bytes: usize,
) -> Option<OutboundCharge> {
    // Charges are only taken under the session lock, which the caller holds,
    // so the queue's share can only shrink while this runs.
    let held_here: usize = frames.iter().map(|entry| entry.charge.bytes()).sum();
    let queued = budget.held().saturating_sub(held_here);
    if queued.saturating_add(bytes) > budget.capacity() {
        return None;
    }
    loop {
        if let Some(charge) = budget.try_charge(bytes) {
            return Some(charge);
        }
        frames.pop_front()?;
    }
}

/// Move `frames` to `budget`, their new owner's, keeping the newest that fit.
///
/// The budget they were charged to belonged to the reservation or the
/// connection being taken over.
fn recharge(frames: &mut VecDeque<BufferedFrame>, budget: &Arc<OutboundBudget>) {
    let mut kept = VecDeque::with_capacity(frames.len());
    while let Some(mut entry) = frames.pop_back() {
        match budget.try_charge(entry.charge.bytes()) {
            Some(charge) => {
                entry.charge = charge;
                kept.push_front(entry);
            }
            None => {
                log::debug!(
                    "dropping {} inherited frame(s) over the outbound budget",
                    frames.len() + 1
                );
                frames.clear();
            }
        }
    }
    *frames = kept;
}

/// Hand a frame to a connected peer's queue, dropping it if the queue is full.
fn enqueue(peer: &PeerHandle, outbound: Outbound) -> Result<(), SessionError> {
    match peer.tx.try_send(outbound) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            log::debug!("dropping frame for peer whose outbound queue is full");
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(SessionError::NoCounterpart),
    }
}

/// The two role slots for one topic.
#[derive(Default)]
struct Slots {
    proposer: Option<Slot>,
    responder: Option<Slot>,
}

impl Slots {
    fn get(&self, role: Role) -> &Option<Slot> {
        match role {
            Role::Proposer => &self.proposer,
            Role::Responder => &self.responder,
        }
    }

    fn get_mut(&mut self, role: Role) -> &mut Option<Slot> {
        match role {
            Role::Proposer => &mut self.proposer,
            Role::Responder => &mut self.responder,
        }
    }

    fn is_connected(&self, role: Role) -> bool {
        matches!(self.get(role), Some(Slot::Connected { .. }))
    }

    /// Drop the frames held for `role`'s peer: they were sent by a
    /// counterpart whose reservation has expired.
    fn discard_held_frames(&mut self, role: Role) {
        if let Some(slot) = self.get_mut(role) {
            let held = slot.held_frames();
            if !held.is_empty() {
                log::debug!(
                    "discarding {} frame(s) from an expired counterpart",
                    held.len()
                );
                held.clear();
            }
        }
    }
}

/// Where a frame from one peer would go if it were routed now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counterpart {
    /// The counterpart is connected: the frame goes to its queue.
    Connected,

    /// The counterpart's slot is reserved while it reconnects: the frame is
    /// buffered for it, if buffering is enabled.
    Reserved,

    /// There is no counterpart: the frame is dropped.
    Absent,
}

/// Result of expiring a reservation.
pub(crate) struct Expiry {
    /// Whether the session now has no peers left.
    pub empty: bool,
}

/// Result of one [`Session::drain_backlog`] step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Drain {
    /// Frames handed to the outbound queue.
    pub delivered: usize,

    /// Whether this connection has nothing left to drain: the backlog is
    /// empty, or the slot or its queue no longer belongs to the connection.
    /// A connection's backlog never grows back once empty, since frames are
    /// only queued behind a non-empty one.
    pub finished: bool,
}

impl Session {
    /// Acquire the slot lock
    fn lock(&self) -> Result<MutexGuard<'_, Slots>, SessionError> {
        self.slots.lock().map_err(|_| SessionError::LockPoisoned)
    }

    /// What a frame from `from` would reach if [`Session::route`]d now.
    ///
    /// The answer can be stale by the time a frame is routed; it is meant for
    /// deciding what a frame costs before it is parsed, not where it goes.
    pub(crate) fn counterpart(&self, from: Role) -> Result<Counterpart, SessionError> {
        Ok(match self.lock()?.get(from.counterpart()) {
            Some(Slot::Connected { .. }) => Counterpart::Connected,
            Some(Slot::Disconnected { .. }) => Counterpart::Reserved,
            None => Counterpart::Absent,
        })
    }

    /// Bind a peer to its role slot.
    ///
    /// A same-identity reservation is reclaimed. A same-identity live
    /// connection is replaced: the relay may not yet have noticed that the old
    /// socket is half-open, and the peer must be able to reconnect without
    /// waiting for the pong or idle deadline. The replaced connection's channel
    /// is closed once its handle is dropped here, which makes that connection
    /// shut down. A different identity gets [`Registration::RoleTaken`] while
    /// the slot is live or reserved.
    ///
    /// When the counterpart is already connected, `ready` is enqueued for both
    /// peers while the slot lock is held, so it precedes anything
    /// [`Session::route`] can send afterwards. Frames buffered for this
    /// identity while it was disconnected, or not yet handed to a replaced
    /// connection, become the slot's backlog with their original expiry; hand
    /// them over with [`Session::drain_backlog`]. An expired reservation
    /// claimed by another identity keeps no frames, and the frames its previous
    /// owner sent to the counterpart are discarded.
    ///
    /// The backlog is charged to the new connection's budget, newest first; a
    /// replaced connection keeps only the frames already in its own queue.
    ///
    /// `permit` is the connection's per-identity permit. A registration that
    /// replaces this identity's own live connection inherits that connection's
    /// permit instead, so it is accepted with `None`: the per-identity cap must
    /// not refuse the documented takeover (§3). Any other registration is
    /// refused with [`SessionError::IdentityLimit`] when it brings no permit.
    pub(crate) fn register(
        &self,
        role: Role,
        peer: PeerHandle,
        ready: &RelayFrame,
        permit: Option<ConnectionPermit>,
    ) -> Result<Registration, SessionError> {
        let mut slots = self.lock()?;
        let now = Instant::now();

        match slots.get(role) {
            Some(Slot::Connected { peer: current, .. }) if current.identity != peer.identity => {
                return Ok(Registration::RoleTaken(role));
            }
            Some(Slot::Disconnected {
                identity, deadline, ..
            }) if now < *deadline && *identity != peer.identity => {
                return Ok(Registration::RoleTaken(role));
            }
            _ => {}
        }

        let inherits = matches!(
            slots.get(role),
            Some(Slot::Connected { peer: current, permit: Some(_), .. })
                if current.identity == peer.identity
        );
        if permit.is_none() && !inherits {
            return Err(SessionError::IdentityLimit);
        }

        let previous = slots.get_mut(role).take();
        let (mut backlog, permit) = match previous {
            // A reservation reclaimed by the same identity keeps its frames,
            // whether or not the grace window has passed.
            Some(Slot::Disconnected {
                identity, buffered, ..
            }) if identity == peer.identity => (buffered, permit),
            // An expired reservation claimed by another identity must not leak
            // the previous owner's frames, nor deliver what the previous owner
            // sent to the counterpart as if it came from the new one.
            Some(Slot::Disconnected { .. }) => {
                slots.discard_held_frames(role.counterpart());
                (VecDeque::new(), permit)
            }
            Some(Slot::Connected {
                backlog,
                permit: inherited,
                ..
            }) => {
                log::debug!("replacing live connection of {}", peer.identity);
                (backlog, inherited.or(permit))
            }
            None => (VecDeque::new(), permit),
        };
        prune_expired(&mut backlog, now);
        recharge(&mut backlog, &peer.budget);
        if !backlog.is_empty() {
            log::debug!(
                "redelivering {} buffered frame(s) to {}",
                backlog.len(),
                peer.identity
            );
        }

        let both_ready = slots.is_connected(role.counterpart());
        if both_ready {
            if peer
                .tx
                .try_send(Outbound::new(ready.clone(), None))
                .is_err()
            {
                log::warn!("could not enqueue session_ready for {}", peer.identity);
            }
            if let Some(Slot::Connected { peer: other, .. }) = slots.get(role.counterpart())
                && other
                    .tx
                    .try_send(Outbound::new(ready.clone(), None))
                    .is_err()
            {
                log::warn!("could not enqueue session_ready for {}", other.identity);
            }
        }
        *slots.get_mut(role) = Some(Slot::Connected {
            peer,
            permit,
            backlog,
        });

        Ok(if both_ready {
            Registration::BothReady
        } else {
            Registration::Waiting
        })
    }

    /// Hand as much of the slot's backlog to the peer's outbound queue as it
    /// has room for, without waiting.
    ///
    /// Expired frames are dropped, never handed over. What does not fit stays
    /// in the backlog, in order, for a later call once the writer has made
    /// room. Only the connection owning `tx` may drain the slot, so a replaced
    /// connection cannot consume its successor's backlog. A frame keeps its
    /// charge as it moves: the queue and the backlog share one budget.
    pub(crate) fn drain_backlog(
        &self,
        role: Role,
        tx: &mpsc::Sender<Outbound>,
    ) -> Result<Drain, SessionError> {
        let mut slots = self.lock()?;
        let Some(Slot::Connected { peer, backlog, .. }) = slots.get_mut(role) else {
            return Ok(Drain {
                delivered: 0,
                finished: true,
            });
        };
        if !peer.tx.same_channel(tx) {
            return Ok(Drain {
                delivered: 0,
                finished: true,
            });
        }

        prune_expired(backlog, Instant::now());
        let mut delivered = 0usize;
        let finished = loop {
            if backlog.is_empty() {
                break true;
            }
            match tx.try_reserve() {
                Ok(permit) => {
                    if let Some(entry) = backlog.pop_front() {
                        permit.send(Outbound::new(entry.frame, Some(entry.charge)));
                        delivered += 1;
                    }
                }
                Err(mpsc::error::TrySendError::Full(())) => break false,
                Err(mpsc::error::TrySendError::Closed(())) => break true,
            }
        };

        Ok(Drain {
            delivered,
            finished,
        })
    }

    /// Reserve a peer's slot for `grace`, buffering frames addressed to it.
    ///
    /// Only acts if the slot still belongs to the connection owning `tx`, so a
    /// replaced connection tearing down cannot release its successor's slot.
    /// The reservation buffers within a budget as large as the connection's.
    pub(crate) fn disconnect(
        &self,
        role: Role,
        tx: &mpsc::WeakSender<Outbound>,
        grace: Duration,
    ) -> Result<bool, SessionError> {
        let mut slots = self.lock()?;

        let Some(Slot::Connected { peer, .. }) = slots.get(role) else {
            return Ok(false);
        };
        let owns_slot = tx.upgrade().is_some_and(|tx| peer.tx.same_channel(&tx));
        if !owns_slot {
            return Ok(false);
        }

        let identity = peer.identity.clone();
        let budget = Arc::new(OutboundBudget::new(peer.budget.capacity()));

        *slots.get_mut(role) = Some(Slot::Disconnected {
            identity,
            deadline: Instant::now() + grace,
            buffered: VecDeque::new(),
            budget,
        });

        Ok(true)
    }

    /// Clear an expired reservation, notifying the surviving peer.
    pub(crate) fn expire(
        &self,
        role: Role,
        notification: &RelayFrame,
    ) -> Result<Option<Expiry>, SessionError> {
        let mut slots = self.lock()?;

        let expired = matches!(
            slots.get(role),
            Some(Slot::Disconnected { deadline, .. }) if Instant::now() >= *deadline
        );
        if !expired {
            return Ok(None);
        }
        *slots.get_mut(role) = None;

        // Frames still held for the survivor came from the peer that just
        // expired: they must not follow `peer_disconnected`, nor a later
        // `session_ready` with another counterpart.
        slots.discard_held_frames(role.counterpart());

        if let Some(Slot::Connected { peer, .. }) = slots.get(role.counterpart())
            && peer
                .tx
                .try_send(Outbound::new(notification.clone(), None))
                .is_err()
        {
            log::warn!(
                "dropping peer_disconnected for {}: outbound queue unavailable",
                peer.identity
            );
        }
        let empty = slots.proposer.is_none() && slots.responder.is_none();

        Ok(Some(Expiry { empty }))
    }

    /// Forward a frame to the counterpart, buffering while it is disconnected.
    ///
    /// Buffered frames expire after `buffer_ttl`; a zero TTL drops them immediately.
    /// A frame queued behind a connected peer's backlog expires the same way.
    ///
    /// Each frame is charged its encoded size to the budget of the slot that
    /// holds it, so a peer that reads slowly has frames dropped rather than
    /// relay memory grown (spec §3). A full buffer or backlog drops its oldest
    /// frames to make room, by count and by bytes; a frame that cannot fit
    /// beside what the outbound queue holds is dropped, like one that finds
    /// the queue full.
    pub(crate) fn route(
        &self,
        from: Role,
        frame: RelayFrame,
        max_buffered: usize,
        buffer_ttl: Duration,
    ) -> Result<(), SessionError> {
        let Some(bytes) = encoded_len(&frame) else {
            log::debug!("dropping a frame that cannot be encoded");
            return Ok(());
        };
        let mut slots = self.lock()?;
        let target = from.counterpart();
        let now = Instant::now();

        if let Some(Slot::Connected { peer, backlog, .. }) = slots.get_mut(target) {
            prune_expired(backlog, now);
            if !backlog.is_empty() {
                while backlog.len() >= max_buffered.max(1) {
                    backlog.pop_front();
                }
                let Some(charge) = make_room(backlog, &peer.budget, bytes) else {
                    log::debug!("dropping frame for peer whose outbound byte budget is full");
                    return Ok(());
                };
                if !backlog.is_empty() {
                    backlog.push_back(BufferedFrame {
                        frame,
                        expires_at: now + buffer_ttl,
                        charge,
                    });
                    return Ok(());
                }
                // Room was made by dropping the whole backlog: nothing is left
                // ahead of the frame, and one left on an empty backlog would
                // never be drained.
                return enqueue(peer, Outbound::new(frame, Some(charge)));
            }
            let Some(charge) = peer.budget.try_charge(bytes) else {
                log::debug!("dropping frame for peer whose outbound byte budget is full");
                return Ok(());
            };
            return enqueue(peer, Outbound::new(frame, Some(charge)));
        }

        match slots.get_mut(target) {
            Some(Slot::Disconnected {
                buffered, budget, ..
            }) => {
                if max_buffered > 0 && !buffer_ttl.is_zero() {
                    prune_expired(buffered, now);
                    if buffered.len() >= max_buffered {
                        buffered.pop_front();
                    }
                    match make_room(buffered, budget, bytes) {
                        Some(charge) => buffered.push_back(BufferedFrame {
                            frame,
                            expires_at: now + buffer_ttl,
                            charge,
                        }),
                        None => log::debug!("dropping frame larger than the reconnect buffer"),
                    }
                }
                Ok(())
            }
            _ => Err(SessionError::NoCounterpart),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connection::RELAY_FRAME_VERSION;
    use crate::limits::{Limiter, RelayLimitsConfig};
    use wallet_session_core::frame::RelayFrameBody;
    use wallet_session_core::message::Topic;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const MAX_BUFFERED: usize = 8;

    /// Buffer TTL used by these tests.
    const BUFFER_TTL: Duration = Duration::from_secs(60);

    /// Outbound queue capacity used by peer handles in these tests.
    const PEER_QUEUE: usize = 8;

    /// Outbound byte budget of peer handles in tests that do not exercise it.
    const PEER_BUDGET: usize = 1024 * 1024;

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([1u8; 32])
    }

    fn peer(seed: u8) -> (PeerHandle, mpsc::Receiver<Outbound>) {
        peer_with(seed, PEER_QUEUE, PEER_BUDGET)
    }

    /// A peer handle with a queue of `frames` and a budget of `bytes`.
    fn peer_with(seed: u8, frames: usize, bytes: usize) -> (PeerHandle, mpsc::Receiver<Outbound>) {
        let (tx, rx) = mpsc::channel(frames);
        (
            PeerHandle {
                identity: DidKey::from_ed25519_bytes([seed; 32]),
                tx,
                budget: Arc::new(OutboundBudget::new(bytes)),
            },
            rx,
        )
    }

    /// Encoded size of a frame, as the writer will send it.
    fn size(frame: &RelayFrame) -> usize {
        encoded_len(frame).expect("encodable frame")
    }

    /// Ids of the frames waiting in a queue, taking them out as a writer would.
    fn take_ids(rx: &mut mpsc::Receiver<Outbound>) -> Vec<String> {
        let mut ids = Vec::new();
        while let Ok(queued) = rx.try_recv() {
            ids.push(queued.frame.id);
        }
        ids
    }

    /// Disconnect whichever connection currently owns `role`'s slot.
    fn disconnect_current(
        session: &Session,
        role: Role,
        grace: Duration,
    ) -> Result<bool, SessionError> {
        let tx = match session.lock()?.get(role) {
            Some(Slot::Connected { peer, .. }) => peer.tx.downgrade(),
            _ => return Ok(false),
        };
        session.disconnect(role, &tx, grace)
    }

    fn frame(topic: &Topic) -> RelayFrame {
        RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "frame-id".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::Message {
                payload: "ciphertext".to_owned(),
            },
        }
    }

    fn ready(topic: &Topic) -> RelayFrame {
        RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "ready".to_owned(),
            topic: topic.clone(),
            body: RelayFrameBody::SessionReady,
        }
    }

    /// The control frame an expiry queues for the surviving peer.
    fn notification() -> RelayFrame {
        RelayFrame {
            v: RELAY_FRAME_VERSION,
            id: "gone".to_owned(),
            topic: topic().expect("topic"),
            body: RelayFrameBody::PeerDisconnected,
        }
    }

    fn frame_with_id(topic: &Topic, id: &str) -> RelayFrame {
        RelayFrame {
            id: id.to_owned(),
            ..frame(topic)
        }
    }

    /// Route a message frame with `id` from the proposer to the responder.
    fn route_id(session: &Session, id: &str) -> Result<(), SessionError> {
        let frame = frame_with_id(&topic().expect("topic"), id);
        session.route(Role::Proposer, frame, MAX_BUFFERED, BUFFER_TTL)
    }

    /// A ready pair whose responder went away while `ids` were sent to it,
    /// with the proposer's queue.
    fn responder_away_with(
        ids: &[&str],
    ) -> Result<(Session, mpsc::Receiver<Outbound>), SessionError> {
        let session = Session::default();
        let (proposer, proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;
        for id in ids {
            route_id(&session, id)?;
        }
        Ok((session, proposer_rx))
    }

    /// Ids a freshly registered peer receives: queued frames, then the backlog.
    ///
    /// Drains in steps like a connection does, emptying the queue in between
    /// as its writer would, so a backlog larger than the queue gets through.
    async fn received_ids(
        session: &Session,
        role: Role,
        tx: &mpsc::Sender<Outbound>,
        rx: &mut mpsc::Receiver<Outbound>,
    ) -> Result<Vec<String>, SessionError> {
        let mut ids = Vec::new();
        loop {
            let drain = session.drain_backlog(role, tx)?;
            ids.extend(take_ids(rx));
            if drain.finished {
                return Ok(ids);
            }
        }
    }

    fn register(
        session: &Session,
        role: Role,
        peer: PeerHandle,
    ) -> Result<Registration, SessionError> {
        let permit = permit(&peer.identity);
        session.register(role, peer, &ready(&topic().expect("topic")), permit)
    }

    /// A permit for `identity`, from a limiter that is never shared: these
    /// tests do not exercise the per-identity cap.
    fn permit(identity: &DidKey) -> Option<ConnectionPermit> {
        Arc::new(Limiter::new(RelayLimitsConfig::default())).acquire_identity(identity)
    }

    fn key(seed: u8) -> DidKey {
        DidKey::from_ed25519_bytes([seed; 32])
    }

    #[test]
    fn second_registration_signals_both_ready() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        assert!(matches!(
            register(&session, Role::Proposer, proposer)?,
            Registration::Waiting
        ));
        assert!(matches!(
            register(&session, Role::Responder, responder)?,
            Registration::BothReady
        ));
        Ok(())
    }

    #[test]
    fn duplicate_role_is_rejected() -> TestResult {
        let session = Session::default();
        let (first, _) = peer(1);
        let (second, _) = peer(2);
        register(&session, Role::Proposer, first)?;
        assert!(matches!(
            register(&session, Role::Proposer, second)?,
            Registration::RoleTaken(Role::Proposer)
        ));
        Ok(())
    }

    #[test]
    fn route_delivers_to_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;

        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;

        assert!(matches!(
            responder_rx.try_recv()?.frame.body,
            RelayFrameBody::SessionReady
        ));
        let received = responder_rx.try_recv()?.frame;
        assert!(matches!(received.body, RelayFrameBody::Message { .. }));
        Ok(())
    }

    #[test]
    fn route_without_counterpart_errors() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        register(&session, Role::Proposer, proposer)?;

        assert!(matches!(
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL),
            Err(SessionError::NoCounterpart)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn counterpart_follows_the_other_slot() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        register(&session, Role::Proposer, proposer)?;
        assert_eq!(session.counterpart(Role::Proposer)?, Counterpart::Absent);

        let (responder, _) = peer(2);
        register(&session, Role::Responder, responder)?;
        assert_eq!(session.counterpart(Role::Proposer)?, Counterpart::Connected);
        assert_eq!(
            session.counterpart(Role::Responder)?,
            Counterpart::Connected
        );

        let grace = Duration::from_secs(10);
        disconnect_current(&session, Role::Responder, grace)?;
        assert_eq!(session.counterpart(Role::Proposer)?, Counterpart::Reserved);

        tokio::time::advance(grace).await;
        session.expire(Role::Responder, &notification())?;
        assert_eq!(session.counterpart(Role::Proposer)?, Counterpart::Absent);
        Ok(())
    }

    #[test]
    fn route_drops_frames_when_outbound_queue_is_full() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;

        // bounded queue only holds PEER_QUEUE frames; extra frames are dropped.
        for _ in 0..PEER_QUEUE + 3 {
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        }

        let mut delivered = 0;
        while responder_rx.try_recv().is_ok() {
            delivered += 1;
        }
        assert_eq!(delivered, PEER_QUEUE);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_buffers_and_same_identity_reclaims() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;

        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        // frames to the disconnected peer are buffered, not dropped
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        assert_eq!(responder_rx.try_recv()?.frame.id, "ready");
        assert!(responder_rx.try_recv().is_err());

        // same identity reconnects within grace and receives session_ready,
        // then the buffer
        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        let registration = register(&session, Role::Responder, responder)?;
        assert!(matches!(registration, Registration::BothReady));
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "frame-id"]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reclaim_with_different_identity_is_rejected() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let (impostor, _) = peer(3);
        assert!(matches!(
            register(&session, Role::Responder, impostor)?,
            Registration::RoleTaken(Role::Responder)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expired_buffered_frames_are_not_redelivered() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let ttl = Duration::from_secs(5);
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, ttl)?;
        tokio::time::advance(Duration::from_secs(6)).await;
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, ttl)?;

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        let ids = received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?;
        assert_eq!(
            ids,
            ["ready", "frame-id"],
            "only the unexpired frame is redelivered"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_drops_oldest() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        for _ in 0..3 {
            session.route(Role::Proposer, frame(&topic()?), 2, BUFFER_TTL)?;
        }

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        let ids = received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?;
        assert_eq!(ids, ["ready", "frame-id", "frame-id"]);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expire_reports_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        assert!(session.expire(Role::Responder, &notification())?.is_none());

        tokio::time::advance(Duration::from_secs(11)).await;
        let expiry = session
            .expire(Role::Responder, &notification())?
            .expect("expired");
        assert!(!expiry.empty);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expire_notifies_the_survivor_within_the_transition() -> TestResult {
        let session = Session::default();
        let (proposer, mut proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(1))?;
        assert_eq!(proposer_rx.try_recv()?.frame.id, "ready");

        tokio::time::advance(Duration::from_secs(2)).await;
        let notice = notification();
        assert!(session.expire(Role::Responder, &notice)?.is_some());

        let queued = proposer_rx.try_recv()?.frame;
        assert!(
            matches!(queued.body, RelayFrameBody::PeerDisconnected),
            "expected the disconnect in the survivor's queue, got {:?}",
            queued.body
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expire_prunes_when_both_gone() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        register(&session, Role::Proposer, proposer)?;
        disconnect_current(&session, Role::Proposer, Duration::from_secs(10))?;

        tokio::time::advance(Duration::from_secs(11)).await;
        let expiry = session
            .expire(Role::Proposer, &notification())?
            .expect("expired");
        assert!(expiry.empty);
        Ok(())
    }

    #[test]
    fn poisoned_session_lock_is_reported() -> TestResult {
        let session = Session::default();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = session.slots.lock();
            panic!("poison the session lock");
        }));
        std::panic::set_hook(previous_hook);
        assert!(outcome.is_err());

        assert!(matches!(
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL),
            Err(SessionError::LockPoisoned)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn session_ready_is_enqueued_before_frames_routed_after_register() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;

        // Nothing else can slip in between registration and the first route.
        session.route(
            Role::Proposer,
            frame_with_id(&topic()?, "m1"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;

        assert_eq!(responder_rx.try_recv()?.frame.id, "ready");
        assert_eq!(responder_rx.try_recv()?.frame.id, "m1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn frames_routed_during_reconnect_queue_behind_the_backlog() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        for id in ["old1", "old2"] {
            session.route(
                Role::Proposer,
                frame_with_id(&topic, id),
                MAX_BUFFERED,
                BUFFER_TTL,
            )?;
        }

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;

        // The counterpart sends before the new connection has drained its backlog.
        for id in ["new1", "new2"] {
            session.route(
                Role::Proposer,
                frame_with_id(&topic, id),
                MAX_BUFFERED,
                BUFFER_TTL,
            )?;
        }

        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "old1", "old2", "new1", "new2"]
        );

        // Once drained, frames go straight to the queue again.
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "live"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;
        assert_eq!(responder_rx.try_recv()?.frame.id, "live");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn backlog_larger_than_the_queue_is_delivered_in_order() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        let total = PEER_QUEUE * 3;
        for i in 0..total {
            session.route(
                Role::Proposer,
                frame_with_id(&topic, &format!("m{i:02}")),
                total,
                BUFFER_TTL,
            )?;
        }

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;

        // One step fills the queue and leaves the rest for later.
        let first = session.drain_backlog(Role::Responder, &tx)?;
        assert_eq!(
            first,
            Drain {
                delivered: PEER_QUEUE - 1,
                finished: false,
            },
            "session_ready holds one slot of the queue"
        );

        let mut ids = take_ids(&mut responder_rx);
        ids.extend(received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?);

        let mut expected = vec!["ready".to_owned()];
        expected.extend((0..total).map(|i| format!("m{i:02}")));
        assert_eq!(ids, expected);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn drain_backlog_stops_when_slot_was_taken_over() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        // The first reconnect dies before it drains anything.
        let (first, mut first_rx) = peer(2);
        let first_tx = first.tx.clone();
        register(&session, Role::Responder, first)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        let (second, mut second_rx) = peer(2);
        let second_tx = second.tx.clone();
        register(&session, Role::Responder, second)?;

        // The stale connection finally gets to run.
        assert_eq!(
            received_ids(&session, Role::Responder, &first_tx, &mut first_rx).await?,
            ["ready"],
            "a stale connection must not consume the new connection's backlog"
        );
        assert_eq!(
            received_ids(&session, Role::Responder, &second_tx, &mut second_rx).await?,
            ["ready", "frame-id"]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn same_identity_replaces_live_connection() -> TestResult {
        let session = Session::default();
        let (proposer, mut proposer_rx) = peer(1);
        let (old, mut old_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, old)?;
        assert_eq!(proposer_rx.try_recv()?.frame.id, "ready");

        // Same identity, new connection, while the old one is still registered.
        let (new, mut new_rx) = peer(2);
        let new_tx = new.tx.clone();
        assert!(matches!(
            register(&session, Role::Responder, new)?,
            Registration::BothReady
        ));

        // The counterpart sees the peer come back.
        assert_eq!(proposer_rx.try_recv()?.frame.id, "ready");

        // Routing now reaches the new connection only.
        session.route(
            Role::Proposer,
            frame_with_id(&topic()?, "m1"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;
        assert_eq!(
            received_ids(&session, Role::Responder, &new_tx, &mut new_rx).await?,
            ["ready", "m1"]
        );

        // The replaced connection's queue is closed once its old frames drain.
        while old_rx.try_recv().is_ok() {}
        assert!(matches!(
            old_rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn different_identity_cannot_replace_live_connection() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (owner, mut owner_rx) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, owner)?;

        let (impostor, _impostor_rx) = peer(3);
        assert!(matches!(
            register(&session, Role::Responder, impostor)?,
            Registration::RoleTaken(Role::Responder)
        ));

        // The owner is untouched and still receives frames.
        session.route(
            Role::Proposer,
            frame_with_id(&topic()?, "m1"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;
        assert_eq!(owner_rx.try_recv()?.frame.id, "ready");
        assert_eq!(owner_rx.try_recv()?.frame.id, "m1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn replaced_connection_cannot_disconnect_its_successor() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (old, _old_rx) = peer(2);
        let old_weak = old.tx.downgrade();
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, old)?;

        let (new, mut new_rx) = peer(2);
        let new_tx = new.tx.clone();
        register(&session, Role::Responder, new)?;

        // The old connection finishes tearing down after being replaced.
        assert!(!session.disconnect(Role::Responder, &old_weak, Duration::from_secs(10))?);

        // The successor still owns the slot: frames reach it, not a buffer.
        session.route(
            Role::Proposer,
            frame_with_id(&topic()?, "m1"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;
        assert_eq!(
            received_ids(&session, Role::Responder, &new_tx, &mut new_rx).await?,
            ["ready", "m1"]
        );

        // And an expiry the old teardown might have scheduled is a no-op.
        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(session.expire(Role::Responder, &notification())?.is_none());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_inherits_undelivered_backlog() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "old"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;

        // First reconnect has not drained its backlog when a second replaces it.
        let (first, _first_rx) = peer(2);
        register(&session, Role::Responder, first)?;
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "new"),
            MAX_BUFFERED,
            BUFFER_TTL,
        )?;

        let (second, mut second_rx) = peer(2);
        let second_tx = second.tx.clone();
        register(&session, Role::Responder, second)?;

        assert_eq!(
            received_ids(&session, Role::Responder, &second_tx, &mut second_rx).await?,
            ["ready", "old", "new"],
            "frames not yet handed to the replaced connection must not be lost"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn drain_backlog_counts_the_frames_it_hands_over() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        for _ in 0..3 {
            session.route(Role::Proposer, frame(&topic), MAX_BUFFERED, BUFFER_TTL)?;
        }

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;

        assert_eq!(
            session.drain_backlog(Role::Responder, &tx)?.delivered,
            3,
            "the count is what the caller owes the peer in inbound budget"
        );
        assert_eq!(
            session.drain_backlog(Role::Responder, &tx)?.delivered,
            0,
            "an empty backlog hands over nothing"
        );
        let _ = responder_rx.try_recv()?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_inherits_the_identity_permit() -> TestResult {
        let limiter = Arc::new(Limiter::new(RelayLimitsConfig {
            max_connections_per_identity: 1,
            ..RelayLimitsConfig::default()
        }));
        let session = Session::default();

        let (first, _) = peer(1);
        let permit = limiter.acquire_identity(&key(1)).expect("first permit");
        session.register(Role::Proposer, first, &ready(&topic()?), Some(permit))?;
        assert!(
            limiter.acquire_identity(&key(1)).is_none(),
            "the slot holds the only permit"
        );

        // The same identity replaces the live connection while at the cap: the
        // replacement carries the incumbent's permit, so no new one is needed.
        let (replacement, _) = peer(1);
        assert!(matches!(
            session.register(Role::Proposer, replacement, &ready(&topic()?), None)?,
            Registration::Waiting
        ));
        assert!(
            limiter.acquire_identity(&key(1)).is_none(),
            "the replacement inherited the incumbent's permit"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn registration_without_a_permit_is_refused() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);

        assert!(matches!(
            session.register(Role::Proposer, proposer, &ready(&topic()?), None),
            Err(SessionError::IdentityLimit)
        ));

        // A reserved slot claimed by its own identity also needs a permit, and
        // a refused registration leaves the reservation in place.
        let (proposer, _) = peer(1);
        session.register(Role::Proposer, proposer, &ready(&topic()?), permit(&key(1)))?;
        disconnect_current(&session, Role::Proposer, Duration::from_secs(10))?;

        let (returning, _) = peer(1);
        assert!(matches!(
            session.register(Role::Proposer, returning, &ready(&topic()?), None),
            Err(SessionError::IdentityLimit)
        ));
        assert!(
            matches!(
                session.lock()?.get(Role::Proposer),
                Some(Slot::Disconnected { .. })
            ),
            "the failed registration must not consume the reservation"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expired_reservation_does_not_leak_frames_to_another_identity() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (original, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, original)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(5))?;

        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;

        // The reservation expires before anyone reconnects.
        tokio::time::advance(Duration::from_secs(6)).await;

        let (other, mut other_rx) = peer(3);
        let other_tx = other.tx.clone();
        assert!(matches!(
            register(&session, Role::Responder, other)?,
            Registration::BothReady
        ));

        assert_eq!(
            received_ids(&session, Role::Responder, &other_tx, &mut other_rx).await?,
            ["ready"],
            "frames buffered for the previous owner must not reach another identity"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expired_reservation_still_redelivers_to_its_owner() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (original, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, original)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(5))?;

        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        tokio::time::advance(Duration::from_secs(6)).await;

        let (reconnect, mut reconnect_rx) = peer(2);
        let tx = reconnect.tx.clone();
        register(&session, Role::Responder, reconnect)?;

        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut reconnect_rx).await?,
            ["ready", "frame-id"],
            "the owner gets its frames back after the reservation expired"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reclaimed_frames_expire_while_waiting_for_the_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let ttl = Duration::from_secs(5);
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, ttl)?;
        disconnect_current(&session, Role::Proposer, Duration::from_secs(60))?;

        // The responder takes its frame back well inside the TTL, but nothing
        // may reach it until its counterpart returns.
        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        assert!(matches!(
            register(&session, Role::Responder, responder)?,
            Registration::Waiting
        ));

        tokio::time::advance(Duration::from_secs(6)).await;
        let (proposer, _proposer_rx) = peer(1);
        assert!(matches!(
            register(&session, Role::Proposer, proposer)?,
            Registration::BothReady
        ));

        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready"],
            "a frame reclaimed before its TTL must not be delivered after it"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn frames_queued_behind_a_backlog_expire_on_their_own_ttl() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        let ttl = Duration::from_secs(5);
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "reclaimed"),
            MAX_BUFFERED,
            ttl,
        )?;

        // The responder returns, but its writer is too slow to take anything.
        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;

        // t=3: queued behind the backlog, expires at t=8.
        tokio::time::advance(Duration::from_secs(3)).await;
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "early"),
            MAX_BUFFERED,
            ttl,
        )?;

        // t=6: "reclaimed" has expired; "late" expires at t=11.
        tokio::time::advance(Duration::from_secs(3)).await;
        session.route(
            Role::Proposer,
            frame_with_id(&topic, "late"),
            MAX_BUFFERED,
            ttl,
        )?;

        tokio::time::advance(Duration::from_secs(3)).await;
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "late"],
            "at t=9 only the frame queued at t=6 is still deliverable"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_keeps_the_expiry_of_inherited_frames() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let ttl = Duration::from_secs(5);
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, ttl)?;

        // The first reconnect takes the frame back but never drains it.
        let (first, _first_rx) = peer(2);
        register(&session, Role::Responder, first)?;

        // Its replacement arrives after the TTL has passed.
        tokio::time::advance(Duration::from_secs(6)).await;
        let (second, mut second_rx) = peer(2);
        let second_tx = second.tx.clone();
        register(&session, Role::Responder, second)?;

        assert_eq!(
            received_ids(&session, Role::Responder, &second_tx, &mut second_rx).await?,
            ["ready"],
            "an inherited frame must not outlive its TTL"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn backlog_expiring_mid_drain_is_not_handed_over() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;

        let topic = topic()?;
        let ttl = Duration::from_secs(5);
        let total = PEER_QUEUE * 2;
        for i in 0..total {
            session.route(
                Role::Proposer,
                frame_with_id(&topic, &format!("m{i:02}")),
                total,
                ttl,
            )?;
        }

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;

        // A slow reader: one step fills the queue, then the writer stalls past
        // the TTL before it makes room for more.
        assert!(!session.drain_backlog(Role::Responder, &tx)?.finished);
        tokio::time::advance(Duration::from_secs(6)).await;

        let mut queued = 0;
        while responder_rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, PEER_QUEUE, "session_ready and the first frames");
        assert_eq!(
            session.drain_backlog(Role::Responder, &tx)?,
            Drain {
                delivered: 0,
                finished: true,
            },
            "the rest of the backlog expired while the writer was stalled"
        );
        assert!(responder_rx.try_recv().is_err());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn counterpart_expiry_discards_the_frames_it_sent() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        disconnect_current(&session, Role::Proposer, Duration::from_secs(1))?;

        // The responder takes its frame back while the proposer is away, and
        // the proposer never returns.
        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(session.expire(Role::Proposer, &notification())?.is_some());

        let (other, _other_rx) = peer(3);
        assert!(matches!(
            register(&session, Role::Proposer, other)?,
            Registration::BothReady
        ));
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["gone", "ready"],
            "frames from an expired counterpart must not follow peer_disconnected"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn claiming_a_lapsed_reservation_discards_what_its_owner_sent() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        disconnect_current(&session, Role::Proposer, Duration::from_secs(1))?;

        // The proposer's grace lapses and another identity takes the role
        // before the expiry is processed.
        tokio::time::advance(Duration::from_secs(2)).await;
        let (other, _other_rx) = peer(3);
        assert!(matches!(
            register(&session, Role::Proposer, other)?,
            Registration::Waiting
        ));

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        assert!(matches!(
            register(&session, Role::Responder, responder)?,
            Registration::BothReady
        ));
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready"],
            "frames the previous proposer sent must not reach the responder as the new one's"
        );
        Ok(())
    }

    #[test]
    fn encoded_len_is_the_text_the_writer_sends() -> TestResult {
        let frame = RelayFrame {
            id: "quote \" backslash \\ newline \n control \u{1}".to_owned(),
            body: RelayFrameBody::Message {
                payload: "é \u{7f} \u{1f} \u{1F600}".to_owned(),
            },
            ..frame(&topic()?)
        };
        assert_eq!(
            encoded_len(&frame),
            Some(serde_json::to_string(&frame)?.len())
        );
        Ok(())
    }

    #[test]
    fn frames_over_the_byte_budget_are_dropped_until_written() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        // Room in the queue for many frames, but bytes for two.
        let (responder, mut responder_rx) = peer_with(2, PEER_QUEUE, 2 * one);
        let budget = Arc::clone(&responder.budget);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;

        for id in ["m1", "m2", "m3"] {
            route_id(&session, id)?;
        }
        assert_eq!(budget.held(), 2 * one, "session_ready is not charged");
        assert_eq!(take_ids(&mut responder_rx), ["ready", "m1", "m2"]);

        // Written frames give their bytes back.
        assert_eq!(budget.held(), 0);
        route_id(&session, "m4")?;
        assert_eq!(take_ids(&mut responder_rx), ["m4"]);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_byte_budget_never_refuses_relay_control_frames() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, mut responder_rx) = peer_with(2, PEER_QUEUE, one);
        let budget = Arc::clone(&responder.budget);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        route_id(&session, "m1")?;
        assert_eq!(budget.held(), budget.capacity());

        // The proposer goes away for good, and another identity takes its role.
        disconnect_current(&session, Role::Proposer, Duration::from_secs(1))?;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(session.expire(Role::Proposer, &notification())?.is_some());
        let (other, _other_rx) = peer(3);
        register(&session, Role::Proposer, other)?;

        assert_eq!(
            take_ids(&mut responder_rx),
            ["ready", "m1", "gone", "ready"],
            "control frames bypass the byte budget"
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn queue_and_backlog_share_one_byte_budget() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let (session, _proposer_rx) = responder_away_with(&["m1", "m2", "m3", "m4"])?;

        // It returns with queue room for session_ready and one frame, and
        // bytes for four frames.
        let (responder, mut responder_rx) = peer_with(2, 2, 4 * one);
        let tx = responder.tx.clone();
        let budget = Arc::clone(&responder.budget);
        register(&session, Role::Responder, responder)?;
        assert_eq!(budget.held(), 4 * one, "charged on reconnect");
        let drain = session.drain_backlog(Role::Responder, &tx)?;
        assert_eq!(drain.delivered, 1);
        assert_eq!(budget.held(), 4 * one, "kept in the queue");

        // A new frame needs room: the oldest backlog frame goes, not the one
        // already queued.
        route_id(&session, "m5")?;
        assert_eq!(budget.held(), 4 * one);
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "m1", "m3", "m4", "m5"]
        );
        assert_eq!(budget.held(), 0, "written frames give their bytes back");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_too_large_beside_the_queue_leaves_the_backlog_alone() -> TestResult {
        let topic = topic()?;
        let one = size(&frame_with_id(&topic, "m1"));
        let (session, _proposer_rx) = responder_away_with(&["m1", "m2"])?;

        let (responder, mut responder_rx) = peer_with(2, 2, 3 * one);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        let drain = session.drain_backlog(Role::Responder, &tx)?;
        assert_eq!(drain.delivered, 1);

        // With one frame queued, this one cannot fit even if the backlog went.
        let large = RelayFrame {
            body: RelayFrameBody::Message {
                payload: "a".repeat(2 * one),
            },
            ..frame_with_id(&topic, "large")
        };
        session.route(Role::Proposer, large, MAX_BUFFERED, BUFFER_TTL)?;
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "m1", "m2"]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_frame_that_displaces_the_whole_backlog_is_queued_directly() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let (session, _proposer_rx) = responder_away_with(&["m1", "m2"])?;

        let (responder, mut responder_rx) = peer_with(2, 2, 2 * one);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        let drain = session.drain_backlog(Role::Responder, &tx)?;
        assert_eq!(drain.delivered, 1);

        // The writer takes session_ready, which frees a queue slot but no bytes.
        assert_eq!(responder_rx.try_recv()?.frame.id, "ready");

        // Room for m3 means dropping m2, the whole backlog. A frame left on an
        // empty backlog would never be drained, so m3 goes to the queue.
        route_id(&session, "m3")?;
        let drain = session.drain_backlog(Role::Responder, &tx)?;
        assert_eq!(
            drain,
            Drain {
                delivered: 0,
                finished: true,
            }
        );
        assert_eq!(take_ids(&mut responder_rx), ["m1", "m3"]);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_buffer_is_capped_by_bytes_dropping_the_oldest() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer_with(2, PEER_QUEUE, 2 * one);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        disconnect_current(&session, Role::Responder, Duration::from_secs(10))?;
        for id in ["m1", "m2", "m3"] {
            route_id(&session, id)?;
        }
        let reserved = match session.lock()?.get(Role::Responder) {
            Some(Slot::Disconnected { budget, .. }) => budget.held(),
            _ => 0,
        };
        assert_eq!(
            reserved,
            2 * one,
            "the reservation is as large as the connection's budget"
        );

        let (responder, mut responder_rx) = peer(2);
        let tx = responder.tx.clone();
        let budget = Arc::clone(&responder.budget);
        register(&session, Role::Responder, responder)?;
        assert_eq!(budget.held(), 2 * one, "moved to the new budget");
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "m2", "m3"]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_reconnect_keeps_the_newest_frames_its_budget_holds() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let (session, _proposer_rx) = responder_away_with(&["m1", "m2", "m3"])?;

        // A connection with a smaller budget than the reservation it reclaims.
        let (responder, mut responder_rx) = peer_with(2, PEER_QUEUE, 2 * one);
        let tx = responder.tx.clone();
        register(&session, Role::Responder, responder)?;
        assert_eq!(
            received_ids(&session, Role::Responder, &tx, &mut responder_rx).await?,
            ["ready", "m2", "m3"]
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn replacement_takes_the_backlog_onto_its_own_budget() -> TestResult {
        let one = size(&frame_with_id(&topic()?, "m1"));
        let (session, _proposer_rx) = responder_away_with(&["m1", "m2", "m3"])?;

        // The first reconnect queues session_ready and one frame.
        let (first, _first_rx) = peer_with(2, 2, PEER_BUDGET);
        let first_tx = first.tx.clone();
        let first_budget = Arc::clone(&first.budget);
        register(&session, Role::Responder, first)?;
        let drain = session.drain_backlog(Role::Responder, &first_tx)?;
        assert_eq!(drain.delivered, 1);
        assert_eq!(first_budget.held(), 3 * one);

        // Its replacement takes the backlog; the queued frame stays behind.
        let (second, mut second_rx) = peer(2);
        let second_tx = second.tx.clone();
        let second_budget = Arc::clone(&second.budget);
        register(&session, Role::Responder, second)?;
        assert_eq!(first_budget.held(), one);
        assert_eq!(second_budget.held(), 2 * one);
        assert_eq!(
            received_ids(&session, Role::Responder, &second_tx, &mut second_rx).await?,
            ["ready", "m2", "m3"]
        );
        Ok(())
    }
}
