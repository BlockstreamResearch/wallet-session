use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};

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
    pub tx: mpsc::Sender<RelayFrame>,
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
        backlog: VecDeque<RelayFrame>,
    },
    Disconnected {
        identity: DidKey,
        deadline: Instant,
        buffered: VecDeque<BufferedFrame>,
    },
}

/// A frame buffered for a disconnected peer, with its expiry time.
struct BufferedFrame {
    frame: RelayFrame,
    expires_at: Instant,
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
}

/// Result of expiring a reservation.
pub(crate) struct Expiry {
    /// Whether the session now has no peers left.
    pub empty: bool,

    /// The remaining peer to notify, if any.
    pub counterpart: Option<PeerHandle>,
}

impl Session {
    /// Acquire the slot lock
    fn lock(&self) -> Result<MutexGuard<'_, Slots>, SessionError> {
        self.slots.lock().map_err(|_| SessionError::LockPoisoned)
    }

    /// Bind a peer to its role slot, reclaiming a same-identity reservation.
    ///
    /// When the counterpart is already connected, `ready` is enqueued for both
    /// peers while the slot lock is held, so it precedes anything
    /// [`Session::route`] can send afterwards. Frames buffered for this peer
    /// while it was disconnected become the slot's backlog; hand them over with
    /// [`Session::drain_backlog`].
    pub(crate) fn register(
        &self,
        role: Role,
        peer: PeerHandle,
        ready: &RelayFrame,
    ) -> Result<Registration, SessionError> {
        let mut slots = self.lock()?;
        let now = Instant::now();

        match slots.get(role) {
            Some(Slot::Connected { .. }) => {
                return Ok(Registration::RoleTaken(role));
            }
            Some(Slot::Disconnected {
                identity, deadline, ..
            }) if now < *deadline && *identity != peer.identity => {
                return Ok(Registration::RoleTaken(role));
            }
            _ => {}
        }

        let backlog: VecDeque<RelayFrame> = match slots.get_mut(role).take() {
            Some(Slot::Disconnected { buffered, .. }) => buffered
                .into_iter()
                .filter(|entry| entry.expires_at > now)
                .map(|entry| entry.frame)
                .collect(),
            _ => VecDeque::new(),
        };
        if !backlog.is_empty() {
            log::debug!(
                "redelivering {} buffered frame(s) to {}",
                backlog.len(),
                peer.identity
            );
        }

        let both_ready = slots.is_connected(role.counterpart());
        if both_ready {
            if peer.tx.try_send(ready.clone()).is_err() {
                log::warn!("could not enqueue session_ready for {}", peer.identity);
            }
            if let Some(Slot::Connected { peer: other, .. }) = slots.get(role.counterpart())
                && other.tx.try_send(ready.clone()).is_err()
            {
                log::warn!("could not enqueue session_ready for {}", other.identity);
            }
        }
        *slots.get_mut(role) = Some(Slot::Connected { peer, backlog });

        Ok(if both_ready {
            Registration::BothReady
        } else {
            Registration::Waiting
        })
    }

    /// Hand the slot's backlog to the peer's outbound queue.
    pub(crate) async fn drain_backlog(
        &self,
        role: Role,
        tx: &mpsc::Sender<RelayFrame>,
    ) -> Result<(), SessionError> {
        loop {
            let Ok(permit) = tx.reserve().await else {
                return Ok(());
            };

            let mut slots = self.lock()?;
            let Some(Slot::Connected { peer, backlog }) = slots.get_mut(role) else {
                return Ok(());
            };
            if !peer.tx.same_channel(tx) {
                return Ok(());
            }
            let Some(frame) = backlog.pop_front() else {
                return Ok(());
            };
            permit.send(frame);
        }
    }

    /// Reserve a peer's slot for `grace`, buffering frames addressed to it.
    pub(crate) fn disconnect(&self, role: Role, grace: Duration) -> Result<(), SessionError> {
        let mut slots = self.lock()?;

        let Some(Slot::Connected { peer, .. }) = slots.get(role) else {
            return Ok(());
        };

        let identity = peer.identity.clone();

        *slots.get_mut(role) = Some(Slot::Disconnected {
            identity,
            deadline: Instant::now() + grace,
            buffered: VecDeque::new(),
        });

        Ok(())
    }

    /// Clear an expired reservation, reporting the remaining peer.
    pub(crate) fn expire(&self, role: Role) -> Result<Option<Expiry>, SessionError> {
        let mut slots = self.lock()?;

        let expired = matches!(
            slots.get(role),
            Some(Slot::Disconnected { deadline, .. }) if Instant::now() >= *deadline
        );
        if !expired {
            return Ok(None);
        }
        *slots.get_mut(role) = None;

        let counterpart = match slots.get(role.counterpart()) {
            Some(Slot::Connected { peer, .. }) => Some(peer.clone()),
            _ => None,
        };
        let empty = slots.proposer.is_none() && slots.responder.is_none();

        Ok(Some(Expiry { empty, counterpart }))
    }

    /// Forward a frame to the counterpart, buffering while it is disconnected.
    ///
    /// Buffered frames expire after `buffer_ttl`; a zero TTL drops them immediately.
    pub(crate) fn route(
        &self,
        from: Role,
        frame: RelayFrame,
        max_buffered: usize,
        buffer_ttl: Duration,
    ) -> Result<(), SessionError> {
        let mut slots = self.lock()?;
        let target = from.counterpart();

        if let Some(Slot::Connected { peer, backlog }) = slots.get_mut(target) {
            if !backlog.is_empty() {
                while backlog.len() >= max_buffered.max(1) {
                    backlog.pop_front();
                }
                backlog.push_back(frame);
                return Ok(());
            }
            return match peer.tx.try_send(frame) {
                Ok(()) => Ok(()),
                Err(mpsc::error::TrySendError::Full(_)) => {
                    log::debug!("dropping frame for peer whose outbound queue is full");
                    Ok(())
                }
                Err(mpsc::error::TrySendError::Closed(_)) => Err(SessionError::NoCounterpart),
            };
        }

        match slots.get_mut(target) {
            Some(Slot::Disconnected { buffered, .. }) => {
                if max_buffered > 0 && !buffer_ttl.is_zero() {
                    if buffered.len() >= max_buffered {
                        buffered.pop_front();
                    }
                    buffered.push_back(BufferedFrame {
                        frame,
                        expires_at: Instant::now() + buffer_ttl,
                    });
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
    use wallet_session_core::frame::RelayFrameBody;
    use wallet_session_core::message::Topic;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const MAX_BUFFERED: usize = 8;

    /// Buffer TTL used by these tests.
    const BUFFER_TTL: Duration = Duration::from_secs(60);

    /// Outbound queue capacity used by peer handles in these tests.
    const PEER_QUEUE: usize = 8;

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([1u8; 32])
    }

    fn peer(seed: u8) -> (PeerHandle, mpsc::Receiver<RelayFrame>) {
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        (
            PeerHandle {
                identity: DidKey::from_ed25519_bytes([seed; 32]),
                tx,
            },
            rx,
        )
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

    fn frame_with_id(topic: &Topic, id: &str) -> RelayFrame {
        RelayFrame {
            id: id.to_owned(),
            ..frame(topic)
        }
    }

    /// Ids a freshly registered peer receives: queued frames, then the backlog.
    async fn received_ids(
        session: &Session,
        role: Role,
        tx: &mpsc::Sender<RelayFrame>,
        rx: &mut mpsc::Receiver<RelayFrame>,
    ) -> Result<Vec<String>, SessionError> {
        session.drain_backlog(role, tx).await?;
        let mut ids = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            ids.push(frame.id);
        }
        Ok(ids)
    }

    fn register(
        session: &Session,
        role: Role,
        peer: PeerHandle,
    ) -> Result<Registration, SessionError> {
        session.register(role, peer, &ready(&topic().expect("topic")))
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
            responder_rx.try_recv()?.body,
            RelayFrameBody::SessionReady
        ));
        let received = responder_rx.try_recv()?;
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

        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        // frames to the disconnected peer are buffered, not dropped
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED, BUFFER_TTL)?;
        assert_eq!(responder_rx.try_recv()?.id, "ready");
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
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        assert!(session.expire(Role::Responder)?.is_none());

        tokio::time::advance(Duration::from_secs(11)).await;
        let expiry = session.expire(Role::Responder)?.expect("expired");
        assert!(!expiry.empty);
        assert!(expiry.counterpart.is_some());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expire_prunes_when_both_gone() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        register(&session, Role::Proposer, proposer)?;
        session.disconnect(Role::Proposer, Duration::from_secs(10))?;

        tokio::time::advance(Duration::from_secs(11)).await;
        let expiry = session.expire(Role::Proposer)?.expect("expired");
        assert!(expiry.empty);
        assert!(expiry.counterpart.is_none());
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

        assert_eq!(responder_rx.try_recv()?.id, "ready");
        assert_eq!(responder_rx.try_recv()?.id, "m1");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn frames_routed_during_reconnect_queue_behind_the_backlog() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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
        assert_eq!(responder_rx.try_recv()?.id, "live");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn backlog_larger_than_the_queue_is_delivered_in_order() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        register(&session, Role::Proposer, proposer)?;
        register(&session, Role::Responder, responder)?;
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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

        let drain = session.drain_backlog(Role::Responder, &tx);
        let collect = async {
            let mut ids = Vec::new();
            while ids.len() < total + 1 {
                match responder_rx.recv().await {
                    Some(frame) => ids.push(frame.id),
                    None => break,
                }
            }
            ids
        };
        let (drained, ids) = tokio::join!(drain, collect);
        drained?;

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
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        // The first reconnect dies before it drains anything.
        let (first, mut first_rx) = peer(2);
        let first_tx = first.tx.clone();
        register(&session, Role::Responder, first)?;
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

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
}
