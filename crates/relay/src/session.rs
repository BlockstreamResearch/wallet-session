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
    Connected(PeerHandle),
    Disconnected {
        identity: DidKey,
        deadline: Instant,
        buffered: VecDeque<RelayFrame>,
    },
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
        matches!(self.get(role), Some(Slot::Connected(_)))
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
    /// Returns the registration result and any frames buffered for this peer
    /// while it was disconnected.
    pub(crate) fn register(
        &self,
        role: Role,
        peer: PeerHandle,
    ) -> Result<(Registration, Vec<RelayFrame>), SessionError> {
        let mut slots = self.lock()?;
        let now = Instant::now();

        match slots.get(role) {
            Some(Slot::Connected(_)) => {
                return Ok((Registration::RoleTaken(role), Vec::new()));
            }
            Some(Slot::Disconnected {
                identity, deadline, ..
            }) if now < *deadline && *identity != peer.identity => {
                return Ok((Registration::RoleTaken(role), Vec::new()));
            }
            _ => {}
        }

        let buffered = match slots.get_mut(role).take() {
            Some(Slot::Disconnected { buffered, .. }) => buffered.into_iter().collect(),
            _ => Vec::new(),
        };
        *slots.get_mut(role) = Some(Slot::Connected(peer));

        let counterpart_connected = slots.is_connected(role.counterpart());
        let registration = if counterpart_connected {
            Registration::BothReady
        } else {
            Registration::Waiting
        };

        Ok((registration, buffered))
    }

    /// Reserve a peer's slot for `grace`, buffering frames addressed to it.
    pub(crate) fn disconnect(&self, role: Role, grace: Duration) -> Result<(), SessionError> {
        let mut slots = self.lock()?;
        let Some(Slot::Connected(peer)) = slots.get(role) else {
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
            Some(Slot::Connected(peer)) => Some(peer.clone()),
            _ => None,
        };
        let empty = slots.proposer.is_none() && slots.responder.is_none();

        Ok(Some(Expiry { empty, counterpart }))
    }

    /// Forward a frame to the counterpart, buffering while it is disconnected.
    pub(crate) fn route(
        &self,
        from: Role,
        frame: RelayFrame,
        max_buffered: usize,
    ) -> Result<(), SessionError> {
        let mut slots = self.lock()?;
        let target = from.counterpart();

        if let Some(Slot::Connected(peer)) = slots.get(target) {
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
                if max_buffered > 0 {
                    if buffered.len() >= max_buffered {
                        buffered.pop_front();
                    }
                    buffered.push_back(frame);
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

    #[test]
    fn second_registration_signals_both_ready() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        assert!(matches!(
            session.register(Role::Proposer, proposer)?.0,
            Registration::Waiting
        ));
        assert!(matches!(
            session.register(Role::Responder, responder)?.0,
            Registration::BothReady
        ));
        Ok(())
    }

    #[test]
    fn duplicate_role_is_rejected() -> TestResult {
        let session = Session::default();
        let (first, _) = peer(1);
        let (second, _) = peer(2);
        session.register(Role::Proposer, first)?;
        assert!(matches!(
            session.register(Role::Proposer, second)?.0,
            Registration::RoleTaken(Role::Proposer)
        ));
        Ok(())
    }

    #[test]
    fn route_delivers_to_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;

        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED)?;

        let received = responder_rx.try_recv()?;
        assert!(matches!(received.body, RelayFrameBody::Message { .. }));
        Ok(())
    }

    #[test]
    fn route_without_counterpart_errors() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        session.register(Role::Proposer, proposer)?;

        assert!(matches!(
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED),
            Err(SessionError::NoCounterpart)
        ));
        Ok(())
    }

    #[test]
    fn route_drops_frames_when_outbound_queue_is_full() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, mut responder_rx) = peer(2);
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;

        // bounded queue only holds PEER_QUEUE frames; extra frames are dropped.
        for _ in 0..PEER_QUEUE + 3 {
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED)?;
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
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;

        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        // frames to the disconnected peer are buffered, not dropped
        session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED)?;
        assert!(responder_rx.try_recv().is_err());

        // same identity reconnects within grace and receives the buffer
        let (responder, _) = peer(2);
        let (registration, buffered) = session.register(Role::Responder, responder)?;
        assert!(matches!(registration, Registration::BothReady));
        assert_eq!(buffered.len(), 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn reclaim_with_different_identity_is_rejected() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        let (impostor, _) = peer(3);
        assert!(matches!(
            session.register(Role::Responder, impostor)?.0,
            Registration::RoleTaken(Role::Responder)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn overflow_drops_oldest() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;
        session.disconnect(Role::Responder, Duration::from_secs(10))?;

        for _ in 0..3 {
            session.route(Role::Proposer, frame(&topic()?), 2)?;
        }

        let (responder, _) = peer(2);
        let (_, buffered) = session.register(Role::Responder, responder)?;
        assert_eq!(buffered.len(), 2);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expire_reports_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;
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
        session.register(Role::Proposer, proposer)?;
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
            session.route(Role::Proposer, frame(&topic()?), MAX_BUFFERED),
            Err(SessionError::LockPoisoned)
        ));
        Ok(())
    }
}
