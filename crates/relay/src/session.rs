use std::sync::{Mutex, MutexGuard};

use thiserror::Error;
use tokio::sync::mpsc;

use crate::frame::RelayFrame;

/// Role a peer claims on a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Proposer,
    Responder,
}

/// A connected peer's outbound channel.
#[derive(Clone)]
pub struct PeerHandle {
    /// `did:key` of the peer.
    pub identity: String,

    /// Channel to the peer's writer task.
    pub tx: mpsc::UnboundedSender<RelayFrame>,
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

/// The two role slots for one topic.
#[derive(Default)]
struct Slots {
    proposer: Option<PeerHandle>,
    responder: Option<PeerHandle>,
}

impl Session {
    /// Acquire the slot lock
    fn lock(&self) -> Result<MutexGuard<'_, Slots>, SessionError> {
        self.slots.lock().map_err(|_| SessionError::LockPoisoned)
    }

    /// Bind a peer to its role slot
    pub(crate) fn register(
        &self,
        role: Role,
        peer: PeerHandle,
    ) -> Result<Registration, SessionError> {
        let mut slots = self.lock()?;

        if slot(&mut slots, role).is_some() {
            return Ok(Registration::RoleTaken(role));
        }
        *slot(&mut slots, role) = Some(peer);

        let counterpart_present = match role {
            Role::Proposer => slots.responder.is_some(),
            Role::Responder => slots.proposer.is_some(),
        };

        Ok(if counterpart_present {
            Registration::BothReady
        } else {
            Registration::Waiting
        })
    }

    /// Clear a peer's slot on disconnect
    pub(crate) fn unregister(&self, role: Role) -> Result<bool, SessionError> {
        let mut slots = self.lock()?;
        *slot(&mut slots, role) = None;
        Ok(slots.proposer.is_none() && slots.responder.is_none())
    }

    /// Forward a frame to the peer on the other side of the topic.
    pub(crate) fn route(&self, from: Role, frame: RelayFrame) -> Result<(), SessionError> {
        let slots = self.lock()?;
        let counterpart = match from {
            Role::Proposer => slots.responder.as_ref(),
            Role::Responder => slots.proposer.as_ref(),
        };

        counterpart
            .ok_or(SessionError::NoCounterpart)?
            .tx
            .send(frame)
            .map_err(|_| SessionError::NoCounterpart)
    }
}

fn slot(slots: &mut Slots, role: Role) -> &mut Option<PeerHandle> {
    match role {
        Role::Proposer => &mut slots.proposer,
        Role::Responder => &mut slots.responder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::RelayFrameBody;
    use wallet_session_core::message::Topic;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([1u8; 32])
    }

    fn peer(identity: &str) -> (PeerHandle, mpsc::UnboundedReceiver<RelayFrame>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            PeerHandle {
                identity: identity.to_owned(),
                tx,
            },
            rx,
        )
    }

    fn frame(topic: &Topic) -> RelayFrame {
        RelayFrame {
            v: 1,
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
        let (proposer, _) = peer("did:key:proposer");
        let (responder, _) = peer("did:key:responder");
        assert!(matches!(
            session.register(Role::Proposer, proposer)?,
            Registration::Waiting
        ));
        assert!(matches!(
            session.register(Role::Responder, responder)?,
            Registration::BothReady
        ));
        Ok(())
    }

    #[test]
    fn duplicate_role_is_rejected() -> TestResult {
        let session = Session::default();
        let (first, _) = peer("did:key:first");
        let (second, _) = peer("did:key:second");
        session.register(Role::Proposer, first)?;
        assert!(matches!(
            session.register(Role::Proposer, second)?,
            Registration::RoleTaken(Role::Proposer)
        ));
        Ok(())
    }

    #[test]
    fn route_delivers_to_counterpart() -> TestResult {
        let session = Session::default();
        let (proposer, _proposer_rx) = peer("did:key:proposer");
        let (responder, mut responder_rx) = peer("did:key:responder");
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;

        session.route(Role::Proposer, frame(&topic()?))?;

        let received = responder_rx.try_recv()?;
        assert!(matches!(received.body, RelayFrameBody::Message { .. }));
        Ok(())
    }

    #[test]
    fn route_without_counterpart_errors() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer("did:key:proposer");
        session.register(Role::Proposer, proposer)?;

        assert!(matches!(
            session.route(Role::Proposer, frame(&topic()?)),
            Err(SessionError::NoCounterpart)
        ));
        Ok(())
    }

    #[test]
    fn route_errors_when_counterpart_channel_is_closed() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer("did:key:proposer");
        let (responder, responder_rx) = peer("did:key:responder");
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;
        drop(responder_rx);

        assert!(matches!(
            session.route(Role::Proposer, frame(&topic()?)),
            Err(SessionError::NoCounterpart)
        ));
        Ok(())
    }

    #[test]
    fn unregister_clears_slot() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer("did:key:proposer");
        let (responder, _) = peer("did:key:responder");
        session.register(Role::Proposer, proposer)?;
        session.register(Role::Responder, responder)?;
        session.unregister(Role::Proposer)?;

        assert!(matches!(
            session.route(Role::Responder, frame(&topic()?)),
            Err(SessionError::NoCounterpart)
        ));
        Ok(())
    }

    #[test]
    fn unregister_reports_empty_session() -> TestResult {
        let session = Session::default();
        let (proposer, _) = peer("did:key:proposer");
        session.register(Role::Proposer, proposer)?;
        assert!(session.unregister(Role::Proposer)?);
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
            session.route(Role::Proposer, frame(&topic()?)),
            Err(SessionError::LockPoisoned)
        ));
        Ok(())
    }
}
