use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;
use wallet_session_core::message::Topic;

use crate::session::{PeerHandle, Registration, Role, Session, SessionError};

/// Directory of live sessions, keyed by topic.
///
/// The registry only handles session lookup and peer registration; routing and
/// slot bookkeeping live on [`Session`].
#[derive(Default)]
pub struct Registry {
    sessions: Mutex<HashMap<Topic, Arc<Session>>>,
}

impl Registry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquire the sessions lock, reporting a poisoned lock.
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<Topic, Arc<Session>>>, RegistryError> {
        self.sessions
            .lock()
            .map_err(|_| RegistryError::LockPoisoned)
    }

    /// Bind a peer to its topic/role slot, returning the shared session.
    ///
    /// Creates the topic's session on first registration. The registry lock is
    /// released before locking the session, so the two locks are never nested.
    pub fn register(
        &self,
        topic: &Topic,
        role: Role,
        peer: PeerHandle,
    ) -> Result<(Arc<Session>, Registration), RegistryError> {
        let identity = peer.identity.clone();
        let (session, created) = {
            let mut sessions = self.lock()?;
            let created = !sessions.contains_key(topic);
            (sessions.entry(topic.clone()).or_default().clone(), created)
        };
        if created {
            log::debug!("created session for topic {topic}");
        }

        let registration = session.register(role, peer)?;
        log::debug!("registered peer {identity} on topic {topic} as {role:?}");
        Ok((session, registration))
    }

    /// Release a peer's slot, dropping the session once both slots are empty.
    pub fn release(&self, topic: &Topic, role: Role) -> Result<(), RegistryError> {
        let mut sessions = self.lock()?;
        let Some(session) = sessions.get(topic) else {
            return Ok(());
        };
        let session = session.clone();

        if session.unregister(role)? {
            sessions.remove(topic);
            log::debug!("removed empty session for topic {topic}");
        }
        log::debug!("released {role:?} slot on topic {topic}");

        Ok(())
    }
}

/// Registration and teardown failures.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry lock poisoned")]
    LockPoisoned,

    #[error(transparent)]
    Session(#[from] SessionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use wallet_session_core::frame::RelayFrame;
    use tokio::sync::mpsc;

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([0u8; 32])
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

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn first_registration_waits() -> TestResult {
        let registry = Registry::new();
        let (proposer, _) = peer("did:key:proposer");
        let (_, registration) = registry.register(&topic()?, Role::Proposer, proposer)?;
        assert!(matches!(registration, Registration::Waiting));
        Ok(())
    }

    #[test]
    fn second_registration_signals_both_ready() -> TestResult {
        let registry = Registry::new();
        let (proposer, _) = peer("did:key:proposer");
        let (responder, _) = peer("did:key:responder");
        let topic = topic()?;
        let (_, first) = registry.register(&topic, Role::Proposer, proposer)?;
        assert!(matches!(first, Registration::Waiting));
        let (_, second) = registry.register(&topic, Role::Responder, responder)?;
        assert!(matches!(second, Registration::BothReady));
        Ok(())
    }

    #[test]
    fn duplicate_role_is_rejected() -> TestResult {
        let registry = Registry::new();
        let (first, _) = peer("did:key:first");
        let (second, _) = peer("did:key:second");
        let topic = topic()?;
        registry.register(&topic, Role::Proposer, first)?;
        let (_, registration) = registry.register(&topic, Role::Proposer, second)?;
        assert!(matches!(
            registration,
            Registration::RoleTaken(Role::Proposer)
        ));
        Ok(())
    }

    #[test]
    fn release_prunes_empty_session() -> TestResult {
        let registry = Registry::new();
        let topic = topic()?;
        let (proposer, _) = peer("did:key:proposer");
        let (first, _) = registry.register(&topic, Role::Proposer, proposer)?;
        registry.release(&topic, Role::Proposer)?;

        let (replacement, _) = peer("did:key:replacement");
        let (second, registration) = registry.register(&topic, Role::Proposer, replacement)?;
        assert!(matches!(registration, Registration::Waiting));
        assert!(!Arc::ptr_eq(&first, &second));
        Ok(())
    }

    #[test]
    fn release_keeps_session_while_peer_remains() -> TestResult {
        let registry = Registry::new();
        let topic = topic()?;
        let (proposer, _) = peer("did:key:proposer");
        let (responder, _) = peer("did:key:responder");
        let (session, _) = registry.register(&topic, Role::Proposer, proposer)?;
        registry.register(&topic, Role::Responder, responder)?;
        registry.release(&topic, Role::Proposer)?;

        let (again, _) = registry.register(&topic, Role::Proposer, peer("did:key:again").0)?;
        assert!(Arc::ptr_eq(&session, &again));
        Ok(())
    }

    #[test]
    fn poisoned_lock_is_reported() -> TestResult {
        let registry = Registry::new();
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.sessions.lock();
            panic!("poison the registry lock");
        }));
        std::panic::set_hook(previous_hook);
        assert!(outcome.is_err());

        let (proposer, _) = peer("did:key:proposer");
        assert!(matches!(
            registry.register(&topic()?, Role::Proposer, proposer),
            Err(RegistryError::LockPoisoned)
        ));
        Ok(())
    }
}
