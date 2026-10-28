use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use thiserror::Error;
use tokio::sync::mpsc;
use wallet_session_core::{frame::RelayFrame, message::Topic};

use crate::limits::ConnectionPermit;
use crate::session::{Outbound, PeerHandle, Registration, Role, Session, SessionError};

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

    /// Bind a peer to its topic/role slot, returning the shared session and any
    /// frames buffered for it while it was disconnected.
    ///
    /// `permit` is the connection's per-identity permit, which the slot then
    /// holds; a same-identity replacement inherits the incumbent's.
    ///
    /// `max_sessions` caps the number of concurrent topics; pass `usize::MAX`
    /// for no limit.
    pub fn register(
        &self,
        topic: &Topic,
        role: Role,
        peer: PeerHandle,
        permit: Option<ConnectionPermit>,
        ready: &RelayFrame,
        max_sessions: usize,
    ) -> Result<(Arc<Session>, Registration), RegistryError> {
        let mut sessions = self.lock()?;

        let created = !sessions.contains_key(topic);
        if created && sessions.len() >= max_sessions {
            log::warn!("rejecting new session for topic {topic}: session limit reached");
            return Err(RegistryError::TooManySessions);
        }
        if created {
            log::debug!("created session for topic {topic}");
        }

        let session = sessions.entry(topic.clone()).or_default().clone();
        let identity = peer.identity.clone();

        let registration = session
            .register(role, peer, ready, permit)
            .inspect_err(|_| {
                if created {
                    sessions.remove(topic);
                }
            })?;

        log::debug!("registered peer {identity} on topic {topic} as {role:?}");

        Ok((session, registration))
    }

    /// Poison the sessions lock, as a panic in a holder would.
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let previous_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.sessions.lock();
            panic!("poison the registry lock");
        }));
        std::panic::set_hook(previous_hook);
        assert!(outcome.is_err());
    }

    /// Number of live sessions.
    ///
    /// Fails once the registry lock is poisoned, after which every
    /// registration fails too; health checks use this to notice.
    pub fn session_count(&self) -> Result<usize, RegistryError> {
        Ok(self.lock()?.len())
    }

    /// Reserve a disconnected peer's slot for `grace`, if `tx` still owns it.
    ///
    /// Returns whether the slot was reserved; `false` means the connection was
    /// already replaced or the session is gone.
    pub fn disconnect(
        &self,
        topic: &Topic,
        role: Role,
        tx: &mpsc::WeakSender<Outbound>,
        grace: Duration,
    ) -> Result<bool, RegistryError> {
        let sessions = self.lock()?;

        let Some(session) = sessions.get(topic) else {
            return Ok(false);
        };

        let reserved = session.disconnect(role, tx, grace)?;
        if reserved {
            log::debug!("reserved {role:?} slot on topic {topic} for {grace:?}");
        }

        Ok(reserved)
    }

    /// Expire a reservation, pruning the session when empty and notifying the
    /// surviving peer with `notification`.
    ///
    /// Returns whether a reservation was expired.
    pub fn expire(
        &self,
        topic: &Topic,
        role: Role,
        notification: &RelayFrame,
    ) -> Result<bool, RegistryError> {
        let mut sessions = self.lock()?;

        let Some(session) = sessions.get(topic) else {
            return Ok(false);
        };

        match session.expire(role, notification)? {
            Some(expiry) => {
                if expiry.empty {
                    sessions.remove(topic);
                    log::debug!("removed empty session for topic {topic}");
                }
                log::debug!("expired {role:?} reservation on topic {topic}");
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// Registration and teardown failures.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry lock poisoned")]
    LockPoisoned,

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("maximum concurrent sessions reached")]
    TooManySessions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    use crate::limits::{Limiter, OutboundBudget, RelayLimitsConfig};

    /// A permit for `identity`, from a limiter that is never shared: these
    /// tests do not exercise the per-identity cap.
    fn permit(identity: &wallet_session_core::did::DidKey) -> Option<ConnectionPermit> {
        Arc::new(Limiter::new(RelayLimitsConfig::default())).acquire_identity(identity)
    }

    /// Register a peer that brings a permit of its own.
    fn register(
        registry: &Registry,
        topic: &Topic,
        role: Role,
        peer: PeerHandle,
        ready: &RelayFrame,
        max_sessions: usize,
    ) -> Result<(Arc<Session>, Registration), RegistryError> {
        let permit = permit(&peer.identity);
        registry.register(topic, role, peer, permit, ready, max_sessions)
    }

    fn topic() -> Result<Topic, wallet_session_core::error::Error> {
        Topic::new([0u8; 32])
    }

    /// Outbound queue capacity used by peer handles in these tests.
    const PEER_QUEUE: usize = 8;

    fn peer(seed: u8) -> (PeerHandle, mpsc::Receiver<Outbound>) {
        let (tx, rx) = mpsc::channel(PEER_QUEUE);
        (
            PeerHandle {
                identity: wallet_session_core::did::DidKey::from_ed25519_bytes([seed; 32]),
                tx,
                budget: Arc::new(OutboundBudget::new(1024 * 1024)),
            },
            rx,
        )
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn notification(topic: &Topic) -> RelayFrame {
        RelayFrame {
            v: 1,
            id: "gone".to_owned(),
            topic: topic.clone(),
            body: wallet_session_core::frame::RelayFrameBody::PeerDisconnected,
        }
    }

    fn ready(topic: &Topic) -> RelayFrame {
        RelayFrame {
            v: 1,
            id: "ready".to_owned(),
            topic: topic.clone(),
            body: wallet_session_core::frame::RelayFrameBody::SessionReady,
        }
    }

    #[test]
    fn first_registration_waits() -> TestResult {
        let registry = Registry::new();
        let (proposer, _) = peer(1);
        let (_, registration) = register(
            &registry,
            &topic()?,
            Role::Proposer,
            proposer,
            &ready(&topic()?),
            usize::MAX,
        )?;
        assert!(matches!(registration, Registration::Waiting));
        Ok(())
    }

    #[test]
    fn second_registration_signals_both_ready() -> TestResult {
        let registry = Registry::new();
        let (proposer, _) = peer(1);
        let (responder, _) = peer(2);
        let topic = topic()?;
        let (_, first) = register(
            &registry,
            &topic,
            Role::Proposer,
            proposer,
            &ready(&topic),
            usize::MAX,
        )?;
        assert!(matches!(first, Registration::Waiting));
        let (_, second) = register(
            &registry,
            &topic,
            Role::Responder,
            responder,
            &ready(&topic),
            usize::MAX,
        )?;
        assert!(matches!(second, Registration::BothReady));
        Ok(())
    }

    #[test]
    fn duplicate_role_is_rejected() -> TestResult {
        let registry = Registry::new();
        let (first, _) = peer(1);
        let (second, _) = peer(2);
        let topic = topic()?;
        register(
            &registry,
            &topic,
            Role::Proposer,
            first,
            &ready(&topic),
            usize::MAX,
        )?;
        let (_, registration) = register(
            &registry,
            &topic,
            Role::Proposer,
            second,
            &ready(&topic),
            usize::MAX,
        )?;
        assert!(matches!(
            registration,
            Registration::RoleTaken(Role::Proposer)
        ));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn disconnect_reserves_and_expire_prunes() -> TestResult {
        let registry = Registry::new();
        let topic = topic()?;
        let (proposer, _) = peer(1);
        let weak = proposer.tx.downgrade();
        let (session, _) = register(
            &registry,
            &topic,
            Role::Proposer,
            proposer,
            &ready(&topic),
            usize::MAX,
        )?;

        assert!(registry.disconnect(&topic, Role::Proposer, &weak, Duration::from_secs(10))?);
        assert!(!registry.expire(&topic, Role::Proposer, &notification(&topic))?);

        tokio::time::advance(Duration::from_secs(11)).await;
        assert!(
            registry.expire(&topic, Role::Proposer, &notification(&topic))?,
            "the reservation expired"
        );
        assert_eq!(
            registry.session_count()?,
            0,
            "expiring the last reservation removes the session"
        );

        let (replacement, _) = peer(3);
        let (again, _) = register(
            &registry,
            &topic,
            Role::Proposer,
            replacement,
            &ready(&topic),
            usize::MAX,
        )?;
        assert!(!Arc::ptr_eq(&session, &again));
        Ok(())
    }

    #[test]
    fn session_count_tracks_live_sessions() -> TestResult {
        let registry = Registry::new();
        assert_eq!(registry.session_count()?, 0);

        let (proposer, _) = peer(1);
        register(
            &registry,
            &topic()?,
            Role::Proposer,
            proposer,
            &ready(&topic()?),
            usize::MAX,
        )?;
        assert_eq!(registry.session_count()?, 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_notification_precedes_a_later_reconnect() -> TestResult {
        use wallet_session_core::frame::RelayFrameBody;

        let registry = Registry::new();
        let topic = topic()?;
        let (proposer, mut proposer_rx) = peer(1);
        let (responder, _) = peer(2);
        let weak = responder.tx.downgrade();

        register(
            &registry,
            &topic,
            Role::Proposer,
            proposer,
            &ready(&topic),
            usize::MAX,
        )?;
        register(
            &registry,
            &topic,
            Role::Responder,
            responder,
            &ready(&topic),
            usize::MAX,
        )?;
        assert!(registry.disconnect(&topic, Role::Responder, &weak, Duration::from_secs(1))?);

        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(registry.expire(&topic, Role::Responder, &notification(&topic))?);

        // The counterpart returns: its `session_ready` must follow the
        // disconnect, because the expiry queued that disconnect before it let
        // go of the slot.
        let (responder, _) = peer(2);
        register(
            &registry,
            &topic,
            Role::Responder,
            responder,
            &ready(&topic),
            usize::MAX,
        )?;

        let mut kinds = Vec::new();
        while let Ok(queued) = proposer_rx.try_recv() {
            kinds.push(match &queued.frame.body {
                RelayFrameBody::SessionReady => "ready",
                RelayFrameBody::PeerDisconnected => "disconnected",
                RelayFrameBody::Message { .. } => "message",
            });
        }
        assert_eq!(
            kinds,
            ["ready", "disconnected", "ready"],
            "the survivor must not be told it is gone after its peer came back"
        );
        Ok(())
    }

    #[test]
    fn refused_registrations_leave_the_registry_unchanged() -> TestResult {
        let registry = Registry::new();

        let (proposer, _) = peer(1);
        register(
            &registry,
            &topic()?,
            Role::Proposer,
            proposer,
            &ready(&topic()?),
            usize::MAX,
        )?;
        assert_eq!(registry.session_count()?, 1);

        for i in 0..10u8 {
            let fresh = Topic::new([200 + i; 32])?;
            let (refused, _) = peer(2);
            assert!(
                registry
                    .register(
                        &fresh,
                        Role::Proposer,
                        refused,
                        None,
                        &ready(&fresh),
                        usize::MAX
                    )
                    .is_err()
            );
        }
        assert_eq!(registry.session_count()?, 1);

        let fresh = Topic::new([1u8; 32])?;
        let (accepted, _) = peer(2);
        register(
            &registry,
            &fresh,
            Role::Proposer,
            accepted,
            &ready(&fresh),
            usize::MAX,
        )?;
        assert_eq!(registry.session_count()?, 2);

        Ok(())
    }

    #[test]
    fn poisoned_lock_is_reported() -> TestResult {
        let registry = Registry::new();
        registry.poison_for_test();

        assert!(matches!(
            registry.session_count(),
            Err(RegistryError::LockPoisoned)
        ));

        let (proposer, _) = peer(1);
        assert!(matches!(
            register(
                &registry,
                &topic()?,
                Role::Proposer,
                proposer,
                &ready(&topic()?),
                usize::MAX
            ),
            Err(RegistryError::LockPoisoned)
        ));
        Ok(())
    }

    #[test]
    fn new_session_over_cap_is_rejected() -> TestResult {
        let registry = Registry::new();
        let (first, _) = peer(1);
        let (second, _) = peer(2);

        register(
            &registry,
            &topic()?,
            Role::Proposer,
            first,
            &ready(&topic()?),
            1,
        )?;
        assert!(matches!(
            register(
                &registry,
                &Topic::new([7u8; 32])?,
                Role::Proposer,
                second,
                &ready(&Topic::new([7u8; 32])?),
                1
            ),
            Err(RegistryError::TooManySessions)
        ));
        Ok(())
    }
}
