//! Feature-gated single-session state harness.

use wc_protocol::{pairing::PairingSymKey, relay::RelayTopic, session::Session};

use super::{
    ActiveSession, SessionExpired, SingleSessionClientError, SingleSessionClientState,
    take_expired_session_from_state,
};
use crate::low_level::SessionSubscription;

/// Deterministic harness for single-session runtime state.
///
/// This type is intentionally smaller than `SingleSessionClient`: it does not
/// open `WebSockets`, publish relay messages, or decrypt payloads. It exists so
/// fuzz targets and integration tests can exercise the same in-memory pending
/// decision and expiry primitives used by the production client.
///
/// # Examples
///
/// ```
/// use wc_core::testkit::SingleSessionStateHarness;
/// use wc_protocol::{pairing::PairingSymKey, session::Session};
///
/// # let json = r#"{
/// #   "topic": "1111111111111111111111111111111111111111111111111111111111111111",
/// #   "pairingTopic": "2222222222222222222222222222222222222222222222222222222222222222",
/// #   "relay": {"protocol": "irn"},
/// #   "expiry": 1780470684,
/// #   "acknowledged": true,
/// #   "controller": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
/// #   "namespaces": {
/// #     "eip155": {
/// #       "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
/// #       "chains": ["eip155:1"],
/// #       "events": ["chainChanged", "accountsChanged"],
/// #       "methods": ["personal_sign"]
/// #     }
/// #   },
/// #   "requiredNamespaces": {},
/// #   "optionalNamespaces": {},
/// #   "self": {
/// #     "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
/// #     "metadata": {"name": "Wallet", "description": "Wallet", "url": "https://example.com/wallet", "icons": []}
/// #   },
/// #   "peer": {
/// #     "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
/// #     "metadata": {"name": "Dapp", "description": "Dapp", "url": "https://example.com/dapp", "icons": []}
/// #   },
/// #   "transportType": "relay"
/// # }"#;
/// let session = serde_json::from_str::<Session>(json)?;
/// let mut harness = SingleSessionStateHarness::new_session(
///     session,
///     PairingSymKey::from_bytes([7; 32]),
/// );
///
/// assert!(harness.mark_session_request_pending(42)?);
/// assert!(!harness.mark_session_request_pending(42)?);
/// harness.complete_session_request(42)?;
/// assert!(harness.complete_session_request(42).is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct SingleSessionStateHarness {
    state: SingleSessionClientState,
}

impl SingleSessionStateHarness {
    /// Builds a harness with no active pairing or session.
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            state: SingleSessionClientState::Idle,
        }
    }

    /// Builds a harness with one active session and deterministic subscription data.
    #[must_use]
    pub fn new_session(session: Session, sym_key: PairingSymKey) -> Self {
        let subscription = SessionSubscription::for_test(session.topic.clone(), sym_key);
        Self {
            state: SingleSessionClientState::Session(Box::new(ActiveSession::new(
                subscription,
                session,
            ))),
        }
    }

    /// Whether no session is currently tracked by the harness.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, SingleSessionClientState::Idle)
    }

    /// Active session, if one exists.
    #[must_use]
    pub const fn active_session(&self) -> Option<&Session> {
        match &self.state {
            SingleSessionClientState::Session(session) => Some(&session.session),
            SingleSessionClientState::Idle | SingleSessionClientState::Pairing(_) => None,
        }
    }

    /// Adds a pending user decision for a session request.
    ///
    /// Returns `false` when the same request ID is already pending. This is the
    /// same duplicate suppression used by `SingleSessionClient::next_event`.
    pub fn mark_session_request_pending(
        &mut self,
        request_id: u64,
    ) -> Result<bool, SingleSessionClientError> {
        Ok(self
            .active_session_mut()?
            .mark_session_request_pending(request_id))
    }

    /// Completes a pending session request decision.
    ///
    /// A second completion for the same request ID fails with the production
    /// `SessionRequestDecisionMissing` error.
    pub fn complete_session_request(
        &mut self,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        let session = self.active_session_mut()?;
        session.ensure_pending_session_request(request_id)?;
        session.complete_session_request(request_id);
        Ok(())
    }

    /// Adds a pending user decision for a session update.
    ///
    /// Returns `false` when the same update ID is already pending.
    pub fn mark_session_update_pending(
        &mut self,
        request_id: u64,
    ) -> Result<bool, SingleSessionClientError> {
        Ok(self
            .active_session_mut()?
            .mark_session_update_pending(request_id))
    }

    /// Completes a pending session update decision.
    ///
    /// A second completion for the same request ID fails with the production
    /// `SessionUpdateDecisionMissing` error.
    pub fn complete_session_update(
        &mut self,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        let session = self.active_session_mut()?;
        session.ensure_pending_session_update(request_id)?;
        session.complete_session_update(request_id);
        Ok(())
    }

    /// Applies the production session-expiry transition at a deterministic time.
    ///
    /// When the active session has expired, this returns one `SessionExpired`
    /// event and clears the state. Calling it again returns `None`.
    pub fn take_expired_session_at(&mut self, now_unix_seconds: u64) -> Option<SessionExpired> {
        take_expired_session_from_state(&mut self.state, now_unix_seconds)
    }

    fn active_session_mut(&mut self) -> Result<&mut ActiveSession, SingleSessionClientError> {
        match &mut self.state {
            SingleSessionClientState::Session(session) => Ok(session),
            SingleSessionClientState::Idle | SingleSessionClientState::Pairing(_) => {
                Err(SingleSessionClientError::SessionMissing {
                    topic: RelayTopic::from_bytes([0; 32]),
                })
            }
        }
    }
}
