//! Feature-gated single-session state harness.

use wc_protocol::{
    pairing::PairingSymKey,
    relay::RelayTopic,
    session::{Session, SessionNamespaces},
};

use super::{
    ActiveSession, SessionExpired, SingleSessionClientError, SingleSessionClientState,
    take_expired_session_from_state,
};
use crate::capabilities::WalletCapabilities;
use crate::low_level::{PairingSubscription, SessionSubscription};

/// Coarse state held by `SingleSessionStateHarness`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSessionHarnessState {
    /// No active pairing or session topic.
    Idle,
    /// One pairing topic is active.
    Pairing,
    /// One session topic is active.
    Session,
}

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

    /// Current single-session state without exposing relay subscription internals.
    #[must_use]
    pub const fn state(&self) -> SingleSessionHarnessState {
        match &self.state {
            SingleSessionClientState::Idle => SingleSessionHarnessState::Idle,
            SingleSessionClientState::Pairing(_) => SingleSessionHarnessState::Pairing,
            SingleSessionClientState::Session(_) => SingleSessionHarnessState::Session,
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

    /// Starts one deterministic pairing topic.
    ///
    /// This mirrors the high-level `SingleSessionClient::pair` state boundary:
    /// a new pairing is accepted only when the runtime is idle. The harness
    /// does not fetch retained messages or subscribe to relay; fuzzing injects
    /// later transitions directly.
    pub fn begin_pairing(
        &mut self,
        topic: RelayTopic,
        sym_key: PairingSymKey,
    ) -> Result<(), SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Idle => {
                self.state = SingleSessionClientState::Pairing(PairingSubscription::for_test(
                    topic, sym_key,
                ));
                Ok(())
            }
            SingleSessionClientState::Pairing(subscription) => {
                Err(SingleSessionClientError::ActivePairingExists {
                    topic: subscription.topic().clone(),
                })
            }
            SingleSessionClientState::Session(session) => {
                Err(SingleSessionClientError::ActiveSessionExists {
                    topic: session.session.topic.clone(),
                })
            }
        }
    }

    /// Applies the pairing-topic close transition for `wc_pairingDelete`.
    ///
    /// `SingleSessionClientEvent::PairingMessage` treats pairing delete as a
    /// terminal pairing event. This harness method exercises the same
    /// single-topic ownership rule without publishing an acknowledgement.
    pub fn inject_pairing_delete(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<(), SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Pairing(subscription) if subscription.topic() == topic => {
                self.state = SingleSessionClientState::Idle;
                Ok(())
            }
            _ => Err(SingleSessionClientError::PairingSubscriptionMissing {
                topic: topic.clone(),
            }),
        }
    }

    /// Adopts an acknowledged session from the active pairing topic.
    ///
    /// Session proposal approval and auth-with-session approval both replace
    /// the pairing topic with the derived session topic. The harness keeps that
    /// transition explicit so stateful fuzzing can check replacement and
    /// stale-pairing behavior without relay I/O.
    pub fn adopt_session_from_pairing(
        &mut self,
        pairing_topic: &RelayTopic,
        session: Session,
        sym_key: PairingSymKey,
    ) -> Result<(), SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Pairing(subscription)
                if subscription.topic() == pairing_topic =>
            {
                let session_subscription =
                    SessionSubscription::for_test(session.topic.clone(), sym_key);
                self.state = SingleSessionClientState::Session(Box::new(ActiveSession::new(
                    session_subscription,
                    session,
                )));
                Ok(())
            }
            _ => Err(SingleSessionClientError::PairingSubscriptionMissing {
                topic: pairing_topic.clone(),
            }),
        }
    }

    /// Adds a pending user decision for a session request on the active topic.
    ///
    /// Session requests are user-visible decisions. Duplicate request IDs stay
    /// suppressed in the active session until one response completes.
    ///
    /// <https://specs.walletconnect.com/2.0/specs/clients/sign/session-events#session_request>
    ///
    /// > Triggered when a session request is received and should be presented
    /// > to the user for approval or rejection.
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

    /// Adds a pending user decision for a session request on `topic`.
    ///
    /// This variant lets fuzzing exercise stale-topic inputs. The production
    /// response path checks the message topic before accepting a decision.
    pub fn mark_session_request_pending_on(
        &mut self,
        topic: &RelayTopic,
        request_id: u64,
    ) -> Result<bool, SingleSessionClientError> {
        Ok(self
            .client_session_mut(topic)?
            .mark_session_request_pending(request_id))
    }

    /// Completes a pending session request decision on the active topic.
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

    /// Completes a pending session request decision on `topic`.
    pub fn complete_session_request_on(
        &mut self,
        topic: &RelayTopic,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        let session = self.client_session_mut(topic)?;
        session.ensure_pending_session_request(request_id)?;
        session.complete_session_request(request_id);
        Ok(())
    }

    /// Adds a pending user decision for a session update on the active topic.
    ///
    /// Namespace replacement changes permissions, so the runtime should surface
    /// a pending decision rather than acknowledging the update automatically.
    ///
    /// <https://docs.walletconnect.network/wallet-sdk/web/usage#updating-a-session>
    ///
    /// > include new accounts or chains or methods in an existing session
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

    /// Adds a pending user decision for a session update on `topic`.
    ///
    /// This variant lets fuzzing feed stale-topic updates into the same topic
    /// guard used by the wallet-facing approval and rejection methods.
    pub fn mark_session_update_pending_on(
        &mut self,
        topic: &RelayTopic,
        request_id: u64,
    ) -> Result<bool, SingleSessionClientError> {
        Ok(self
            .client_session_mut(topic)?
            .mark_session_update_pending(request_id))
    }

    /// Completes a pending session update decision on the active topic.
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

    /// Completes a pending session update decision on `topic`.
    pub fn complete_session_update_on(
        &mut self,
        topic: &RelayTopic,
        request_id: u64,
    ) -> Result<(), SingleSessionClientError> {
        let session = self.client_session_mut(topic)?;
        session.ensure_pending_session_update(request_id)?;
        session.complete_session_update(request_id);
        Ok(())
    }

    /// Applies an approved namespace replacement and clears the pending update.
    ///
    /// This mirrors the high-level client rule that local namespaces mutate
    /// only after an acknowledged approval path. The relay acknowledgement is
    /// outside the harness; this method covers the state mutation that follows.
    pub fn approve_session_update_on(
        &mut self,
        topic: &RelayTopic,
        request_id: u64,
        namespaces: SessionNamespaces,
        capabilities: &WalletCapabilities,
    ) -> Result<(), SingleSessionClientError> {
        let session = self.client_session_mut(topic)?;
        session.ensure_pending_session_update(request_id)?;
        capabilities
            .validate_session_update_namespaces(&namespaces)
            .map_err(|source| SingleSessionClientError::SessionUpdateApproval { source })?;
        session.session.namespaces = namespaces;
        session.complete_session_update(request_id);
        Ok(())
    }

    /// Refreshes active session expiry after a deterministic `wc_sessionExtend`.
    ///
    /// The production client acknowledges the peer before updating the stored
    /// expiry. The harness models only the post-ack state change.
    pub fn inject_session_extend(
        &mut self,
        topic: &RelayTopic,
        expiry: u64,
    ) -> Result<(), SingleSessionClientError> {
        self.client_session_mut(topic)?.session.expiry = expiry;
        Ok(())
    }

    /// Clears the active session for `wc_sessionDelete`.
    ///
    /// The high-level client acknowledges delete before clearing state. The
    /// harness applies the same clear operation directly so fuzzing can verify
    /// pending decisions disappear with the session.
    pub fn inject_session_delete(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<(), SingleSessionClientError> {
        self.client_session(topic)?;
        self.state = SingleSessionClientState::Idle;
        Ok(())
    }

    /// Applies the production session-expiry transition at a deterministic time.
    ///
    /// When the active session has expired, this returns one `SessionExpired`
    /// event and clears the state. Calling it again returns `None`.
    pub fn take_expired_session_at(&mut self, now_unix_seconds: u64) -> Option<SessionExpired> {
        take_expired_session_from_state(&mut self.state, now_unix_seconds)
    }

    /// Number of session requests still awaiting a caller decision.
    #[must_use]
    pub fn pending_session_request_count(&self) -> usize {
        self.active_client_session()
            .map_or(0, |session| session.pending_session_requests.len())
    }

    /// Number of session updates still awaiting a caller decision.
    #[must_use]
    pub fn pending_session_update_count(&self) -> usize {
        self.active_client_session()
            .map_or(0, |session| session.pending_session_updates.len())
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

    fn active_client_session(&self) -> Option<&ActiveSession> {
        match &self.state {
            SingleSessionClientState::Session(session) => Some(session),
            SingleSessionClientState::Idle | SingleSessionClientState::Pairing(_) => None,
        }
    }

    fn client_session(
        &self,
        topic: &RelayTopic,
    ) -> Result<&ActiveSession, SingleSessionClientError> {
        match &self.state {
            SingleSessionClientState::Session(session) if session.session.topic == *topic => {
                Ok(session)
            }
            _ => Err(SingleSessionClientError::SessionMissing {
                topic: topic.clone(),
            }),
        }
    }

    fn client_session_mut(
        &mut self,
        topic: &RelayTopic,
    ) -> Result<&mut ActiveSession, SingleSessionClientError> {
        match &mut self.state {
            SingleSessionClientState::Session(session) if session.session.topic == *topic => {
                Ok(session)
            }
            _ => Err(SingleSessionClientError::SessionMissing {
                topic: topic.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SingleSessionHarnessState, SingleSessionStateHarness};
    use crate::{WalletCapabilities, WalletChainCapability};
    use wc_protocol::{
        caip::{Caip2ChainId, Caip10AccountId},
        pairing::PairingSymKey,
        relay::RelayTopic,
        session::{Session, SessionEventName, SessionMethod},
    };

    #[test]
    fn pairing_adoption_replaces_pairing_with_one_session() -> Result<(), Box<dyn std::error::Error>>
    {
        let session = test_session()?;
        let pairing_topic = session.pairing_topic.clone();
        let session_topic = session.topic.clone();
        let mut harness = SingleSessionStateHarness::idle();

        harness.begin_pairing(pairing_topic.clone(), sym_key())?;
        assert_eq!(harness.state(), SingleSessionHarnessState::Pairing);
        assert!(
            harness
                .begin_pairing(RelayTopic::from_bytes([0x33; 32]), sym_key())
                .is_err()
        );

        harness.adopt_session_from_pairing(&pairing_topic, session, sym_key())?;
        assert_eq!(harness.state(), SingleSessionHarnessState::Session);
        assert_eq!(
            harness
                .active_session()
                .expect("session exists after adoption")
                .topic,
            session_topic
        );
        assert!(harness.begin_pairing(pairing_topic, sym_key()).is_err());

        Ok(())
    }

    #[test]
    fn session_update_approval_mutates_namespaces_once() -> Result<(), Box<dyn std::error::Error>> {
        let session = test_session()?;
        let topic = session.topic.clone();
        let namespaces = session.namespaces.clone();
        let mut harness = SingleSessionStateHarness::new_session(session, sym_key());
        let capabilities = test_capabilities()?;

        assert!(harness.mark_session_update_pending_on(&topic, 7)?);
        assert_eq!(harness.pending_session_update_count(), 1);
        harness.approve_session_update_on(&topic, 7, namespaces, &capabilities)?;
        assert_eq!(harness.pending_session_update_count(), 0);
        assert!(harness.complete_session_update_on(&topic, 7).is_err());

        Ok(())
    }

    #[test]
    fn session_delete_clears_pending_decisions() -> Result<(), Box<dyn std::error::Error>> {
        let session = test_session()?;
        let topic = session.topic.clone();
        let mut harness = SingleSessionStateHarness::new_session(session, sym_key());

        assert!(harness.mark_session_request_pending_on(&topic, 11)?);
        assert!(harness.mark_session_update_pending_on(&topic, 12)?);
        harness.inject_session_delete(&topic)?;

        assert_eq!(harness.state(), SingleSessionHarnessState::Idle);
        assert_eq!(harness.pending_session_request_count(), 0);
        assert_eq!(harness.pending_session_update_count(), 0);
        assert!(harness.complete_session_request_on(&topic, 11).is_err());
        assert!(harness.complete_session_update_on(&topic, 12).is_err());

        Ok(())
    }

    fn test_session() -> Result<Session, serde_json::Error> {
        serde_json::from_str(
            r#"{
              "topic": "1111111111111111111111111111111111111111111111111111111111111111",
              "pairingTopic": "2222222222222222222222222222222222222222222222222222222222222222",
              "relay": {"protocol": "irn"},
              "expiry": 1780470684,
              "acknowledged": true,
              "controller": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
              "namespaces": {
                "eip155": {
                  "accounts": ["eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87"],
                  "chains": ["eip155:1"],
                  "events": ["chainChanged", "accountsChanged"],
                  "methods": ["personal_sign"]
                }
              },
              "requiredNamespaces": {},
              "optionalNamespaces": {},
              "self": {
                "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
                "metadata": {"name": "Wallet", "description": "Wallet", "url": "https://example.com/wallet", "icons": []}
              },
              "peer": {
                "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                "metadata": {"name": "Dapp", "description": "Dapp", "url": "https://example.com/dapp", "icons": []}
              },
              "transportType": "relay"
            }"#,
        )
    }

    fn test_capabilities() -> Result<WalletCapabilities, Box<dyn std::error::Error>> {
        Ok(WalletCapabilities::new([WalletChainCapability::new(
            Caip2ChainId::parse("eip155:1")?,
            vec![Caip10AccountId::parse(
                "eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
            )?],
            vec![SessionMethod::parse("personal_sign")?],
            vec![
                SessionEventName::parse("chainChanged")?,
                SessionEventName::parse("accountsChanged")?,
            ],
        )?])?)
    }

    fn sym_key() -> PairingSymKey {
        PairingSymKey::from_bytes([0x42; 32])
    }
}
