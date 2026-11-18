use std::fmt;

use wallet_session_core::{did::DidKey, message::Topic};

pub use wallet_session_core::connection::Role;

/// Lifecycle state of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Connected, waiting for `session_ready`.
    Idle,

    /// Proposal sent, awaiting approval.
    ProposalSent,

    /// Proposal received, awaiting a local decision.
    ProposalReceived,

    /// Session established.
    Active,

    /// Proposal rejected.
    Rejected,

    /// Session torn down.
    Disconnected,
}

/// A single paired session.
///
/// Its `Debug` output shows topics only by their log tag: a pairing topic is
/// a bearer secret, and anyone who learns it can take the free role on it.
#[derive(Clone)]
pub struct Session {
    /// Topic used for the initial handshake.
    pub pairing_topic: Topic,

    /// Topic currently carrying application traffic.
    pub topic: Topic,

    /// Local role.
    pub role: Role,

    /// `did:key` of the peer, once known.
    ///
    /// This is the `from` of the first envelope we accepted on the pairing
    /// topic. Envelopes are not signed with the identity key, so it is only
    /// the identity that a holder of the pairing key declared. Do not use it
    /// to recognise a known wallet or application.
    pub peer_did: Option<DidKey>,

    /// Current lifecycle state.
    pub state: SessionState,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("pairing_topic", &self.pairing_topic.log_tag())
            .field("topic", &self.topic.log_tag())
            .field("role", &self.role)
            .field("peer_did", &self.peer_did)
            .field("state", &self.state)
            .finish()
    }
}

impl Session {
    /// Start a session on `topic` for the given role.
    pub fn new(topic: Topic, role: Role) -> Self {
        Self {
            pairing_topic: topic.clone(),
            topic,
            role,
            peer_did: None,
            state: SessionState::Idle,
        }
    }

    /// Whether application messages may be exchanged.
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_show_topics() {
        let session = Session::new(Topic::new([9u8; 32]).expect("topic"), Role::Responder);
        let debug = format!("{session:?}");
        let topic = &session.pairing_topic;
        for raw in [topic.to_string(), format!("{topic:?}")] {
            assert!(!debug.contains(&raw), "{debug}");
        }
        assert!(debug.contains("Responder"), "{debug}");
    }
}
