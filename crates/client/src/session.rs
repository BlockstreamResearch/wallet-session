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
#[derive(Debug, Clone)]
pub struct Session {
    /// Topic used for the initial handshake.
    pub pairing_topic: Topic,

    /// Topic currently carrying application traffic.
    pub topic: Topic,

    /// Local role.
    pub role: Role,

    /// `did:key` of the peer, once known.
    pub peer_did: Option<DidKey>,

    /// Current lifecycle state.
    pub state: SessionState,
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
