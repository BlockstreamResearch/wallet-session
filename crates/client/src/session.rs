use wallet_session_core::message::Topic;

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
    /// Topic both peers are connected to.
    pub topic: Topic,

    /// Local role.
    pub role: Role,

    /// `did:key` of the peer, once known.
    pub peer_did: Option<String>,

    /// Current lifecycle state.
    pub state: SessionState,
}

impl Session {
    /// Start a session on `topic` for the given role.
    pub fn new(topic: Topic, role: Role) -> Self {
        Self {
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
