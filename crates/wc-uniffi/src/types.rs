use std::{fmt, sync::Arc};

use wc_protocol::verify::VerifyAttestationHash;

/// Opaque JSON payload returned to Kotlin only through explicit accessors.
#[derive(uniffi::Object)]
pub struct WcJsonPayload {
    json: String,
    sha256: String,
    byte_len: i64,
}

impl fmt::Debug for WcJsonPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WcJsonPayload")
            .field("byte_len", &self.byte_len)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl WcJsonPayload {
    pub(crate) fn new(json: String) -> Arc<Self> {
        Arc::new(Self {
            sha256: VerifyAttestationHash::from_message(&json).to_string(),
            byte_len: i64::try_from(json.len()).unwrap_or(i64::MAX),
            json,
        })
    }
}

#[uniffi::export]
impl WcJsonPayload {
    /// Returns the raw JSON payload. Call only at the point the wallet UI needs it.
    #[must_use]
    pub fn json(&self) -> String {
        self.json.clone()
    }

    /// Stable SHA-256 hash of the JSON payload.
    #[must_use]
    pub fn sha256(&self) -> String {
        self.sha256.clone()
    }

    /// UTF-8 byte length of the JSON payload.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "UniFFI exported methods are kept as regular functions."
    )]
    pub fn byte_len(&self) -> i64 {
        self.byte_len
    }
}

/// Wallet metadata sent to dapps during session approval.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcWalletMetadata {
    /// Wallet display name.
    pub name: String,
    /// Wallet description.
    pub description: String,
    /// Wallet website or app URL.
    pub url: String,
    /// Icon URLs.
    pub icons: Vec<String>,
    /// Optional Verify URL.
    pub verify_url: Option<String>,
    /// Optional native redirect URI.
    pub redirect_native: Option<String>,
    /// Optional universal redirect URL.
    pub redirect_universal: Option<String>,
    /// Whether link mode is supported.
    pub redirect_link_mode: Option<bool>,
}

/// Wallet capability for one CAIP-2 chain.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcChainCapability {
    /// CAIP-2 chain ID.
    pub chain_id: String,
    /// CAIP-10 accounts owned by the wallet on this chain.
    pub accounts: Vec<String>,
    /// JSON-RPC methods supported for the chain.
    pub methods: Vec<String>,
    /// Session events supported for the chain.
    pub events: Vec<String>,
}

/// Wallet capabilities and optional properties used for proposal approval.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcCapabilities {
    /// Per-chain wallet capabilities.
    pub chains: Vec<WcChainCapability>,
    /// Optional JSON object for session properties.
    pub session_properties_json: Option<String>,
    /// Optional JSON object for scoped properties.
    pub scoped_properties_json: Option<String>,
}

/// `WalletConnect` event kind returned to Kotlin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WcEventKind {
    /// No event was available before the receive timeout.
    None,
    /// `wc_sessionPropose` review is pending.
    SessionProposal,
    /// `wc_sessionAuthenticate` review is pending.
    SessionAuthenticate,
    /// Non-approval pairing-topic message.
    PairingMessage,
    /// Proposal expired.
    SessionProposalExpired,
    /// Authentication request expired.
    SessionAuthenticateExpired,
    /// `wc_sessionRequest` review is pending.
    SessionRequest,
    /// `wc_sessionUpdate` review is pending.
    SessionUpdate,
    /// Incoming session event.
    SessionEvent,
    /// Incoming session ping was handled.
    SessionPing,
    /// Incoming session extend was handled.
    SessionExtend,
    /// Incoming session delete was handled.
    SessionDelete,
    /// Unsupported session-topic message.
    UnsupportedSessionMessage,
    /// Invalid session request was rejected automatically.
    RejectedSessionRequest,
    /// Local session expiry was detected.
    SessionExpired,
}

/// Approval kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum WcPendingApprovalKind {
    /// Session proposal.
    SessionProposal,
    /// Session authentication request.
    SessionAuthenticate,
    /// Chain-specific session request.
    SessionRequest,
    /// Session namespace update.
    SessionUpdate,
}

/// Event returned by `WcClient.nextEvent`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcEvent {
    /// Event kind.
    pub kind: WcEventKind,
    /// Pairing/session topic when applicable.
    pub topic: Option<String>,
    /// JSON-RPC request id when applicable.
    pub request_id: Option<i64>,
    /// Stable review payload for wallet UI/policy.
    pub review: Option<Arc<WcJsonPayload>>,
    /// Human-readable diagnostic for non-review events.
    pub message: Option<String>,
}

/// Pending approval returned by `WcClient.pendingApprovals`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcPendingApproval {
    /// Approval kind.
    pub kind: WcPendingApprovalKind,
    /// Pairing/session topic.
    pub topic: String,
    /// JSON-RPC request id.
    pub request_id: i64,
    /// Stable review payload for wallet UI/policy.
    pub review: Arc<WcJsonPayload>,
}

/// Acknowledged session summary.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcSessionInfo {
    /// Session topic.
    pub topic: String,
    /// Unix expiry timestamp.
    pub expiry: i64,
    /// Whether the peer acknowledged settlement.
    pub acknowledged: bool,
    /// Full typed session payload.
    pub session: Arc<WcJsonPayload>,
}

/// Result of approving `wc_sessionAuthenticate`.
#[derive(Debug, Clone, uniffi::Record)]
pub struct WcSessionAuthenticateOutcome {
    /// Relay acknowledgement for the authentication response publish.
    pub response_ack: bool,
    /// Auth-created session, when methods/namespaces were granted.
    pub session: Option<WcSessionInfo>,
}
