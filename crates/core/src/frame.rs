use serde::{Deserialize, Serialize};

use crate::message::{MessageId, Topic};

/// Plaintext control frame exchanged over the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayFrame {
    /// Protocol version.
    pub v: u8,

    /// Message id.
    pub id: MessageId,

    /// Frame topic.
    pub topic: Topic,

    /// Type-specific body.
    #[serde(flatten)]
    pub body: RelayFrameBody,
}

impl RelayFrame {
    /// The only relay frame version this crate speaks.
    pub const VERSION: u8 = 1;
}

/// The relay control/forward variants carried by a [`RelayFrame`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayFrameBody {
    /// Relay signal that both peers are connected.
    SessionReady,

    /// Relay signal that the counterpart disconnected and its session expired.
    PeerDisconnected,

    /// Opaque application envelope routed to the counterpart.
    Message { payload: String },
}

impl RelayFrameBody {
    pub fn relay_only_body(&self) -> Option<&'static str> {
        match self {
            RelayFrameBody::SessionReady => Some("session_ready"),
            RelayFrameBody::PeerDisconnected => Some("peer_disconnected"),
            RelayFrameBody::Message { .. } => None,
        }
    }
}
