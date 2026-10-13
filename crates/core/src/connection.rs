use std::fmt;

use serde::{Deserialize, Serialize};

use crate::message::Topic;

/// Role a peer claims on a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Proposer,

    Responder,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Proposer => "proposer",
            Role::Responder => "responder",
        }
    }

    pub fn counterpart(self) -> Self {
        match self {
            Role::Proposer => Role::Responder,
            Role::Responder => Role::Proposer,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Query carried on the relay WebSocket handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionQuery {
    /// Signed connection token.
    pub auth: String,

    /// Claimed role.
    pub role: Role,

    /// Topic to subscribe to.
    pub topic: Topic,

    /// Optional registration id; an attribution label only, not authorization.
    /// TODO: should be it's own struct
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn connection_query_round_trips() -> TestResult {
        let query = ConnectionQuery {
            auth: "token".to_owned(),
            role: Role::Proposer,
            topic: Topic::new([5u8; 32])?,
            registration_id: Some("reg-1".to_owned()),
        };

        let encoded = serde_urlencoded::to_string(&query)?;
        let decoded: ConnectionQuery = serde_urlencoded::from_str(&encoded)?;
        assert_eq!(decoded, query);
        Ok(())
    }

    #[test]
    fn responder_query_omits_registration_id() -> TestResult {
        let query = ConnectionQuery {
            auth: "token".to_owned(),
            role: Role::Responder,
            topic: Topic::new([5u8; 32])?,
            registration_id: None,
        };

        let encoded = serde_urlencoded::to_string(&query)?;
        assert!(!encoded.contains("registrationId"));
        Ok(())
    }
}
