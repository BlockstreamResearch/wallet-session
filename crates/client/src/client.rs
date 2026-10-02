use serde_json::Value;
use wallet_session_core::{
    frame::{RelayFrame, RelayFrameBody},
    message::Topic,
};

use crate::{
    config::ClientConfig,
    error::Result,
    identity::IdentityKey,
    messages::{ClientMessage, RequestId},
    random,
    relay::RelayClient,
    session::{Role, Session, SessionState},
};

pub struct Client {
    transport: RelayClient,
    session: Session,
}

impl Client {
    pub async fn connect(
        config: ClientConfig,
        identity: IdentityKey,
        role: Role,
        topic: Topic,
    ) -> Result<Self> {
        let transport = RelayClient::connect(&config, &identity, role, &topic).await?;
        Ok(Self {
            transport,
            session: Session::new(topic, role),
        })
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn is_ready(&self) -> bool {
        self.session.state != SessionState::Idle
    }

    pub async fn wait_session_ready(&mut self) -> Result<()> {
        while !self.is_ready() {
            let frame = self.transport.recv().await?;
            match frame.body {
                RelayFrameBody::SessionReady => {
                    self.session.state = SessionState::Active;
                }
                RelayFrameBody::Message { payload } => {
                    log::debug!("dropping message received before session_ready: {payload}");
                }
            }
        }
        Ok(())
    }

    pub async fn send(&mut self, message: &ClientMessage) -> Result<()> {
        let frame = RelayFrame {
            v: 1,
            id: random::id()?,
            topic: self.transport.topic().clone(),
            body: RelayFrameBody::Message {
                payload: message.to_payload()?,
            },
        };
        self.transport.send(frame).await
    }

    pub async fn recv(&mut self) -> Result<ClientMessage> {
        loop {
            let frame = self.transport.recv().await?;
            if let RelayFrameBody::Message { payload } = frame.body {
                return ClientMessage::from_payload(&payload);
            }
        }
    }

    /// Send a `proposal` and move to `ProposalSent`.
    pub async fn propose(&mut self, proposal: Value) -> Result<()> {
        self.send(&ClientMessage::Proposal { proposal }).await?;
        self.session.state = SessionState::ProposalSent;
        Ok(())
    }

    /// Send an `approve` and move to `Active`.
    pub async fn approve(&mut self, approval: Value) -> Result<()> {
        self.send(&ClientMessage::Approve { approval }).await?;
        self.session.state = SessionState::Active;
        Ok(())
    }

    /// Send a `reject` and move to `Rejected`.
    pub async fn reject(&mut self, code: u32, message: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Reject {
            code,
            message: message.into(),
        })
        .await?;
        self.session.state = SessionState::Rejected;
        Ok(())
    }

    /// Send a `request` and return its correlation id.
    pub async fn request(&mut self, request: Value) -> Result<RequestId> {
        let request_id = random::id()?;
        self.send(&ClientMessage::Request {
            request_id: request_id.clone(),
            request,
        })
        .await?;
        Ok(request_id)
    }

    /// Send a `response` (or error) for a request.
    pub async fn respond(
        &mut self,
        request_id: impl Into<String>,
        response: Option<Value>,
        error: Option<Value>,
    ) -> Result<()> {
        self.send(&ClientMessage::Response {
            request_id: request_id.into(),
            response,
            error,
        })
        .await
    }

    /// Acknowledge a received message.
    pub async fn ack(&mut self, ack_id: impl Into<String>) -> Result<()> {
        self.send(&ClientMessage::Ack {
            ack_id: ack_id.into(),
        })
        .await
    }

    /// Gracefully disconnect.
    pub async fn disconnect(&mut self, reason: impl Into<String>, code: u32) -> Result<()> {
        self.send(&ClientMessage::Disconnect {
            reason: reason.into(),
            code,
            message: String::new(),
        })
        .await?;
        self.session.state = SessionState::Disconnected;
        Ok(())
    }
}
