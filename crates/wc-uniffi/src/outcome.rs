use wc_core::SessionAuthenticateApprovalOutcome;

use crate::{
    error::WcUniFfiError,
    types::{WcJsonPayload, WcSessionAuthenticateOutcome, WcSessionInfo},
    util::{json_string, u64_to_i64},
};

pub fn session_info(
    session: &wc_protocol::session::Session,
) -> Result<WcSessionInfo, WcUniFfiError> {
    Ok(WcSessionInfo {
        topic: session.topic.to_string(),
        expiry: u64_to_i64(session.expiry)?,
        acknowledged: session.acknowledged,
        session: WcJsonPayload::new(json_string(session)?),
    })
}

pub fn session_authenticate_outcome(
    outcome: SessionAuthenticateApprovalOutcome,
) -> Result<WcSessionAuthenticateOutcome, WcUniFfiError> {
    Ok(WcSessionAuthenticateOutcome {
        response_ack: outcome.response_ack(),
        session: outcome.session().map(session_info).transpose()?,
    })
}

pub fn session_message_request_id(
    message: &wc_core::SessionReceivedMessage,
) -> Option<Result<i64, WcUniFfiError>> {
    match message.payload() {
        wc_core::SessionPayload::SessionRequest(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::SessionUpdate(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::SessionExtend(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::SessionEvent(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::SessionPing(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::SessionDelete(request) => Some(u64_to_i64(request.id)),
        wc_core::SessionPayload::Sign(_)
        | wc_core::SessionPayload::Unknown(_)
        | wc_core::SessionPayload::Missing => None,
    }
}
