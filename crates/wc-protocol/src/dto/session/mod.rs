//! Sign API session DTOs.

mod action;
mod authenticate;
mod delete;
mod event;
mod extend;
mod method;
mod ping;
mod proposal;
mod request;
mod rpc;
mod settle;
mod types;
mod update;

pub use action::{SessionEventName, SessionEventNameError, SessionMethod, SessionMethodError};
pub use authenticate::{
    AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
    CacaoSignatureType, CacaoSignatureValue, SessionAuthenticateParams, SessionAuthenticateResult,
};
pub use delete::SessionDeleteParams;
pub use event::{SessionEvent, SessionEventParams};
pub use extend::SessionExtendParams;
pub use method::SignMethod;
pub use ping::SessionPingParams;
pub use proposal::{
    DappMetadata, DappRedirect, ProposalNamespace, ProposalNamespaces, ProposalRequests, Proposer,
    RelayProtocolOptions, SessionProposeErrorResponse, SessionProposeParams, SessionProposeResult,
    session_propose_error_response,
};
pub use request::{
    SessionRequest, SessionRequestErrorResponse, SessionRequestParams, SessionRequestResponse,
    SessionRequestResult, session_request_error_response, session_request_success_response,
};
pub use rpc::{
    JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResponse,
    SessionAck, SessionAckResponse, SessionDeleteResponse, SessionEventResponse,
    SessionExtendResponse, SessionPingResponse, SessionSettleResponse, SessionUpdateResponse,
    session_ack_response,
};
pub use settle::{SessionSettleParams, SpecialNamespace, SpecialNamespaces};
pub use types::{
    ScopedProperties, Session, SessionConfig, SessionNamespace, SessionNamespaces,
    SessionParticipant, SessionProperties, SessionTransportType,
};
pub use update::SessionUpdateParams;
