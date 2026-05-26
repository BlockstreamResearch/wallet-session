//! Sign API session DTOs.

mod method;
mod proposal;
mod request;
mod rpc;
mod settle;
mod types;
mod update;

pub use method::SignMethod;
pub use proposal::{
    DappMetadata, DappRedirect, ProposalNamespace, ProposalNamespaces, ProposalRequests, Proposer,
    RelayProtocolOptions, SessionProposeParams,
};
pub use request::{SessionRequest, SessionRequestParams};
pub use rpc::JsonRpcRequest;
pub use settle::{SessionSettleParams, SpecialNamespace, SpecialNamespaces};
pub use types::{
    ScopedProperties, SessionConfig, SessionNamespace, SessionNamespaces, SessionParticipant,
    SessionProperties,
};
pub use update::SessionUpdateParams;
