//! Integration tests for Sign API session DTOs.

mod session {
    use wc_protocol::caip::{Caip2ChainId, Caip10AccountId};
    use wc_protocol::did::DidPkh;
    use wc_protocol::key::X25519PublicKey;
    use wc_protocol::session::{SessionEventName, SessionMethod};

    fn chain(value: &str) -> Caip2ChainId {
        value.parse().expect("test chain ID parses")
    }

    fn account(value: &str) -> Caip10AccountId {
        value.parse().expect("test account ID parses")
    }

    fn did_pkh(value: &str) -> DidPkh {
        value.parse().expect("test DID PKH parses")
    }

    fn public_key(value: &str) -> X25519PublicKey {
        value.parse().expect("test X25519 public key parses")
    }

    fn method(value: &str) -> SessionMethod {
        value.parse().expect("test session method parses")
    }

    fn event_name(value: &str) -> SessionEventName {
        value.parse().expect("test session event name parses")
    }

    fn chain_strings(values: &[Caip2ChainId]) -> Vec<&str> {
        values.iter().map(Caip2ChainId::as_str).collect()
    }

    fn account_strings(values: &[Caip10AccountId]) -> Vec<&str> {
        values.iter().map(Caip10AccountId::as_str).collect()
    }

    mod action;
    mod authenticate;
    mod delete;
    mod event;
    mod extend;
    mod ping;
    mod proposal;
    mod request;
    mod rpc;
    mod settle;
    mod types;
    mod update;
    mod wallet_call;
}
