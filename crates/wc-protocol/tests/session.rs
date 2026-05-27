//! Integration tests for Sign API session DTOs.

mod session {
    use wc_protocol::caip::{Caip2ChainId, Caip10AccountId};

    fn chain(value: &str) -> Caip2ChainId {
        value.parse().expect("test chain ID parses")
    }

    fn account(value: &str) -> Caip10AccountId {
        value.parse().expect("test account ID parses")
    }

    fn chain_strings(values: &[Caip2ChainId]) -> Vec<&str> {
        values.iter().map(Caip2ChainId::as_str).collect()
    }

    fn account_strings(values: &[Caip10AccountId]) -> Vec<&str> {
        values.iter().map(Caip10AccountId::as_str).collect()
    }

    mod authenticate;
    mod delete;
    mod event;
    mod extend;
    mod ping;
    mod proposal;
    mod request;
    mod settle;
    mod types;
    mod update;
}
