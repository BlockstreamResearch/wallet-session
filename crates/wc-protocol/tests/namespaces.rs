//! Namespace validation tests.

use std::collections::BTreeMap;

use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, NamespaceKey},
    namespaces::{
        NamespaceValidationError, is_chain_authorized, is_event_authorized, is_method_authorized,
        validate_approved_namespaces, validate_required_namespaces,
    },
    session::{
        ProposalNamespace, ProposalNamespaces, SessionEventName, SessionMethod, SessionNamespace,
        SessionNamespaces,
    },
};

fn chain(value: &str) -> Caip2ChainId {
    Caip2ChainId::parse(value).expect("chain parses")
}

fn account(value: &str) -> Caip10AccountId {
    Caip10AccountId::parse(value).expect("account parses")
}

fn key(value: &str) -> NamespaceKey {
    NamespaceKey::parse(value).expect("namespace key parses")
}

fn method(value: &str) -> SessionMethod {
    value.parse().expect("method parses")
}

fn event_name(value: &str) -> SessionEventName {
    value.parse().expect("event parses")
}

fn proposal_namespace(
    chains: Option<Vec<&str>>,
    methods: Vec<&str>,
    events: Vec<&str>,
) -> ProposalNamespace {
    ProposalNamespace {
        chains: chains.map(|chains| chains.into_iter().map(chain).collect()),
        methods: methods.into_iter().map(method).collect(),
        events: events.into_iter().map(event_name).collect(),
    }
}

fn session_namespace(
    accounts: Vec<&str>,
    methods: Vec<&str>,
    events: Vec<&str>,
) -> SessionNamespace {
    SessionNamespace {
        chains: None,
        accounts: accounts.into_iter().map(account).collect(),
        methods: methods.into_iter().map(method).collect(),
        events: events.into_iter().map(event_name).collect(),
    }
}

fn required(entries: Vec<(&str, ProposalNamespace)>) -> ProposalNamespaces {
    entries
        .into_iter()
        .map(|(key_value, namespace)| (key(key_value), namespace))
        .collect()
}

fn approved(entries: Vec<(&str, SessionNamespace)>) -> SessionNamespaces {
    entries
        .into_iter()
        .map(|(key_value, namespace)| (key(key_value), namespace))
        .collect()
}

#[test]
fn validates_namespace_key_approval() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(
            Some(vec!["eip155:1"]),
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    validate_approved_namespaces(&required, &approved).expect("namespaces conform");
}

#[test]
fn validates_chain_key_approval() {
    let required = required(vec![(
        "eip155:1",
        proposal_namespace(None, vec!["personal_sign"], vec!["accountsChanged"]),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    validate_approved_namespaces(&required, &approved).expect("chain key conforms");
}

#[test]
fn rejects_bare_required_namespace_without_chains() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(None, vec!["personal_sign"], vec!["accountsChanged"]),
    )]);

    let error =
        validate_required_namespaces(&required).expect_err("bare namespace chains required");

    assert_eq!(
        error,
        NamespaceValidationError::MissingChains {
            namespace: "eip155".parse().expect("namespace parses")
        }
    );
}

#[test]
fn rejects_chain_with_wrong_namespace_prefix() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(
            Some(vec!["eip155:1", "cosmos:cosmoshub-4"]),
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    let error =
        validate_required_namespaces(&required).expect_err("chain namespace must match key");

    assert_eq!(
        error,
        NamespaceValidationError::ChainNamespaceMismatch {
            namespace: "eip155".parse().expect("namespace parses"),
            chain_id: chain("cosmos:cosmoshub-4")
        }
    );
}

#[test]
fn rejects_missing_required_namespace() {
    let required = required(vec![
        (
            "eip155",
            proposal_namespace(Some(vec!["eip155:1"]), vec!["eth_sign"], vec![]),
        ),
        (
            "cosmos",
            proposal_namespace(
                Some(vec!["cosmos:cosmoshub-4"]),
                vec!["cosmos_signDirect"],
                vec![],
            ),
        ),
    ]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["eth_sign"],
            vec![],
        ),
    )]);

    let error = validate_approved_namespaces(&required, &approved).expect_err("cosmos is missing");

    assert_eq!(
        error,
        NamespaceValidationError::MissingRequiredNamespace {
            namespace: "cosmos".parse().expect("namespace parses")
        }
    );
}

#[test]
fn rejects_missing_account_for_required_chain() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(
            Some(vec!["eip155:1", "eip155:137"]),
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    let error =
        validate_approved_namespaces(&required, &approved).expect_err("chain account is missing");

    assert_eq!(
        error,
        NamespaceValidationError::MissingAccountForChain {
            chain_id: chain("eip155:137")
        }
    );
}

#[test]
fn rejects_missing_required_method() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(
            Some(vec!["eip155:1"]),
            vec!["personal_sign", "eth_signTypedData"],
            vec!["accountsChanged"],
        ),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    let error = validate_approved_namespaces(&required, &approved).expect_err("method is missing");

    assert_eq!(
        error,
        NamespaceValidationError::MissingMethod {
            chain_id: chain("eip155:1"),
            method: method("eth_signTypedData")
        }
    );
}

#[test]
fn rejects_missing_required_event() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(
            Some(vec!["eip155:1"]),
            vec!["personal_sign"],
            vec!["accountsChanged", "chainChanged"],
        ),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    let error = validate_approved_namespaces(&required, &approved).expect_err("event is missing");

    assert_eq!(
        error,
        NamespaceValidationError::MissingEvent {
            chain_id: chain("eip155:1"),
            event: event_name("chainChanged")
        }
    );
}

#[test]
fn rejects_account_namespace_mismatch() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(Some(vec!["eip155:1"]), vec!["eth_sign"], vec![]),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec![
                "eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "cosmos:cosmoshub-4:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0",
            ],
            vec!["eth_sign"],
            vec![],
        ),
    )]);

    let error =
        validate_approved_namespaces(&required, &approved).expect_err("account namespace mismatch");

    assert_eq!(
        error,
        NamespaceValidationError::AccountNamespaceMismatch {
            namespace: key("eip155"),
            account: account("cosmos:cosmoshub-4:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0")
        }
    );
}

#[test]
fn allows_same_namespace_accounts_for_unrequested_chains() {
    let required = required(vec![(
        "eip155",
        proposal_namespace(Some(vec!["eip155:1"]), vec!["eth_sign"], vec![]),
    )]);
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec![
                "eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "eip155:42:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ],
            vec!["eth_sign", "personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    validate_approved_namespaces(&required, &approved).expect("extra chain is allowed");
}

#[test]
fn checks_runtime_chain_method_and_event_authorization() {
    let approved = approved(vec![(
        "eip155",
        session_namespace(
            vec!["eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            vec!["personal_sign"],
            vec!["accountsChanged"],
        ),
    )]);

    assert!(is_chain_authorized(&approved, &chain("eip155:1")));
    assert!(!is_chain_authorized(&approved, &chain("eip155:137")));
    assert!(is_method_authorized(
        &approved,
        &chain("eip155:1"),
        "personal_sign"
    ));
    assert!(!is_method_authorized(
        &approved,
        &chain("eip155:1"),
        "eth_signTypedData"
    ));
    assert!(is_event_authorized(
        &approved,
        &chain("eip155:1"),
        "accountsChanged"
    ));
    assert!(!is_event_authorized(
        &approved,
        &chain("eip155:1"),
        "disconnect"
    ));
}

#[test]
fn empty_required_namespaces_are_allowed() {
    let required = BTreeMap::new();

    validate_required_namespaces(&required).expect("empty requirements are valid");
}
