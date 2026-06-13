//! Capability planner integration tests.

use std::collections::BTreeMap;

use serde_json::json;
use wc_core::{
    ProposalPlanningError, SessionUpdateApprovalError, WalletCapabilities, WalletCapabilityError,
    WalletChainCapability,
};
use wc_protocol::{
    caip::{Caip2ChainId, Caip10AccountId, NamespaceKey},
    key::X25519PublicKey,
    namespaces::{NamespaceValidationError, is_method_authorized},
    session::{
        DappMetadata, JsonRpcRequest, ProposalNamespace, ProposalNamespaces, RelayProtocolOptions,
        SessionEventName, SessionMethod, SessionNamespace, SessionNamespaces, SessionProposeParams,
        SignMethod,
    },
};

#[test]
fn required_namespace_is_approved_when_wallet_satisfies_it()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["personal_sign"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    let namespace = &approval.namespaces[&NamespaceKey::parse("eip155")?];
    assert_eq!(namespace.accounts.len(), 1);
    assert!(is_method_authorized(
        &approval.namespaces,
        &Caip2ChainId::parse("eip155:1")?,
        "personal_sign",
    ));

    Ok(())
}

#[test]
fn missing_required_method_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["eth_sendTransaction"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("required method must be rejected");

    assert!(matches!(
        error,
        ProposalPlanningError::MissingRequiredMethod { .. }
    ));

    Ok(())
}

#[test]
fn missing_required_event_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["personal_sign"], ["chainChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("required event must be rejected");

    assert!(matches!(
        error,
        ProposalPlanningError::MissingRequiredEvent { .. }
    ));

    Ok(())
}

#[test]
fn missing_required_account_is_rejected_during_capability_building()
-> Result<(), Box<dyn std::error::Error>> {
    let chain_id = Caip2ChainId::parse("eip155:1")?;
    let error = WalletChainCapability::new(
        chain_id,
        Vec::new(),
        vec!["personal_sign".parse()?],
        vec!["accountsChanged".parse()?],
    )
    .expect_err("empty chain account set must be rejected");

    assert!(matches!(error, WalletCapabilityError::EmptyAccounts { .. }));

    Ok(())
}

#[test]
fn account_chain_mismatch_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let error = WalletChainCapability::new(
        Caip2ChainId::parse("eip155:1")?,
        vec![Caip10AccountId::parse(
            "eip155:137:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        )?],
        vec!["personal_sign".parse()?],
        vec!["accountsChanged".parse()?],
    )
    .expect_err("account from another chain must be rejected");

    assert!(matches!(
        error,
        WalletCapabilityError::AccountChainMismatch { .. }
    ));

    Ok(())
}

#[test]
fn optional_namespaces_are_intersected_with_wallet_capabilities()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(
                ["eip155:1", "eip155:137"],
                ["personal_sign"],
                ["accountsChanged"],
            )?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    let namespace = &approval.namespaces[&NamespaceKey::parse("eip155")?];
    assert_eq!(
        namespace.chains.as_deref(),
        Some(&[Caip2ChainId::parse("eip155:1")?][..])
    );
    assert_eq!(namespace.accounts.len(), 1);

    Ok(())
}

#[test]
fn optional_methods_are_intersected_without_widening_permissions()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(
                ["eip155:1"],
                ["personal_sign", "eth_signTypedData_v4"],
                ["accountsChanged"],
            )?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    let namespace = &approval.namespaces[&NamespaceKey::parse("eip155")?];
    assert_eq!(namespace.methods, vec!["personal_sign".parse()?]);

    Ok(())
}

#[test]
fn optional_chain_with_no_supported_methods_is_not_approved()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["eth_signTypedData_v4"], ["accountsChanged"])?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("optional chain with no supported methods must not be approved");

    assert_eq!(error, ProposalPlanningError::NoSupportedNamespaces);

    Ok(())
}

#[test]
fn optional_method_only_namespace_is_approved() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["personal_sign"], [])?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        [],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    let namespace = &approval.namespaces[&NamespaceKey::parse("eip155")?];
    assert_eq!(namespace.accounts.len(), 1);
    assert_eq!(namespace.methods, vec!["personal_sign".parse()?]);
    assert!(namespace.events.is_empty());

    Ok(())
}

#[test]
fn optional_event_only_namespace_is_approved() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], [], ["accountsChanged"])?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        [],
        ["accountsChanged"],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    let namespace = &approval.namespaces[&NamespaceKey::parse("eip155")?];
    assert_eq!(namespace.accounts.len(), 1);
    assert!(namespace.methods.is_empty());
    assert_eq!(namespace.events, vec!["accountsChanged".parse()?]);

    Ok(())
}

#[test]
fn optional_chain_with_no_supported_events_is_not_approved()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], [], ["chainChanged"])?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("optional chain with no supported event must not disclose accounts");

    assert_eq!(error, ProposalPlanningError::NoSupportedNamespaces);

    Ok(())
}

#[test]
fn optional_chain_with_no_requested_actions_is_not_approved()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([("eip155", proposal_namespace(["eip155:1"], [], [])?)])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("optional chain with no usable action must not disclose accounts");

    assert_eq!(error, ProposalPlanningError::NoSupportedNamespaces);

    Ok(())
}

#[test]
fn optional_only_unsupported_proposal_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        ProposalNamespaces::new(),
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:137"], ["personal_sign"], ["accountsChanged"])?,
        )])?,
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("unsupported optional-only proposal must not be approved");

    assert_eq!(error, ProposalPlanningError::NoSupportedNamespaces);

    Ok(())
}

#[test]
fn chain_key_proposal_keeps_chain_scoped_approved_namespace()
-> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        namespaces([(
            "eip155:1",
            ProposalNamespace {
                chains: None,
                methods: vec!["personal_sign".parse()?],
                events: vec!["accountsChanged".parse()?],
            },
        )])?,
        ProposalNamespaces::new(),
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    assert!(
        approval
            .namespaces
            .contains_key(&NamespaceKey::parse("eip155:1")?)
    );

    Ok(())
}

#[test]
fn approval_includes_supported_session_and_scoped_properties()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["wallet_sendCalls"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    proposal.params.session_properties = Some(BTreeMap::from([
        ("atomic".to_owned(), json!({"status": "supported"})),
        ("futureOptional".to_owned(), json!({"optional": true})),
    ]));
    proposal.params.scoped_properties = Some(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!({
            "atomic": {"status": "supported"},
            "paymasterService": {"optional": true}
        }),
    )]));
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["wallet_sendCalls"],
        ["accountsChanged"],
    )?])?
    .with_session_properties(BTreeMap::from([(
        "atomic".to_owned(),
        json!({"status": "ready"}),
    )]))
    .with_scoped_properties(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!({"atomic": {"status": "supported"}}),
    )]));

    let approval =
        capabilities.plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)?;

    assert_eq!(
        approval.session_properties.as_ref().expect("properties")["atomic"],
        json!({"status": "ready"})
    );
    assert!(
        approval
            .session_properties
            .as_ref()
            .expect("properties")
            .get("futureOptional")
            .is_none()
    );
    assert_eq!(
        approval.scoped_properties.as_ref().expect("scoped")["eip155:1"]["atomic"],
        json!({"status": "supported"})
    );
    assert!(
        approval.scoped_properties.as_ref().expect("scoped")["eip155:1"]
            .get("paymasterService")
            .is_none()
    );

    Ok(())
}

#[test]
fn unsupported_required_session_property_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["wallet_sendCalls"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    proposal.params.session_properties = Some(BTreeMap::from([(
        "atomic".to_owned(),
        json!({"status": "supported"}),
    )]));
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["wallet_sendCalls"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("unsupported required session property must reject");

    assert_eq!(
        error,
        ProposalPlanningError::UnsupportedSessionProperty {
            property: "atomic".to_owned(),
        }
    );

    Ok(())
}

#[test]
fn unsupported_required_scoped_property_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["wallet_sendCalls"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    proposal.params.scoped_properties = Some(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!({"paymasterService": {"supported": true}}),
    )]));
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["wallet_sendCalls"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("unsupported required scoped property must reject");

    assert_eq!(
        error,
        ProposalPlanningError::UnsupportedScopedProperty {
            scope: "eip155:1".to_owned(),
            property: "paymasterService".to_owned(),
        }
    );

    Ok(())
}

#[test]
fn non_object_requested_scoped_property_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["wallet_sendCalls"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    proposal.params.scoped_properties =
        Some(BTreeMap::from([("eip155:1".to_owned(), json!(["atomic"]))]));
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["wallet_sendCalls"],
        ["accountsChanged"],
    )?])?
    .with_scoped_properties(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!({"atomic": {"status": "supported"}}),
    )]));

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("non-object requested scoped property must reject");

    assert_eq!(
        error,
        ProposalPlanningError::UnsupportedScopedPropertyShape {
            scope: "eip155:1".to_owned(),
        }
    );

    Ok(())
}

#[test]
fn non_object_supported_scoped_property_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut proposal = proposal(
        namespaces([(
            "eip155",
            proposal_namespace(["eip155:1"], ["wallet_sendCalls"], ["accountsChanged"])?,
        )])?,
        ProposalNamespaces::new(),
    )?;
    proposal.params.scoped_properties = Some(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!({"atomic": {"status": "supported"}}),
    )]));
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["wallet_sendCalls"],
        ["accountsChanged"],
    )?])?
    .with_scoped_properties(BTreeMap::from([(
        "eip155:1".to_owned(),
        json!("wallet-wide-atomic-support"),
    )]));

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("non-object supported scoped property must reject");

    assert_eq!(
        error,
        ProposalPlanningError::UnsupportedScopedPropertyShape {
            scope: "eip155:1".to_owned(),
        }
    );

    Ok(())
}

#[test]
fn malformed_proposal_namespace_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = proposal(
        namespaces([(
            "eip155",
            ProposalNamespace {
                chains: None,
                methods: vec!["personal_sign".parse()?],
                events: vec!["accountsChanged".parse()?],
            },
        )])?,
        ProposalNamespaces::new(),
    )?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .plan_session_approval(&proposal, wallet_metadata(), 1_780_000_000)
        .expect_err("bare namespace without chains must be rejected");

    assert!(matches!(
        error,
        ProposalPlanningError::ProposalNamespaces {
            source: NamespaceValidationError::MissingChains { .. }
        }
    ));

    Ok(())
}

#[test]
fn session_update_replacement_is_valid_when_within_wallet_capabilities()
-> Result<(), Box<dyn std::error::Error>> {
    let update = session_namespaces([(
        "eip155",
        session_namespace(
            ["eip155:1"],
            ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
            ["personal_sign"],
            ["accountsChanged"],
        )?,
    )])?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign", "eth_signTypedData_v4"],
        ["accountsChanged"],
    )?])?;

    capabilities.validate_session_update_namespaces(&update)?;

    Ok(())
}

#[test]
fn session_update_replacement_rejects_unsupported_method() -> Result<(), Box<dyn std::error::Error>>
{
    let update = session_namespaces([(
        "eip155",
        session_namespace(
            ["eip155:1"],
            ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
            ["personal_sign", "eth_sendTransaction"],
            ["accountsChanged"],
        )?,
    )])?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .validate_session_update_namespaces(&update)
        .expect_err("unsupported update method must be rejected");

    assert_eq!(
        error,
        SessionUpdateApprovalError::UnsupportedMethod {
            chain_id: Caip2ChainId::parse("eip155:1")?,
            method: SessionMethod::parse("eth_sendTransaction")?,
        }
    );

    Ok(())
}

#[test]
fn session_update_replacement_rejects_unsupported_account() -> Result<(), Box<dyn std::error::Error>>
{
    let update = session_namespaces([(
        "eip155",
        session_namespace(
            ["eip155:1"],
            ["eip155:1:0x2222222222222222222222222222222222222222"],
            ["personal_sign"],
            ["accountsChanged"],
        )?,
    )])?;
    let capabilities = capabilities([chain_capability(
        "eip155:1",
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
        ["personal_sign"],
        ["accountsChanged"],
    )?])?;

    let error = capabilities
        .validate_session_update_namespaces(&update)
        .expect_err("unsupported update account must be rejected");

    assert_eq!(
        error,
        SessionUpdateApprovalError::UnsupportedAccount {
            chain_id: Caip2ChainId::parse("eip155:1")?,
            account: Caip10AccountId::parse("eip155:1:0x2222222222222222222222222222222222222222",)?,
        }
    );

    Ok(())
}

fn proposal(
    required_namespaces: ProposalNamespaces,
    optional_namespaces: ProposalNamespaces,
) -> Result<JsonRpcRequest<SessionProposeParams>, Box<dyn std::error::Error>> {
    Ok(JsonRpcRequest::new(
        1,
        SignMethod::SessionPropose,
        SessionProposeParams {
            id: Some(1),
            pairing_topic: None,
            expiry: None,
            expiry_timestamp: Some(1_780_000_000),
            relays: vec![RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: None,
            }],
            proposer: wc_protocol::session::Proposer {
                public_key: X25519PublicKey::from_hex(
                    "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
                )?,
                metadata: DappMetadata {
                    name: "Dapp".to_owned(),
                    description: "Dapp".to_owned(),
                    url: "https://example.com/dapp".to_owned(),
                    icons: Vec::new(),
                    verify_url: None,
                    redirect: None,
                },
            },
            required_namespaces,
            optional_namespaces,
            session_properties: None,
            scoped_properties: None,
            attestation: None,
            encrypted_id: None,
            requests: None,
        },
    ))
}

fn namespaces(
    values: impl IntoIterator<Item = (&'static str, ProposalNamespace)>,
) -> Result<ProposalNamespaces, Box<dyn std::error::Error>> {
    let mut namespaces = BTreeMap::new();
    for (key, namespace) in values {
        namespaces.insert(NamespaceKey::parse(key)?, namespace);
    }
    Ok(namespaces)
}

fn session_namespaces(
    values: impl IntoIterator<Item = (&'static str, SessionNamespace)>,
) -> Result<SessionNamespaces, Box<dyn std::error::Error>> {
    let mut namespaces = BTreeMap::new();
    for (key, namespace) in values {
        namespaces.insert(NamespaceKey::parse(key)?, namespace);
    }
    Ok(namespaces)
}

fn proposal_namespace<
    const CHAIN_COUNT: usize,
    const METHOD_COUNT: usize,
    const EVENT_COUNT: usize,
>(
    chains: [&str; CHAIN_COUNT],
    methods: [&str; METHOD_COUNT],
    events: [&str; EVENT_COUNT],
) -> Result<ProposalNamespace, Box<dyn std::error::Error>> {
    Ok(ProposalNamespace {
        chains: Some(
            chains
                .into_iter()
                .map(Caip2ChainId::parse)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        methods: methods
            .into_iter()
            .map(str::parse::<SessionMethod>)
            .collect::<Result<Vec<_>, _>>()?,
        events: events
            .into_iter()
            .map(str::parse::<SessionEventName>)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn session_namespace<
    const CHAIN_COUNT: usize,
    const ACCOUNT_COUNT: usize,
    const METHOD_COUNT: usize,
    const EVENT_COUNT: usize,
>(
    chains: [&str; CHAIN_COUNT],
    accounts: [&str; ACCOUNT_COUNT],
    methods: [&str; METHOD_COUNT],
    events: [&str; EVENT_COUNT],
) -> Result<SessionNamespace, Box<dyn std::error::Error>> {
    Ok(SessionNamespace {
        chains: Some(
            chains
                .into_iter()
                .map(Caip2ChainId::parse)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        accounts: accounts
            .into_iter()
            .map(Caip10AccountId::parse)
            .collect::<Result<Vec<_>, _>>()?,
        methods: methods
            .into_iter()
            .map(str::parse::<SessionMethod>)
            .collect::<Result<Vec<_>, _>>()?,
        events: events
            .into_iter()
            .map(str::parse::<SessionEventName>)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn capabilities(
    chains: impl IntoIterator<Item = WalletChainCapability>,
) -> Result<WalletCapabilities, WalletCapabilityError> {
    WalletCapabilities::new(chains)
}

fn chain_capability<
    const ACCOUNT_COUNT: usize,
    const METHOD_COUNT: usize,
    const EVENT_COUNT: usize,
>(
    chain_id: &str,
    accounts: [&str; ACCOUNT_COUNT],
    methods: [&str; METHOD_COUNT],
    events: [&str; EVENT_COUNT],
) -> Result<WalletChainCapability, Box<dyn std::error::Error>> {
    WalletChainCapability::new(
        Caip2ChainId::parse(chain_id)?,
        accounts
            .into_iter()
            .map(Caip10AccountId::parse)
            .collect::<Result<Vec<_>, _>>()?,
        methods
            .into_iter()
            .map(str::parse::<SessionMethod>)
            .collect::<Result<Vec<_>, _>>()?,
        events
            .into_iter()
            .map(str::parse::<SessionEventName>)
            .collect::<Result<Vec<_>, _>>()?,
    )
    .map_err(Into::into)
}

fn wallet_metadata() -> DappMetadata {
    DappMetadata {
        name: "Wallet".to_owned(),
        description: "Wallet".to_owned(),
        url: "https://example.com/wallet".to_owned(),
        icons: Vec::new(),
        verify_url: None,
        redirect: None,
    }
}
