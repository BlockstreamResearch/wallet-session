use std::collections::BTreeMap;

use serde_json::json;
use wc_protocol::session::{
    DappMetadata, JsonRpcRequest, RelayProtocolOptions, SessionConfig, SessionNamespace,
    SessionParticipant, SessionSettleParams, SignMethod, SpecialNamespace,
};

const LIVE_SESSION_SETTLE_JSON: &str = r#"{
  "id": 1779813457451118,
  "jsonrpc": "2.0",
  "method": "wc_sessionSettle",
  "params": {
    "relay": {
      "protocol": "irn"
    },
    "namespaces": {
      "eip155": {
        "chains": [
          "eip155:1"
        ],
        "methods": [
          "personal_sign"
        ],
        "events": [
          "accountsChanged",
          "chainChanged"
        ],
        "accounts": [
          "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
        ]
      }
    },
    "controller": {
      "publicKey": "316472c516263b72d3b79e1e4a8260e4c2dfbf908c25698fee126c0888ea445f",
      "metadata": {
        "name": "wc-rs live settle wallet",
        "description": "Temporary live probe wallet",
        "url": "https://example.com/wallet",
        "icons": [
          ""
        ]
      }
    },
    "expiry": 1780418257
  }
}"#;

#[test]
fn deserializes_live_settle_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionSettleParams>>(LIVE_SESSION_SETTLE_JSON)
            .expect("session settle parses");

    assert!(request.is_session_settle());
    assert_eq!(request.method, SignMethod::SessionSettle);
    assert_eq!(request.params.relay.protocol, "irn");
    assert_eq!(
        request.params.controller.public_key,
        "316472c516263b72d3b79e1e4a8260e4c2dfbf908c25698fee126c0888ea445f"
    );
    assert_eq!(
        request.params.controller.metadata.name,
        "wc-rs live settle wallet"
    );
    assert_eq!(
        request.params.namespaces["eip155"].chains.as_deref(),
        Some(["eip155:1".to_owned()].as_slice())
    );
    assert_eq!(
        request.params.namespaces["eip155"].accounts,
        ["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]
    );
    assert_eq!(request.params.expiry, 1_780_418_257);
    assert!(request.params.is_expired_at(1_800_000_000));
}

#[test]
fn serializes_current_optional_fields() {
    let request = JsonRpcRequest::new(
        3,
        SignMethod::SessionSettle,
        SessionSettleParams {
            relay: RelayProtocolOptions {
                protocol: "irn".to_owned(),
                data: Some("relay-data".to_owned()),
            },
            namespaces: BTreeMap::from([(
                "eip155".to_owned(),
                SessionNamespace {
                    chains: Some(vec!["eip155:1".to_owned()]),
                    accounts: vec![
                        "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".to_owned(),
                    ],
                    methods: vec!["personal_sign".to_owned()],
                    events: vec!["accountsChanged".to_owned()],
                },
            )]),
            controller: SessionParticipant {
                public_key: "316472c516263b72d3b79e1e4a8260e4c2dfbf908c25698fee126c0888ea445f"
                    .to_owned(),
                metadata: DappMetadata {
                    name: "Wallet".to_owned(),
                    description: "Wallet app".to_owned(),
                    url: "https://example.com/wallet".to_owned(),
                    icons: vec![],
                    verify_url: None,
                    redirect: None,
                },
            },
            expiry: 1_780_418_257,
            session_properties: Some(BTreeMap::from([(
                "caip154-mandatory".to_owned(),
                "true".to_owned(),
            )])),
            scoped_properties: Some(BTreeMap::from([(
                "eip155:1".to_owned(),
                json!({"walletService": ["https://example.com"]}),
            )])),
            session_config: Some(SessionConfig {
                disable_deep_link: Some(true),
            }),
            special_namespaces: Some(BTreeMap::from([(
                "cosmos".to_owned(),
                SpecialNamespace {
                    methods: vec!["cosmos_signDirect".to_owned()],
                    events: vec![],
                },
            )])),
            proposal_requests_responses: Some(json!({
                "authentication": [],
                "walletPay": []
            })),
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionSettle");
    assert_eq!(value["params"]["relay"]["data"], "relay-data");
    assert_eq!(
        value["params"]["sessionProperties"]["caip154-mandatory"],
        "true"
    );
    assert_eq!(value["params"]["sessionConfig"]["disableDeepLink"], true);
    assert_eq!(
        value["params"]["specialNamespaces"]["cosmos"]["methods"],
        json!(["cosmos_signDirect"])
    );
    assert_eq!(
        value["params"]["proposalRequestsResponses"]["authentication"],
        json!([])
    );
}

#[test]
fn preserves_namespace_without_chains() {
    let value = json!({
        "relay": {"protocol": "irn"},
        "namespaces": {
            "eip155:42161": {
                "accounts": ["eip155:42161:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
                "methods": ["personal_sign"],
                "events": []
            }
        },
        "controller": {
            "publicKey": "316472c516263b72d3b79e1e4a8260e4c2dfbf908c25698fee126c0888ea445f",
            "metadata": {
                "name": "Wallet",
                "description": "Wallet app",
                "url": "https://example.com/wallet",
                "icons": []
            }
        },
        "expiry": 1_780_418_257
    });

    let params = serde_json::from_value::<SessionSettleParams>(value).expect("parses");

    assert_eq!(params.namespaces["eip155:42161"].chains, None);
    assert!(!params.is_expired_at(1_700_000_000));
}
