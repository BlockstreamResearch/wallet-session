use std::collections::BTreeMap;

use serde_json::json;

use super::{account, account_strings, chain, chain_strings, event_name, method};
use wc_protocol::session::{JsonRpcRequest, SessionNamespace, SessionUpdateParams, SignMethod};

const LIVE_SESSION_UPDATE_JSON: &str = r#"{
  "id": 1779814258441957,
  "jsonrpc": "2.0",
  "method": "wc_sessionUpdate",
  "params": {
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
          "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
          "eip155:1:0x1111111111111111111111111111111111111111"
        ]
      }
    }
  }
}"#;

#[test]
fn deserializes_live_update_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionUpdateParams>>(LIVE_SESSION_UPDATE_JSON)
            .expect("session update parses");

    assert!(request.is_session_update());
    assert_eq!(request.method, SignMethod::SessionUpdate);
    let chains = request.params.namespaces["eip155"]
        .chains
        .as_deref()
        .expect("chains");
    assert_eq!(chain_strings(chains), ["eip155:1"]);
    assert_eq!(
        account_strings(&request.params.namespaces["eip155"].accounts),
        [
            "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
            "eip155:1:0x1111111111111111111111111111111111111111"
        ]
    );
}

#[test]
fn serializes_namespace_replacement() {
    let request = JsonRpcRequest::new(
        7,
        SignMethod::SessionUpdate,
        SessionUpdateParams {
            namespaces: BTreeMap::from([(
                "eip155".parse().expect("namespace key parses"),
                SessionNamespace {
                    chains: Some(vec![chain("eip155:1")]),
                    accounts: vec![
                        account("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"),
                        account("eip155:1:0x1111111111111111111111111111111111111111"),
                    ],
                    methods: vec![method("personal_sign")],
                    events: vec![event_name("accountsChanged"), event_name("chainChanged")],
                },
            )]),
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionUpdate");
    assert_eq!(
        value["params"]["namespaces"]["eip155"]["accounts"],
        json!([
            "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
            "eip155:1:0x1111111111111111111111111111111111111111"
        ])
    );
}

#[test]
fn preserves_namespace_without_chains() {
    let value = json!({
        "namespaces": {
            "eip155:42161": {
                "accounts": ["eip155:42161:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"],
                "methods": ["personal_sign"],
                "events": []
            }
        }
    });

    let params = serde_json::from_value::<SessionUpdateParams>(value).expect("parses");

    assert_eq!(params.namespaces["eip155:42161"].chains, None);
    assert_eq!(
        account_strings(&params.namespaces["eip155:42161"].accounts),
        ["eip155:42161:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]
    );
}
