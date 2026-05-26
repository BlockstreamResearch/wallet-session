use std::collections::BTreeMap;

use serde_json::json;
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
    assert_eq!(
        request.params.namespaces["eip155"].chains.as_deref(),
        Some(["eip155:1".to_owned()].as_slice())
    );
    assert_eq!(
        request.params.namespaces["eip155"].accounts,
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
                "eip155".to_owned(),
                SessionNamespace {
                    chains: Some(vec!["eip155:1".to_owned()]),
                    accounts: vec![
                        "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb".to_owned(),
                        "eip155:1:0x1111111111111111111111111111111111111111".to_owned(),
                    ],
                    methods: vec!["personal_sign".to_owned()],
                    events: vec!["accountsChanged".to_owned(), "chainChanged".to_owned()],
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
        params.namespaces["eip155:42161"].accounts,
        ["eip155:42161:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]
    );
}
