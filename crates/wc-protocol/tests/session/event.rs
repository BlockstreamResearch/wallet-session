use serde_json::json;
use wc_protocol::session::{JsonRpcRequest, SessionEvent, SessionEventParams, SignMethod};

const LIVE_SESSION_EVENT_JSON: &str = r#"{
  "id": 1779814971131764,
  "jsonrpc": "2.0",
  "method": "wc_sessionEvent",
  "params": {
    "event": {
      "name": "accountsChanged",
      "data": [
        "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
      ]
    },
    "chainId": "eip155:1"
  }
}"#;

#[test]
fn deserializes_live_event_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionEventParams>>(LIVE_SESSION_EVENT_JSON)
            .expect("session event parses");

    assert!(request.is_session_event());
    assert_eq!(request.method, SignMethod::SessionEvent);
    assert_eq!(request.params.chain_id, "eip155:1");
    assert_eq!(request.params.event.name, "accountsChanged");
    assert_eq!(
        request.params.event.data,
        json!(["eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"])
    );
}

#[test]
fn serializes_chain_specific_object_data() {
    let request = JsonRpcRequest::new(
        11,
        SignMethod::SessionEvent,
        SessionEventParams {
            event: SessionEvent {
                name: "chainChanged".to_owned(),
                data: json!({
                    "chainId": "0x1",
                    "networkVersion": "1"
                }),
            },
            chain_id: "eip155:1".to_owned(),
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionEvent");
    assert_eq!(value["params"]["chainId"], "eip155:1");
    assert_eq!(value["params"]["event"]["name"], "chainChanged");
    assert_eq!(value["params"]["event"]["data"]["chainId"], "0x1");
}

#[test]
fn preserves_null_and_scalar_data() {
    for data in [json!(null), json!(true), json!("0x1"), json!(1)] {
        let params = serde_json::from_value::<SessionEventParams>(json!({
            "event": {
                "name": "chainChanged",
                "data": data
            },
            "chainId": "eip155:1"
        }))
        .expect("parses");

        assert_eq!(params.event.name, "chainChanged");
        assert_eq!(params.chain_id, "eip155:1");
    }
}
