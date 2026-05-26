use serde_json::json;
use wc_protocol::session::{JsonRpcRequest, SessionExtendParams, SignMethod};

const LIVE_SESSION_EXTEND_JSON: &str = r#"{
  "id": 1779814634097256,
  "jsonrpc": "2.0",
  "method": "wc_sessionExtend",
  "params": {}
}"#;

#[test]
fn deserializes_live_extend_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionExtendParams>>(LIVE_SESSION_EXTEND_JSON)
            .expect("session extend parses");

    assert!(request.is_session_extend());
    assert_eq!(request.method, SignMethod::SessionExtend);
    assert_eq!(request.params.expiry, None);
    assert!(!request.params.is_expired_at(1_800_000_000));
}

#[test]
fn deserializes_spec_expiry_shape() {
    let value = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "wc_sessionExtend",
        "params": {
            "expiry": 1_780_419_434
        }
    });

    let request =
        serde_json::from_value::<JsonRpcRequest<SessionExtendParams>>(value).expect("parses");

    assert_eq!(request.params.expiry, Some(1_780_419_434));
    assert!(request.params.is_expired_at(1_800_000_000));
}

#[test]
fn serializes_empty_params_by_default() {
    let request = JsonRpcRequest::new(5, SignMethod::SessionExtend, SessionExtendParams::default());

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionExtend");
    assert_eq!(value["params"], json!({}));
}
