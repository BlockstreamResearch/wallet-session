use serde_json::json;
use wc_protocol::session::{JsonRpcRequest, SessionPingParams, SignMethod};

const LIVE_SESSION_PING_JSON: &str = r#"{
  "id": 1779815548912752,
  "jsonrpc": "2.0",
  "method": "wc_sessionPing",
  "params": {}
}"#;

#[test]
fn deserializes_live_ping_shape() {
    let request = serde_json::from_str::<JsonRpcRequest<SessionPingParams>>(LIVE_SESSION_PING_JSON)
        .expect("session ping parses");

    assert!(request.is_session_ping());
    assert_eq!(request.method, SignMethod::SessionPing);
    assert_eq!(request.params, SessionPingParams::default());
}

#[test]
fn serializes_empty_params() {
    let request = JsonRpcRequest::new(17, SignMethod::SessionPing, SessionPingParams::default());

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionPing");
    assert_eq!(value["params"], json!({}));
}

#[test]
fn accepts_record_shaped_params() {
    let value = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "wc_sessionPing",
        "params": {
            "ignored": true
        }
    });

    let request = serde_json::from_value::<JsonRpcRequest<SessionPingParams>>(value)
        .expect("record-shaped params parse");

    assert_eq!(request.params, SessionPingParams::default());
}
