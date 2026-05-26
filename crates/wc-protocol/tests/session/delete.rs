use wc_protocol::session::{JsonRpcRequest, SessionDeleteParams, SignMethod};

const LIVE_SESSION_DELETE_JSON: &str = r#"{
  "id": 1779815254038350,
  "jsonrpc": "2.0",
  "method": "wc_sessionDelete",
  "params": {
    "message": "User disconnected.",
    "code": 6000
  }
}"#;

#[test]
fn deserializes_live_delete_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionDeleteParams>>(LIVE_SESSION_DELETE_JSON)
            .expect("session delete parses");

    assert!(request.is_session_delete());
    assert_eq!(request.method, SignMethod::SessionDelete);
    assert_eq!(
        request.params,
        SessionDeleteParams {
            code: SessionDeleteParams::USER_DISCONNECTED_CODE,
            message: SessionDeleteParams::USER_DISCONNECTED_MESSAGE.to_owned(),
        }
    );
}

#[test]
fn serializes_user_disconnected_reason() {
    let request = JsonRpcRequest::new(
        13,
        SignMethod::SessionDelete,
        SessionDeleteParams::user_disconnected(),
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionDelete");
    assert_eq!(
        value["params"]["code"],
        SessionDeleteParams::USER_DISCONNECTED_CODE
    );
    assert_eq!(
        value["params"]["message"],
        SessionDeleteParams::USER_DISCONNECTED_MESSAGE
    );
}

#[test]
fn preserves_custom_reason() {
    let value = serde_json::json!({
        "code": 6001,
        "message": "Session closed by wallet policy."
    });

    let params = serde_json::from_value::<SessionDeleteParams>(value).expect("parses");

    assert_eq!(params.code, 6001);
    assert_eq!(params.message, "Session closed by wallet policy.");
}
