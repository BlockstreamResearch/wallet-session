//! Integration tests for Pairing API DTOs.

use serde_json::json;
use wc_protocol::dto::pairing::{
    PairingDeleteParams, PairingJsonRpcRequest, PairingJsonRpcResponse, PairingMethod,
    PairingPingParams,
};

const LIVE_PAIRING_PING_JSON: &str = r#"{
  "id": 1779866795062281,
  "jsonrpc": "2.0",
  "method": "wc_pairingPing",
  "params": {}
}"#;

const LIVE_PAIRING_PING_RESPONSE_JSON: &str = r#"{
  "id": 1779866795062281,
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_PAIRING_DELETE_JSON: &str = r#"{
  "id": 1779866796850380,
  "jsonrpc": "2.0",
  "method": "wc_pairingDelete",
  "params": {
    "message": "User disconnected.",
    "code": 6000
  }
}"#;

#[test]
fn deserializes_live_pairing_ping_shape() {
    let request =
        serde_json::from_str::<PairingJsonRpcRequest<PairingPingParams>>(LIVE_PAIRING_PING_JSON)
            .expect("pairing ping parses");

    assert!(request.is_pairing_ping());
    assert_eq!(request.id, 1_779_866_795_062_281);
    assert_eq!(request.method, PairingMethod::Ping);
}

#[test]
fn deserializes_live_pairing_ping_response_shape() {
    let response =
        serde_json::from_str::<PairingJsonRpcResponse<bool>>(LIVE_PAIRING_PING_RESPONSE_JSON)
            .expect("pairing ping response parses");

    assert_eq!(response.id, 1_779_866_795_062_281);
    assert!(response.result);
}

#[test]
fn deserializes_live_pairing_delete_shape() {
    let request = serde_json::from_str::<PairingJsonRpcRequest<PairingDeleteParams>>(
        LIVE_PAIRING_DELETE_JSON,
    )
    .expect("pairing delete parses");

    assert!(request.is_pairing_delete());
    assert_eq!(request.id, 1_779_866_796_850_380);
    assert_eq!(request.method, PairingMethod::Delete);
    assert_eq!(
        request.params.code,
        PairingDeleteParams::USER_DISCONNECTED_CODE
    );
    assert_eq!(
        request.params.message,
        PairingDeleteParams::USER_DISCONNECTED_MESSAGE
    );
}

#[test]
fn serializes_pairing_ping_request_and_response() {
    let request = PairingJsonRpcRequest::new(7, PairingMethod::Ping, PairingPingParams::default());
    let response = PairingJsonRpcResponse::new(7, true);

    let request_value = serde_json::to_value(request).expect("serializes request");
    let response_value = serde_json::to_value(response).expect("serializes response");

    assert_eq!(request_value["jsonrpc"], "2.0");
    assert_eq!(request_value["method"], "wc_pairingPing");
    assert_eq!(request_value["params"], json!({}));
    assert_eq!(response_value["jsonrpc"], "2.0");
    assert_eq!(response_value["result"], true);
}

#[test]
fn serializes_pairing_delete_request() {
    let request = PairingJsonRpcRequest::new(
        8,
        PairingMethod::Delete,
        PairingDeleteParams::user_disconnected(),
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_pairingDelete");
    assert_eq!(
        value["params"]["code"],
        PairingDeleteParams::USER_DISCONNECTED_CODE
    );
    assert_eq!(
        value["params"]["message"],
        PairingDeleteParams::USER_DISCONNECTED_MESSAGE
    );
}
