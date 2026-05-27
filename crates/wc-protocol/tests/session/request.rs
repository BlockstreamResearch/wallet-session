use serde_json::json;

use super::{chain, method};
use wc_protocol::session::{
    JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse, JsonRpcRequest, SessionRequest,
    SessionRequestErrorResponse, SessionRequestParams, SessionRequestResponse, SignMethod,
    session_request_error_response, session_request_success_response,
};

const LIVE_PERSONAL_SIGN_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "method": "wc_sessionRequest",
  "params": {
    "request": {
      "method": "personal_sign",
      "params": [
        "0x68656c6c6f2077616c6c6574636f6e6e6563742d7273",
        "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
      ],
      "expiryTimestamp": 1779813158
    },
    "chainId": "eip155:1"
  }
}"#;

const LIVE_SESSION_REQUEST_SUCCESS_STRING_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "result": "0xsignature"
}"#;

const LIVE_SESSION_REQUEST_SUCCESS_OBJECT_JSON: &str = r#"{
  "id": 1779812558761961,
  "jsonrpc": "2.0",
  "result": {
    "transactionHash": "0xabc",
    "nested": {
      "ok": true
    }
  }
}"#;

const LIVE_SESSION_REQUEST_SUCCESS_ARRAY_JSON: &str = r#"{
  "id": 1779812558761962,
  "jsonrpc": "2.0",
  "result": ["0x1", "0x2"]
}"#;

const LIVE_SESSION_REQUEST_USER_REJECTED_JSON: &str = r#"{
  "id": 1779812558761963,
  "jsonrpc": "2.0",
  "error": {
    "message": "User rejected.",
    "code": 5000
  }
}"#;

const LIVE_SESSION_REQUEST_INVALID_METHOD_WITH_DATA_JSON: &str = r#"{
  "id": 1779812558761964,
  "jsonrpc": "2.0",
  "error": {
    "message": "Invalid method.",
    "code": 1001,
    "data": "method not approved"
  }
}"#;

#[test]
fn deserializes_live_personal_sign_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionRequestParams>>(LIVE_PERSONAL_SIGN_JSON)
            .expect("session request parses");

    assert!(request.is_session_request());
    assert_eq!(request.method, SignMethod::SessionRequest);
    assert_eq!(request.params.chain_id.as_str(), "eip155:1");
    assert_eq!(request.params.request.method.as_str(), "personal_sign");
    assert_eq!(
        request.params.request.params,
        json!([
            "0x68656c6c6f2077616c6c6574636f6e6e6563742d7273",
            "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
        ])
    );
    assert_eq!(request.params.request.expiry_timestamp, Some(1_779_813_158));
    assert!(request.params.is_expired_at(1_800_000_000));
}

#[test]
fn deserializes_spec_expiry_alias() {
    let value = json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "wc_sessionRequest",
        "params": {
            "request": {
                "method": "eth_signTransaction",
                "params": [{
                    "from": "0x1456225dE90927193F7A171E64a600416f96f2C8",
                    "to": "0x1456225dE90927193F7A171E64a600416f96f2C8",
                    "data": "0x",
                    "nonce": "0x00",
                    "gasPrice": "0xa72c",
                    "gasLimit": "0x5208",
                    "value": "0x00"
                }],
                "expiry": 1_700_000_300
            },
            "chainId": "eip155:5"
        }
    });

    let request =
        serde_json::from_value::<JsonRpcRequest<SessionRequestParams>>(value).expect("parses");

    assert_eq!(request.params.chain_id.as_str(), "eip155:5");
    assert_eq!(
        request.params.request.method.as_str(),
        "eth_signTransaction"
    );
    assert_eq!(request.params.request.expiry_timestamp, Some(1_700_000_300));
}

#[test]
fn serializes_current_expiry_timestamp_name() {
    let request = JsonRpcRequest::new(
        9,
        SignMethod::SessionRequest,
        SessionRequestParams {
            chain_id: chain("eip155:1"),
            request: SessionRequest {
                method: method("personal_sign"),
                params: json!(["0x68656c6c6f", "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"]),
                expiry_timestamp: Some(1_700_000_300),
            },
        },
    );

    let value = serde_json::to_value(request).expect("serializes");

    assert_eq!(value["method"], "wc_sessionRequest");
    assert_eq!(value["params"]["chainId"], "eip155:1");
    assert_eq!(value["params"]["request"]["method"], "personal_sign");
    assert_eq!(value["params"]["request"]["expiryTimestamp"], 1_700_000_300);
    assert!(value["params"]["request"].get("expiry").is_none());
}

#[test]
fn preserves_object_params_without_expiry() {
    let value = json!({
        "chainId": "eip155:1",
        "request": {
            "method": "wallet_sendCalls",
            "params": {
                "version": "2.0.0",
                "from": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
                "chainId": "0x1",
                "calls": []
            }
        }
    });

    let params = serde_json::from_value::<SessionRequestParams>(value).expect("parses");

    assert_eq!(params.request.expiry_timestamp, None);
    assert_eq!(params.request.params["version"], "2.0.0");
    assert!(!params.is_expired_at(1_800_000_000));
}

#[test]
fn deserializes_live_session_request_success_string_result() {
    let response =
        serde_json::from_str::<SessionRequestResponse>(LIVE_SESSION_REQUEST_SUCCESS_STRING_JSON)
            .expect("success response parses");

    assert_eq!(response.id, 1_779_812_558_761_960);
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.result.as_value(), &json!("0xsignature"));
}

#[test]
fn deserializes_live_session_request_success_object_result() {
    let response =
        serde_json::from_str::<SessionRequestResponse>(LIVE_SESSION_REQUEST_SUCCESS_OBJECT_JSON)
            .expect("success response parses");

    assert_eq!(response.id, 1_779_812_558_761_961);
    assert_eq!(response.result.as_value()["transactionHash"], "0xabc");
    assert_eq!(response.result.as_value()["nested"]["ok"], true);
}

#[test]
fn deserializes_live_session_request_success_array_result() {
    let response =
        serde_json::from_str::<SessionRequestResponse>(LIVE_SESSION_REQUEST_SUCCESS_ARRAY_JSON)
            .expect("success response parses");

    assert_eq!(response.id, 1_779_812_558_761_962);
    assert_eq!(response.result.as_value(), &json!(["0x1", "0x2"]));
}

#[test]
fn serializes_session_request_success_response_like_walletconnect_js() {
    let response = session_request_success_response(1_779_812_558_761_960, json!("0xsignature"));
    let value = serde_json::to_value(response).expect("serializes");
    let live = serde_json::from_str::<serde_json::Value>(LIVE_SESSION_REQUEST_SUCCESS_STRING_JSON)
        .expect("live fixture parses");

    assert_eq!(value, live);
}

#[test]
fn deserializes_live_session_request_user_rejected_error() {
    let response = serde_json::from_str::<SessionRequestErrorResponse>(
        LIVE_SESSION_REQUEST_USER_REJECTED_JSON,
    )
    .expect("error response parses");

    assert_eq!(response.id, 1_779_812_558_761_963);
    assert_eq!(response.error.code, JsonRpcErrorCode::UserRejected);
    assert_eq!(response.error.message, "User rejected.");
    assert_eq!(response.error.data, None);
}

#[test]
fn deserializes_live_session_request_invalid_method_error_with_data() {
    let response = serde_json::from_str::<JsonRpcErrorResponse>(
        LIVE_SESSION_REQUEST_INVALID_METHOD_WITH_DATA_JSON,
    )
    .expect("error response parses");

    assert_eq!(response.id, 1_779_812_558_761_964);
    assert_eq!(response.error.code, JsonRpcErrorCode::InvalidMethod);
    assert_eq!(response.error.message, "Invalid method.");
    assert_eq!(response.error.data, Some(json!("method not approved")));
}

#[test]
fn serializes_session_request_error_response_like_walletconnect_js() {
    let response = session_request_error_response(
        1_779_812_558_761_963,
        JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
    );
    let value = serde_json::to_value(response).expect("serializes");
    let live = serde_json::from_str::<serde_json::Value>(LIVE_SESSION_REQUEST_USER_REJECTED_JSON)
        .expect("live fixture parses");

    assert_eq!(value, live);
}
