use serde_json::json;
use wc_protocol::session::{JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod};

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

#[test]
fn deserializes_live_personal_sign_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionRequestParams>>(LIVE_PERSONAL_SIGN_JSON)
            .expect("session request parses");

    assert!(request.is_session_request());
    assert_eq!(request.method, SignMethod::SessionRequest);
    assert_eq!(request.params.chain_id, "eip155:1");
    assert_eq!(request.params.request.method, "personal_sign");
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

    assert_eq!(request.params.chain_id, "eip155:5");
    assert_eq!(request.params.request.method, "eth_signTransaction");
    assert_eq!(request.params.request.expiry_timestamp, Some(1_700_000_300));
}

#[test]
fn serializes_current_expiry_timestamp_name() {
    let request = JsonRpcRequest::new(
        9,
        SignMethod::SessionRequest,
        SessionRequestParams {
            chain_id: "eip155:1".to_owned(),
            request: SessionRequest {
                method: "personal_sign".to_owned(),
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
