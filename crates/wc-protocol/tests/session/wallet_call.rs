use serde_json::json;

use super::method;
use wc_protocol::session::{
    JsonRpcRequest, SessionRequest, SessionRequestParams, WalletCallMethod, WalletCallRequest,
    WalletCallRequestError, WalletGetCallsStatusParams, WalletGetCallsStatusResult,
    WalletGetCapabilitiesParams, WalletSendCallsParams, WalletSendCallsResult,
    WalletShowCallsStatusParams,
};

const LIVE_WALLET_GET_CAPABILITIES_JSON: &str = r#"{
  "id": 1780066411466810,
  "jsonrpc": "2.0",
  "method": "wc_sessionRequest",
  "params": {
    "request": {
      "method": "wallet_getCapabilities",
      "params": [
        "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        ["0x1"]
      ],
      "expiryTimestamp": 1780066711
    },
    "chainId": "eip155:1"
  }
}"#;

const LIVE_WALLET_SEND_CALLS_JSON: &str = r#"{
  "id": 1780066445063620,
  "jsonrpc": "2.0",
  "method": "wc_sessionRequest",
  "params": {
    "request": {
      "method": "wallet_sendCalls",
      "params": [{
        "version": "2.0.0",
        "from": "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb",
        "chainId": "0x1",
        "atomicRequired": true,
        "calls": [{
          "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
          "value": "0x0",
          "data": "0x"
        }],
        "capabilities": {
          "paymasterService": {
            "url": "https://example.com/paymaster",
            "optional": true
          }
        }
      }],
      "expiryTimestamp": 1780066745
    },
    "chainId": "eip155:1"
  }
}"#;

#[test]
fn deserializes_live_wallet_get_capabilities_request_shape() {
    let request = serde_json::from_str::<JsonRpcRequest<SessionRequestParams>>(
        LIVE_WALLET_GET_CAPABILITIES_JSON,
    )
    .expect("wallet_getCapabilities request parses");

    let wallet_call = WalletCallRequest::from_session_request(&request.params.request)
        .expect("wallet call params parse")
        .expect("wallet call method");

    assert_eq!(wallet_call.method(), WalletCallMethod::GetCapabilities);
    let WalletCallRequest::GetCapabilities(WalletGetCapabilitiesParams(address, chains)) =
        wallet_call
    else {
        panic!("expected wallet_getCapabilities");
    };
    assert_eq!(address, "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
    assert_eq!(chains, Some(vec!["0x1".to_owned()]));
}

#[test]
fn deserializes_live_wallet_send_calls_request_shape() {
    let request =
        serde_json::from_str::<JsonRpcRequest<SessionRequestParams>>(LIVE_WALLET_SEND_CALLS_JSON)
            .expect("wallet_sendCalls request parses");

    let wallet_call = WalletCallRequest::from_session_request(&request.params.request)
        .expect("wallet call params parse")
        .expect("wallet call method");

    assert_eq!(wallet_call.method(), WalletCallMethod::SendCalls);
    let WalletCallRequest::SendCalls(WalletSendCallsParams(send_calls)) = wallet_call else {
        panic!("expected wallet_sendCalls");
    };
    assert_eq!(send_calls.version, "2.0.0");
    assert_eq!(
        send_calls.from.as_deref(),
        Some("0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
    );
    assert_eq!(send_calls.chain_id, "0x1");
    assert!(send_calls.atomic_required);
    assert_eq!(send_calls.calls.len(), 1);
    assert_eq!(
        send_calls.calls[0].to.as_deref(),
        Some("0xd46e8dd67c5d32be8058bb8eb970870f07244567")
    );
    assert_eq!(
        send_calls.capabilities.as_ref().expect("capability exists")["paymasterService"]["optional"],
        true
    );
}

#[test]
fn parses_wallet_call_status_request_shapes() {
    let bundle_id = "0xe670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331";
    let get_status = SessionRequest {
        method: method("wallet_getCallsStatus"),
        params: json!([bundle_id]),
        expiry_timestamp: None,
    };
    let show_status = SessionRequest {
        method: method("wallet_showCallsStatus"),
        params: json!([bundle_id]),
        expiry_timestamp: None,
    };

    let get_status = WalletCallRequest::from_session_request(&get_status)
        .expect("get status parses")
        .expect("wallet call");
    let show_status = WalletCallRequest::from_session_request(&show_status)
        .expect("show status parses")
        .expect("wallet call");

    assert!(matches!(
        get_status,
        WalletCallRequest::GetCallsStatus(WalletGetCallsStatusParams(id)) if id == bundle_id
    ));
    assert!(matches!(
        show_status,
        WalletCallRequest::ShowCallsStatus(WalletShowCallsStatusParams(id)) if id == bundle_id
    ));
}

#[test]
fn parses_wallet_get_capabilities_without_chain_filter() {
    let params = serde_json::from_value::<WalletGetCapabilitiesParams>(json!([
        "0xd46e8dd67c5d32be8058bb8eb970870f07244567"
    ]))
    .expect("optional chain list may be absent");

    assert_eq!(params.0, "0xd46e8dd67c5d32be8058bb8eb970870f07244567");
    assert_eq!(params.1, None);
}

#[test]
fn ignores_non_wallet_call_session_methods() {
    let request = SessionRequest {
        method: method("personal_sign"),
        params: json!([]),
        expiry_timestamp: None,
    };

    let wallet_call =
        WalletCallRequest::from_session_request(&request).expect("non-wallet call is not an error");

    assert!(wallet_call.is_none());
}

#[test]
fn surfaces_source_for_malformed_wallet_call_params() {
    let request = SessionRequest {
        method: method("wallet_getCallsStatus"),
        params: json!({"id": "not-an-array"}),
        expiry_timestamp: None,
    };

    let error = WalletCallRequest::from_session_request(&request)
        .expect_err("wallet_getCallsStatus params must be a tuple array");

    assert!(matches!(
        error,
        WalletCallRequestError::Params {
            method: WalletCallMethod::GetCallsStatus,
            ..
        }
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn serializes_wallet_send_calls_result_shape() {
    let result = WalletSendCallsResult {
        id: "0x0000000000000000000000000000000000000000000000000000000000000001".to_owned(),
        capabilities: None,
    };

    let value = serde_json::to_value(result).expect("serializes");

    assert_eq!(
        value,
        json!({
            "id": "0x0000000000000000000000000000000000000000000000000000000000000001"
        })
    );
}

#[test]
fn deserializes_wallet_get_calls_status_result_with_receipt_subset() {
    let result = serde_json::from_value::<WalletGetCallsStatusResult>(json!({
        "version": "2.0.0",
        "chainId": "0x01",
        "id": "0x00000000000000000000000000000000000000000000000000000000000000000e670ec64341771606e55d6b4ca35a1a6b75ee3d5145a99d05921026d1527331",
        "status": 200,
        "atomic": true,
        "receipts": [{
            "logs": [{
                "address": "0xa922b54716264130634d6ff183747a8ead91a40b",
                "topics": ["0x5a2a90727cc9d000dd060b1132a5c977c9702bb3a52afe360c9c22f0e9451a68"],
                "data": "0xabcd"
            }],
            "status": "0x1",
            "blockHash": "0xf19bbafd9fd0124ec110b848e8de4ab4f62bf60c189524e54213285e7f540d4a",
            "blockNumber": "0xabcd",
            "gasUsed": "0xdef",
            "transactionHash": "0x9b7bb827c2e5e3c1a0a44dc53e573aa0b3af3bd1f9f5ed03071b100bb039eaff"
        }]
    }))
    .expect("status result parses");

    assert_eq!(result.status, 200);
    assert_eq!(
        result.receipts.expect("receipt exists")[0].logs[0].data,
        "0xabcd"
    );
}
