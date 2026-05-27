use wc_protocol::session::{
    JsonRpcResponse, SessionAck, SessionAckResponse, SessionDeleteResponse, SessionEventResponse,
    SessionExtendResponse, SessionPingResponse, SessionSettleResponse, SessionUpdateResponse,
    session_ack_response,
};

const LIVE_ACK_TRUE_ID_ZERO_JSON: &str = r#"{
  "id": 0,
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_ACK_TRUE_TYPICAL_ID_JSON: &str = r#"{
  "id": 1779812558761960,
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_ACK_TRUE_MAX_SAFE_ID_JSON: &str = r#"{
  "id": 9007199254740991,
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_FALSE_RESULT_EDGE_JSON: &str = r#"{
  "id": 1779812558761961,
  "jsonrpc": "2.0",
  "result": false
}"#;

const LIVE_NULL_RESULT_EDGE_JSON: &str = r#"{
  "id": 1779812558761962,
  "jsonrpc": "2.0",
  "result": null
}"#;

const LIVE_STRING_RESULT_EDGE_JSON: &str = r#"{
  "id": 1779812558761963,
  "jsonrpc": "2.0",
  "result": "true"
}"#;

const LIVE_STRING_ID_EDGE_JSON: &str = r#"{
  "id": "1779812558761960",
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_NEGATIVE_ID_EDGE_JSON: &str = r#"{
  "id": -1,
  "jsonrpc": "2.0",
  "result": true
}"#;

const LIVE_FLOAT_ID_EDGE_JSON: &str = r#"{
  "id": 1.5,
  "jsonrpc": "2.0",
  "result": true
}"#;

#[test]
fn deserializes_live_ack_true_edge_ids() {
    let zero = serde_json::from_str::<SessionAckResponse>(LIVE_ACK_TRUE_ID_ZERO_JSON)
        .expect("zero id ack parses");
    let typical = serde_json::from_str::<SessionAckResponse>(LIVE_ACK_TRUE_TYPICAL_ID_JSON)
        .expect("typical id ack parses");
    let max_safe = serde_json::from_str::<SessionAckResponse>(LIVE_ACK_TRUE_MAX_SAFE_ID_JSON)
        .expect("max safe id ack parses");

    assert_eq!(zero.id, 0);
    assert_eq!(zero.result, SessionAck);
    assert_eq!(typical.id, 1_779_812_558_761_960);
    assert_eq!(typical.result, SessionAck);
    assert_eq!(max_safe.id, 9_007_199_254_740_991);
    assert_eq!(max_safe.result, SessionAck);
}

#[test]
fn serializes_ack_response_like_walletconnect_js() {
    let response = session_ack_response(1_779_812_558_761_960);
    let value = serde_json::to_value(response).expect("serializes");
    let live = serde_json::from_str::<serde_json::Value>(LIVE_ACK_TRUE_TYPICAL_ID_JSON)
        .expect("live fixture parses");

    assert_eq!(value, live);
}

#[test]
fn rejects_live_formatter_non_ack_result_edges() {
    for json in [
        LIVE_FALSE_RESULT_EDGE_JSON,
        LIVE_NULL_RESULT_EDGE_JSON,
        LIVE_STRING_RESULT_EDGE_JSON,
    ] {
        assert!(serde_json::from_str::<SessionAckResponse>(json).is_err());
    }
}

#[test]
fn rejects_live_formatter_non_numeric_u64_id_edges() {
    for json in [
        LIVE_STRING_ID_EDGE_JSON,
        LIVE_NEGATIVE_ID_EDGE_JSON,
        LIVE_FLOAT_ID_EDGE_JSON,
    ] {
        assert!(serde_json::from_str::<SessionAckResponse>(json).is_err());
    }
}

#[test]
fn method_response_aliases_use_the_strict_ack_payload() {
    let settle: SessionSettleResponse = session_ack_response(1);
    let update: SessionUpdateResponse = session_ack_response(2);
    let extend: SessionExtendResponse = session_ack_response(3);
    let ping: SessionPingResponse = session_ack_response(4);
    let event: SessionEventResponse = session_ack_response(5);
    let delete: SessionDeleteResponse = session_ack_response(6);

    assert_eq!(settle.result, SessionAck);
    assert_eq!(update.result, SessionAck);
    assert_eq!(extend.result, SessionAck);
    assert_eq!(ping.result, SessionAck);
    assert_eq!(event.result, SessionAck);
    assert_eq!(delete.result, SessionAck);
}

#[test]
fn ack_payload_is_not_interchangeable_with_loose_bool_response() {
    let loose = serde_json::from_str::<JsonRpcResponse<bool>>(LIVE_FALSE_RESULT_EDGE_JSON)
        .expect("generic bool response parses false");

    assert!(!loose.result);
    assert!(serde_json::from_str::<SessionAckResponse>(LIVE_FALSE_RESULT_EDGE_JSON).is_err());
}
