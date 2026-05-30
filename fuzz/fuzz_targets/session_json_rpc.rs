#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_protocol::{
    dto::pairing::{
        PairingDeleteParams, PairingJsonRpcRequest, PairingJsonRpcResponse, PairingPingParams,
    },
    session::{
        JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResponse, SessionAuthenticateParams,
        SessionAuthenticateResult, SessionDeleteParams, SessionEventParams, SessionExtendParams,
        SessionProposeParams, SessionProposeResult, SessionRequestParams, SessionRequestResult,
        SessionSettleParams, SessionUpdateParams, WalletCallRequest,
    },
};

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    parse_sign_requests(&value);
    parse_sign_responses(&value);
    parse_pairing_messages(&value);
});

fn parse_sign_requests(value: &Value) {
    let _ = serde_json::from_value::<JsonRpcRequest<SessionProposeParams>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcRequest<SessionAuthenticateParams>>(value.clone());
    let request = serde_json::from_value::<JsonRpcRequest<SessionRequestParams>>(value.clone());
    if let Ok(request) = request {
        let _ = WalletCallRequest::from_session_request(&request.params.request);
    }
    let _ = serde_json::from_value::<JsonRpcRequest<SessionSettleParams>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcRequest<SessionUpdateParams>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcRequest<SessionExtendParams>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcRequest<SessionEventParams>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcRequest<SessionDeleteParams>>(value.clone());
}

fn parse_sign_responses(value: &Value) {
    let _ = serde_json::from_value::<JsonRpcResponse<SessionProposeResult>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcResponse<SessionAuthenticateResult>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcResponse<SessionRequestResult>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcResponse<bool>>(value.clone());
    let _ = serde_json::from_value::<JsonRpcErrorResponse>(value.clone());
}

fn parse_pairing_messages(value: &Value) {
    let _ = serde_json::from_value::<PairingJsonRpcRequest<PairingPingParams>>(value.clone());
    let _ = serde_json::from_value::<PairingJsonRpcRequest<PairingDeleteParams>>(value.clone());
    let _ = serde_json::from_value::<PairingJsonRpcResponse<bool>>(value.clone());
}
