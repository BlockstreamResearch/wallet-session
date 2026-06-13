#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_core::{
    SessionAuthenticateReview, SessionRequestApproval, SessionRequestReview,
    UnknownSessionRequestMethodPolicy, WalletCallStatusRegistry,
};
use wc_protocol::{
    caip::Caip10AccountId,
    dto::pairing::{
        PairingDeleteParams, PairingJsonRpcRequest, PairingJsonRpcResponse, PairingPingParams,
    },
    relay::RelayTopic,
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
    let auth_request =
        serde_json::from_value::<JsonRpcRequest<SessionAuthenticateParams>>(value.clone());
    if let Ok(request) = auth_request {
        exercise_authenticate_review(&request);
    }
    let session_request =
        serde_json::from_value::<JsonRpcRequest<SessionRequestParams>>(value.clone());
    if let Ok(request) = session_request {
        let _ = WalletCallRequest::from_session_request(&request.params.request);
        exercise_session_request_review(&request);
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

fn exercise_authenticate_review(request: &JsonRpcRequest<SessionAuthenticateParams>) {
    let Ok(review) = SessionAuthenticateReview::from_request(fuzz_topic(), 0, request) else {
        return;
    };

    let payload = review.auth_payload_review();
    let _ = payload.chains();
    let _ = payload.audience();
    let _ = payload.domain();
    let _ = payload.nonce();
    let _ = payload.statement();
    let _ = payload.resources();
    let _ = payload.recap_resources();

    for account in fuzz_accounts() {
        let account_review = review.account_review(account);
        let _ = account_review.status();
        let _ = account_review.is_requested_chain();
    }
}

fn exercise_session_request_review(request: &JsonRpcRequest<SessionRequestParams>) {
    let Ok(review) = SessionRequestReview::from_request(fuzz_topic(), 0, request) else {
        return;
    };

    let review = review.with_authorized_accounts(fuzz_accounts());
    let _ = review.method_review();
    let _ = review.method_review_with_unknown_policy(UnknownSessionRequestMethodPolicy::Reject);
    let _ = review.signing_request_review();
    let _ = review.transaction_request_review();
    let _ = review.wallet_call_review();
    let registry = WalletCallStatusRegistry::new();
    let _ = review.wallet_call_review_for_registry(&registry);
    let _ = SessionRequestApproval::new(&review, UnknownSessionRequestMethodPolicy::Reject);
    let _ = SessionRequestApproval::with_wallet_call_status_registry(
        &review,
        UnknownSessionRequestMethodPolicy::Reject,
        &registry,
    );
    let _ = review.wallet_call_request();
}

fn fuzz_topic() -> RelayTopic {
    RelayTopic::from_bytes([0x42; 32])
}

fn fuzz_accounts() -> Vec<Caip10AccountId> {
    vec![
        "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
            .parse()
            .expect("valid fuzz EIP-155 account"),
        "eip155:137:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
            .parse()
            .expect("valid fuzz Polygon account"),
    ]
}
