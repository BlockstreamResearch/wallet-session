#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_bitcoin::{
    BitcoinAccountAddresses, BitcoinAccountScope, BitcoinAddress, BitcoinConnectedAccount,
    BitcoinMethod, BitcoinRequest, BitcoinRequestReview, GetAccountAddressesParams,
    SendTransferParams, SendTransferResult, SignMessageParams, SignMessageResult, SignPsbtParams,
    SignPsbtResult,
};
use wc_core::SessionRequestReview;
use wc_protocol::{
    caip::Caip10AccountId,
    relay::RelayTopic,
    session::{JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod},
};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const ACCOUNT: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
const CHAIN_ID: &str = "bip122:000000000019d6689c085ae165831e93";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    parse_bitcoin_dtos(&value);
    parse_bitcoin_requests(&value);
    parse_bitcoin_review(&value);
});

fn parse_bitcoin_dtos(value: &Value) {
    let _ = serde_json::from_value::<SendTransferParams>(value.clone());
    let _ = serde_json::from_value::<SendTransferResult>(value.clone());
    let _ = serde_json::from_value::<GetAccountAddressesParams>(value.clone());
    let addresses = serde_json::from_value::<BitcoinAccountAddresses>(value.clone());
    if let Ok(addresses) = addresses {
        let _ = addresses.session_property_value();
        if let Ok(chain_id) = CHAIN_ID.parse() {
            let _ = addresses.addresses_changed_event_params(chain_id);
        }
    }
    let sign_psbt = serde_json::from_value::<SignPsbtParams>(value.clone());
    if let Ok(request) = &sign_psbt {
        let result = serde_json::from_value::<SignPsbtResult>(value.clone());
        if let Ok(result) = result {
            let _ = result.validate_for_request(request);
        }
    }
    let _ = serde_json::from_value::<SignMessageParams>(value.clone());
    let _ = serde_json::from_value::<SignMessageResult>(value.clone());
}

fn parse_bitcoin_requests(value: &Value) {
    for method in [
        BitcoinMethod::SendTransfer,
        BitcoinMethod::GetAccountAddresses,
        BitcoinMethod::SignPsbt,
        BitcoinMethod::SignMessage,
    ] {
        let _ = BitcoinRequest::from_bitcoin_method_and_params(method, value);
    }
}

fn parse_bitcoin_review(value: &Value) {
    for method in [
        BitcoinMethod::SendTransfer,
        BitcoinMethod::GetAccountAddresses,
        BitcoinMethod::SignPsbt,
        BitcoinMethod::SignMessage,
    ] {
        let request = JsonRpcRequest::new(
            1,
            SignMethod::SessionRequest,
            SessionRequestParams {
                chain_id: CHAIN_ID.parse().expect("valid fuzz chain id"),
                request: SessionRequest {
                    method: method.session_method(),
                    params: value.clone(),
                    expiry_timestamp: Some(4_000_000_000),
                },
            },
        );

        let Ok(review) = SessionRequestReview::from_request(fuzz_topic(), 0, &request) else {
            continue;
        };
        let review = review.with_authorized_accounts(fuzz_accounts());
        if let Ok(review) = BitcoinRequestReview::from_session_request(&review) {
            let _ = review.ensure_account_scope(&fuzz_account_scope());
        }
    }
}

fn fuzz_account_scope() -> BitcoinAccountScope {
    let account =
        BitcoinConnectedAccount::parse_wallet_first_external_address(ACCOUNT)
            .expect("valid fuzz account");
    BitcoinAccountScope::new(
        account,
        [ACCOUNT]
            .into_iter()
            .map(|address| address.parse::<BitcoinAddress>().expect("valid fuzz address")),
    )
    .expect("fuzz scope includes account")
}

fn fuzz_topic() -> RelayTopic {
    RelayTopic::from_bytes([0x24; 32])
}

fn fuzz_accounts() -> Vec<Caip10AccountId> {
    vec![
        format!("{CHAIN_ID}:{ACCOUNT}")
            .parse()
            .expect("valid fuzz Bitcoin account"),
    ]
}
