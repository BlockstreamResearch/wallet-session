#![allow(missing_docs)]

use serde_json::{Value, json};
use wc_bitcoin::{
    BITCOIN_MAINNET_CHAIN_ID, BitcoinAccountAddress, BitcoinAccountAddresses,
    BitcoinAccountAuthorization, BitcoinAccountScope, BitcoinAddress, BitcoinConnectedAccount,
    BitcoinEvent, BitcoinMemo, BitcoinMethod, BitcoinPsbt, BitcoinRequest, BitcoinRequestError,
    BitcoinRequestReview, BitcoinTxid, BitcoinWalletAddressRole,
    GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY, GetAccountAddressesParams, SendTransferParams,
    SendTransferResult, SignMessageParams, SignMessageProtocol, SignPsbtInput, SignPsbtParams,
    SignPsbtResult,
};
use wc_core::SessionRequestReview;
use wc_protocol::{
    caip::Caip10AccountId,
    relay::RelayTopic,
    session::{JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod},
};

const ACCOUNT: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
const RECIPIENT: &str = "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e";
const TXID: &str = "f007551f169722ce74104d6673bd46ce193c624b8550889526d1b93820d725f7";
const PSBT: &str = "cHNidP8BAAoCAAAAAAAAAAAAAA==";

#[test]
fn parses_send_transfer_request_and_result_shape() {
    let params: SendTransferParams = serde_json::from_value(json!({
        "account": ACCOUNT,
        "recipientAddress": RECIPIENT,
        "amount": "123000000",
        "memo": "636861726c6579206c6f766573206865"
    }))
    .expect("sendTransfer params parse");

    assert_eq!(params.account.as_str(), ACCOUNT);
    assert_eq!(params.amount.to_sat(), 123_000_000);
    assert_eq!(params.memo.expect("memo").byte_len(), 16);

    let result: SendTransferResult =
        serde_json::from_value(json!({ "txid": TXID })).expect("result parses");
    assert_eq!(result.txid.to_string(), TXID);
}

#[test]
fn rejects_send_transfer_unknown_fields_and_long_memo() {
    let unknown_field = serde_json::from_value::<SendTransferParams>(json!({
        "account": ACCOUNT,
        "recipientAddress": RECIPIENT,
        "amount": "1",
        "feeRate": "1"
    }))
    .expect_err("unknown fields fail closed");
    assert!(unknown_field.to_string().contains("unknown field"));

    let long_memo = "aa".repeat(81);
    let error = BitcoinMemo::parse(long_memo).expect_err("memo over 80 bytes fails");
    assert!(error.to_string().contains("too long"));
}

#[test]
fn parses_get_account_addresses_and_session_event_helpers() {
    let params: GetAccountAddressesParams =
        serde_json::from_value(json!({ "account": ACCOUNT, "intentions": ["payment"] }))
            .expect("getAccountAddresses params parse");
    assert_eq!(params.intentions, ["payment"]);

    let addresses = sample_addresses();
    let properties = addresses
        .session_properties()
        .expect("properties serialize");
    let property = properties
        .get(GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY)
        .and_then(Value::as_str)
        .expect("serialized property");
    assert!(property.contains(ACCOUNT));

    let event = addresses
        .addresses_changed_event_params(BITCOIN_MAINNET_CHAIN_ID.parse().expect("chain parses"))
        .expect("event params serialize");
    assert_eq!(
        event.event.name.as_str(),
        BitcoinEvent::AddressesChanged.as_str()
    );
    assert_eq!(event.chain_id.as_str(), BITCOIN_MAINNET_CHAIN_ID);
}

#[test]
fn rejects_empty_get_account_addresses_intention() {
    let method = BitcoinMethod::GetAccountAddresses.session_method();
    let error = BitcoinRequest::from_method_and_params(
        &method,
        &json!({ "account": ACCOUNT, "intentions": [""] }),
    )
    .expect_err("empty intention fails");
    assert!(matches!(error, BitcoinRequestError::InvalidParams { .. }));
}

#[test]
fn parses_sign_psbt_defaults_and_requires_inputs() {
    let params: SignPsbtParams = serde_json::from_value(json!({
        "account": ACCOUNT,
        "psbt": PSBT,
        "signInputs": [{ "address": ACCOUNT, "index": 0 }]
    }))
    .expect("signPsbt params parse");

    assert!(!params.broadcast);
    assert_eq!(params.sign_inputs[0].sighash_types_or_default(), &[1]);

    let method = BitcoinMethod::SignPsbt.session_method();
    let error = BitcoinRequest::from_method_and_params(
        &method,
        &json!({ "account": ACCOUNT, "psbt": PSBT, "signInputs": [] }),
    )
    .expect_err("empty signInputs fail");
    assert!(matches!(error, BitcoinRequestError::InvalidParams { .. }));

    let error = BitcoinRequest::from_method_and_params(
        &method,
        &json!({
            "account": ACCOUNT,
            "psbt": PSBT,
            "signInputs": [{ "address": ACCOUNT, "index": 0, "sighashTypes": [511] }]
        }),
    )
    .expect_err("invalid sighash type fails");
    assert!(matches!(error, BitcoinRequestError::InvalidParams { .. }));
}

#[test]
fn broadcast_sign_psbt_result_requires_txid() {
    let request = SignPsbtParams {
        account: ACCOUNT.parse().expect("account parses"),
        psbt: BitcoinPsbt::parse(PSBT).expect("psbt parses"),
        sign_inputs: vec![SignPsbtInput {
            address: ACCOUNT.parse().expect("input address parses"),
            index: 0,
            sighash_types: None,
        }],
        broadcast: true,
    };
    let result = SignPsbtResult::signed(BitcoinPsbt::parse(PSBT).expect("psbt parses"));

    assert!(matches!(
        result.validate_for_request(&request),
        Err(BitcoinRequestError::BroadcastResultMissingTxid)
    ));

    let broadcast = SignPsbtResult::broadcast(
        BitcoinPsbt::parse(PSBT).expect("psbt parses"),
        BitcoinTxid::parse(TXID).expect("txid parses"),
    );
    broadcast
        .validate_for_request(&request)
        .expect("broadcast txid is present");
}

#[test]
fn parses_sign_message_defaults() {
    let params: SignMessageParams = serde_json::from_value(json!({
        "account": ACCOUNT,
        "message": "hello"
    }))
    .expect("signMessage params parse");

    assert_eq!(params.protocol_or_default(), SignMessageProtocol::Ecdsa);
    assert_eq!(params.signing_address().as_str(), ACCOUNT);

    let bip322: SignMessageParams = serde_json::from_value(json!({
        "account": ACCOUNT,
        "message": "hello",
        "address": ACCOUNT,
        "protocol": "bip322"
    }))
    .expect("bip322 params parse");
    assert_eq!(bip322.protocol_or_default(), SignMessageProtocol::Bip322);
}

#[test]
fn builds_authorized_bitcoin_request_review() {
    let review = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SendTransfer,
        json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "123000000"
        }),
    )
    .with_authorized_accounts([authorized_account()]);

    let bitcoin = BitcoinRequestReview::from_session_request(&review).expect("review parses");

    assert_eq!(bitcoin.request_id(), 7);
    assert_eq!(bitcoin.chain_id().as_str(), BITCOIN_MAINNET_CHAIN_ID);
    assert_eq!(
        bitcoin.authorization(),
        BitcoinAccountAuthorization::Authorized
    );
    assert_eq!(bitcoin.request().method(), BitcoinMethod::SendTransfer);
}

#[test]
fn account_scope_allows_secondary_wallet_addresses_inside_scope() {
    let review = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SignPsbt,
        json!({
            "account": ACCOUNT,
            "psbt": PSBT,
            "signInputs": [{ "address": RECIPIENT, "index": 0 }]
        }),
    )
    .with_authorized_accounts([authorized_account()]);
    let bitcoin = BitcoinRequestReview::from_session_request(&review).expect("review parses");
    let scope = account_scope([ACCOUNT, RECIPIENT]);

    let scoped = bitcoin
        .into_account_scoped(scope)
        .expect("secondary signer is in scope");

    assert_eq!(scoped.review().request().method(), BitcoinMethod::SignPsbt);
}

#[test]
fn account_scope_rejects_secondary_wallet_addresses_outside_scope() {
    let psbt = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SignPsbt,
        json!({
            "account": ACCOUNT,
            "psbt": PSBT,
            "signInputs": [{ "address": RECIPIENT, "index": 0 }]
        }),
    )
    .with_authorized_accounts([authorized_account()]);
    let psbt = BitcoinRequestReview::from_session_request(&psbt).expect("review parses");
    assert!(matches!(
        psbt.ensure_account_scope(&account_scope([ACCOUNT])),
        Err(BitcoinRequestError::UnauthorizedWalletAddress {
            role: BitcoinWalletAddressRole::PsbtInputSigner,
            ..
        })
    ));

    let message = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SignMessage,
        json!({
            "account": ACCOUNT,
            "message": "hello",
            "address": RECIPIENT
        }),
    )
    .with_authorized_accounts([authorized_account()]);
    let message = BitcoinRequestReview::from_session_request(&message).expect("review parses");
    assert!(matches!(
        message.ensure_account_scope(&account_scope([ACCOUNT])),
        Err(BitcoinRequestError::UnauthorizedWalletAddress {
            role: BitcoinWalletAddressRole::MessageSigner,
            ..
        })
    ));

    let transfer = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SendTransfer,
        json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "1",
            "changeAddress": RECIPIENT
        }),
    )
    .with_authorized_accounts([authorized_account()]);
    let transfer = BitcoinRequestReview::from_session_request(&transfer).expect("review parses");
    assert!(matches!(
        transfer.ensure_account_scope(&account_scope([ACCOUNT])),
        Err(BitcoinRequestError::UnauthorizedWalletAddress {
            role: BitcoinWalletAddressRole::ChangeAddress,
            ..
        })
    ));
}

#[test]
fn connected_account_can_be_built_from_default_first_external_entry() {
    let addresses = sample_addresses();
    let account = BitcoinConnectedAccount::from_first_external_entry(&addresses.as_slice()[0])
        .expect("sample account has default first external path");
    assert_eq!(account.as_str(), ACCOUNT);

    let change_entry = BitcoinAccountAddress {
        address: RECIPIENT.parse().expect("address parses"),
        public_key: None,
        path: Some("m/84'/0'/0'/1/0".parse().expect("path parses")),
        intention: None,
    };
    assert!(BitcoinConnectedAccount::from_first_external_entry(&change_entry).is_err());
}

#[test]
fn rejects_unauthorized_or_non_bitcoin_session_request_review() {
    let unauthorized = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SendTransfer,
        json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "1"
        }),
    )
    .with_authorized_accounts([
        "bip122:000000000019d6689c085ae165831e93:132F25rTsvBdp9JzLLBHP5mvGY66i1xdiM"
            .parse::<Caip10AccountId>()
            .expect("authorized account parses"),
    ]);

    assert!(matches!(
        BitcoinRequestReview::from_session_request(&unauthorized),
        Err(BitcoinRequestError::UnauthorizedAccount { .. })
    ));

    let wrong_chain = session_request_review(
        "eip155:1",
        BitcoinMethod::SendTransfer,
        json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "1"
        }),
    );
    assert!(matches!(
        BitcoinRequestReview::from_session_request(&wrong_chain),
        Err(BitcoinRequestError::UnsupportedChain { .. })
    ));
}

#[test]
fn value_newtypes_reject_malformed_wire_values() {
    assert!(BitcoinAddress::parse("has space").is_err());
    assert!("12a".parse::<wc_bitcoin::HexBytes>().is_err());
    assert!("not-a-key".parse::<wc_bitcoin::BitcoinPublicKey>().is_err());
    assert!(
        "2100000000000001"
            .parse::<wc_bitcoin::BitcoinAmountSats>()
            .is_err()
    );
    assert!(BitcoinTxid::parse("0x1234").is_err());
    assert!(BitcoinPsbt::parse("abcd=ef").is_err());
}

#[test]
fn amount_sats_serializes_canonical_satoshi_string() {
    let amount = "00000042"
        .parse::<wc_bitcoin::BitcoinAmountSats>()
        .expect("amount parses through rust-bitcoin");

    assert_eq!(amount.to_sat(), 42);
    assert_eq!(amount.to_string(), "42");
    assert_eq!(
        serde_json::to_value(amount).expect("amount serializes"),
        json!("42")
    );
}

fn sample_addresses() -> BitcoinAccountAddresses {
    BitcoinAccountAddresses::new(vec![BitcoinAccountAddress {
        address: ACCOUNT.parse().expect("address parses"),
        public_key: Some(
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
                .parse()
                .expect("public key parses"),
        ),
        path: Some("m/84'/0'/0'/0/0".parse().expect("path parses")),
        intention: None,
    }])
}

fn account_scope(addresses: impl IntoIterator<Item = &'static str>) -> BitcoinAccountScope {
    let connected_account = BitcoinConnectedAccount::parse_wallet_first_external_address(ACCOUNT)
        .expect("connected account parses");
    BitcoinAccountScope::new(
        connected_account,
        addresses
            .into_iter()
            .map(|address| address.parse::<BitcoinAddress>().expect("address parses")),
    )
    .expect("scope includes connected account")
}

fn session_request_review(
    chain_id: &str,
    method: BitcoinMethod,
    params: Value,
) -> SessionRequestReview {
    let request = JsonRpcRequest::new(
        7,
        SignMethod::SessionRequest,
        SessionRequestParams {
            chain_id: chain_id.parse().expect("chain id parses"),
            request: SessionRequest {
                method: method.session_method(),
                params,
                expiry_timestamp: Some(4_000_000_000),
            },
        },
    );

    SessionRequestReview::from_request(RelayTopic::from_bytes([7; 32]), 0, &request)
        .expect("session request review builds")
}

fn authorized_account() -> Caip10AccountId {
    format!("{BITCOIN_MAINNET_CHAIN_ID}:{ACCOUNT}")
        .parse()
        .expect("authorized Bitcoin account parses")
}
