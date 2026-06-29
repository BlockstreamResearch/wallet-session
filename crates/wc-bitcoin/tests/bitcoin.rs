#![allow(missing_docs)]

use std::str::FromStr;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, psbt::Psbt, transaction,
};
use serde_json::{Value, json};
use wc_bitcoin::{
    BITCOIN_MAINNET_CHAIN_ID, BitcoinAccountAddress, BitcoinAccountAddresses,
    BitcoinAccountAuthorization, BitcoinAccountScope, BitcoinAddress, BitcoinConnectedAccount,
    BitcoinEvent, BitcoinMemo, BitcoinMethod, BitcoinPsbt, BitcoinPsbtOutputDestination,
    BitcoinRequest, BitcoinRequestError, BitcoinRequestReview, BitcoinTxid,
    BitcoinWalletAddressRole, GET_ACCOUNT_ADDRESSES_SESSION_PROPERTY, GetAccountAddressesParams,
    SendTransferParams, SendTransferResult, SignMessageParams, SignMessageProtocol,
    SignMessageResult, SignPsbtInput, SignPsbtParams, SignPsbtResult,
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
    assert!(property.contains("m/84'/0'/0'/0/0"));
    let reparsed: BitcoinAccountAddresses =
        serde_json::from_str(property).expect("serialized property reparses");
    assert_eq!(
        reparsed.as_slice()[0].path,
        sample_addresses().as_slice()[0].path
    );

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
fn get_account_addresses_result_must_stay_inside_account_scope() {
    let request = GetAccountAddressesParams {
        account: ACCOUNT.parse().expect("account parses"),
        intentions: Vec::new(),
    };
    let valid = sample_addresses();
    valid
        .validate_for_request_and_scope(&request, &account_scope([ACCOUNT]))
        .expect("sample address is in account scope");

    let leaked = BitcoinAccountAddresses::new(vec![
        sample_addresses().into_vec().remove(0),
        BitcoinAccountAddress {
            address: RECIPIENT.parse().expect("recipient parses"),
            public_key: None,
            path: None,
            intention: None,
        },
    ]);
    assert!(matches!(
        leaked.validate_for_request_and_scope(&request, &account_scope([ACCOUNT])),
        Err(BitcoinRequestError::UnauthorizedWalletAddress {
            role: BitcoinWalletAddressRole::AccountAddressResult,
            ..
        })
    ));

    let missing_connected = BitcoinAccountAddresses::new(vec![BitcoinAccountAddress {
        address: RECIPIENT.parse().expect("recipient parses"),
        public_key: None,
        path: None,
        intention: None,
    }]);
    assert!(matches!(
        missing_connected
            .validate_for_request_and_scope(&request, &account_scope([ACCOUNT, RECIPIENT])),
        Err(BitcoinRequestError::AccountAddressesResultMissingConnectedAccount)
    ));
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
fn parses_sign_psbt_defaults_and_allows_wallet_selected_inputs() {
    let params: SignPsbtParams = serde_json::from_value(json!({
        "account": ACCOUNT,
        "psbt": PSBT,
        "signInputs": [{ "address": ACCOUNT, "index": 0 }]
    }))
    .expect("signPsbt params parse");

    assert!(!params.broadcast);
    assert_eq!(params.sign_inputs[0].sighash_types_or_default(), &[1]);

    let method = BitcoinMethod::SignPsbt.session_method();
    let wallet_selected = BitcoinRequest::from_method_and_params(
        &method,
        &json!({ "account": ACCOUNT, "psbt": PSBT, "signInputs": [] }),
    )
    .expect("empty signInputs let the wallet select spendable inputs");
    assert!(matches!(wallet_selected, BitcoinRequest::SignPsbt(_)));

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
fn summarizes_sign_psbt_outputs_and_fee_when_input_amounts_are_present() {
    let account = Address::from_str(ACCOUNT)
        .expect("account address parses")
        .require_network(Network::Bitcoin)
        .expect("account is mainnet");
    let recipient = Address::from_str(RECIPIENT)
        .expect("recipient address parses")
        .require_network(Network::Bitcoin)
        .expect("recipient is mainnet");
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(TXID.parse::<Txid>().expect("txid parses"), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: recipient.script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("unsigned tx converts to PSBT");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: account.script_pubkey(),
    });

    let psbt =
        BitcoinPsbt::parse(BASE64_STANDARD.encode(psbt.serialize())).expect("PSBT parses newtype");
    let summary = psbt
        .summary(Some("000000000019d6689c085ae165831e93"))
        .expect("summary builds");

    assert_eq!(summary.input_count, 1);
    assert_eq!(summary.output_count, 1);
    assert_eq!(summary.total_output_sats, Some(99_000));
    assert_eq!(summary.known_input_count, 1);
    assert_eq!(summary.total_input_sats, Some(100_000));
    assert_eq!(summary.fee_sats, Some(1_000));
    assert_eq!(summary.op_return_output_count, 0);
    assert_eq!(
        summary.outputs[0].destination,
        BitcoinPsbtOutputDestination::Address(RECIPIENT.to_owned())
    );
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
fn sign_message_result_must_match_reviewed_signing_address() {
    let request = SignMessageParams {
        account: ACCOUNT.parse().expect("account parses"),
        message: "hello".to_owned(),
        address: Some(RECIPIENT.parse().expect("recipient parses")),
        protocol: None,
    };

    let valid = SignMessageResult {
        address: RECIPIENT.parse().expect("recipient parses"),
        signature: "abcdef".parse().expect("signature parses"),
        message_hash: None,
    };
    valid
        .validate_for_request(&request)
        .expect("result address matches signer");

    let wrong = SignMessageResult {
        address: ACCOUNT.parse().expect("account parses"),
        signature: "abcdef".parse().expect("signature parses"),
        message_hash: None,
    };
    assert!(matches!(
        wrong.validate_for_request(&request),
        Err(BitcoinRequestError::SignMessageResultAddressMismatch { .. })
    ));
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
        serde_json::from_value::<SendTransferParams>(json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "2100000000000001"
        }))
        .is_err()
    );
    assert!(BitcoinTxid::parse("0x1234").is_err());
    assert!(BitcoinPsbt::parse("abcd=ef").is_err());
}

#[test]
fn send_transfer_amount_serializes_canonical_satoshi_string() {
    let params = serde_json::from_value::<SendTransferParams>(json!({
        "account": ACCOUNT,
        "recipientAddress": RECIPIENT,
        "amount": "00000042"
    }))
    .expect("sendTransfer params parse");

    assert_eq!(params.amount.to_sat(), 42);
    let serialized = serde_json::to_value(params).expect("params serialize");
    assert_eq!(serialized["amount"], json!("42"));
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
