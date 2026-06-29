use std::str::FromStr;

use base64::prelude::{BASE64_STANDARD, Engine as _};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness, absolute, psbt::Psbt, transaction,
};
use serde_json::{Value, json};
use wc_bitcoin::{
    BitcoinAccountScope, BitcoinAddress, BitcoinConnectedAccount, BitcoinMethod, BitcoinPsbt,
    BitcoinRequest, GetAccountAddressesParams, SignMessageParams, SignPsbtInput, SignPsbtParams,
};
use wc_core::SessionRequestReview;
use wc_protocol::{
    caip::Caip10AccountId,
    relay::RelayTopic,
    session::{JsonRpcRequest, SessionRequest, SessionRequestParams, SignMethod},
};

use crate::{
    bitcoin::{bitcoin_request_display_json_value, validated_bitcoin_result},
    capabilities::{required_session_namespaces, wallet_capabilities},
    config::{WcClientConfig, single_session_config},
    error::WcUniFfiError,
    exports::{wc_canonical_account_id, wc_canonical_chain_id, wc_generate_relay_auth_seed_hex},
    review::{active_session_review_json, session_request_review_json},
    types::{WcCapabilities, WcChainCapability, WcJsonPayload},
    util::{hex_32, json_string},
    wc_bitcoin_addresses_changed_event_params_json, wc_bitcoin_session_properties_json,
};

const ACCOUNT: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";
const RECIPIENT: &str = "bc1pgllnmtxs0g058qz7c6qgaqq4qknwrqj9z7rqn9e2dzhmcfmhlu4sfadf5e";
const PUBKEY: &str = "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
const TXID: &str = "f007551f169722ce74104d6673bd46ce193c624b8550889526d1b93820d725f7";
const BITCOIN_MAINNET_CHAIN_ID: &str = "bip122:000000000019d6689c085ae165831e93";

#[test]
fn generated_relay_seed_is_lowercase_32_byte_hex() {
    let seed = wc_generate_relay_auth_seed_hex().expect("seed is generated");

    assert_eq!(seed.len(), 64);
    assert!(seed.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(seed.bytes().all(|byte| !byte.is_ascii_uppercase()));
    assert!(hex_32("relay_auth_seed_hex", &seed).is_ok());
}

#[test]
fn client_config_debug_redacts_relay_auth_seed() {
    let config = WcClientConfig::new(
        "project".to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "wallet".to_owned(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let debug = format!("{config:?}");

    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
}

#[test]
fn json_payload_debug_redacts_payload_body() {
    let payload = WcJsonPayload::new(
        r#"{"address":"bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw","signature":"abcdef"}"#
            .to_owned(),
    );
    let debug = format!("{payload:?}");

    assert!(debug.contains("sha256"));
    assert!(debug.contains("byte_len"));
    assert!(!debug.contains("bc1qvz"));
    assert!(!debug.contains("abcdef"));
    assert!(payload.json().contains("signature"));
}

#[test]
fn config_conversion_validates_seed_and_timing_bounds() {
    let config = WcClientConfig::new(
        "project".to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "wallet".to_owned(),
        Some("wss://relay.walletconnect.com".to_owned()),
        Some("blockstream-green-test".to_owned()),
        Some(300),
        Some(1_000),
        Some(16),
        Some(250),
        Some(3),
    );

    let converted = single_session_config(&config).expect("config converts");

    assert_eq!(converted.pairing().project_id, "project");
    assert_eq!(converted.pairing().auth_subject, "wallet");
    assert_eq!(
        converted.pairing().relay_url,
        "wss://relay.walletconnect.com"
    );
    assert_eq!(converted.max_queued_events(), 16);

    let invalid = WcClientConfig::new(
        "project".to_owned(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        "wallet".to_owned(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    assert!(matches!(
        single_session_config(&invalid),
        Err(WcUniFfiError::InvalidInput { .. })
    ));

    let zero_cooldown = WcClientConfig::new(
        "project".to_owned(),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        "wallet".to_owned(),
        None,
        None,
        None,
        None,
        None,
        Some(0),
        None,
    );
    assert!(matches!(
        single_session_config(&zero_cooldown),
        Err(WcUniFfiError::InvalidInput { .. })
    ));
}

#[test]
fn canonical_id_helpers_accept_bitcoin_ids_and_reject_malformed_values() {
    assert_eq!(
        wc_canonical_chain_id("bip122:000000000019d6689c085ae165831e93".to_owned())
            .expect("chain parses"),
        "bip122:000000000019d6689c085ae165831e93"
    );
    assert_eq!(
        wc_canonical_account_id(format!("bip122:000000000019d6689c085ae165831e93:{ACCOUNT}"))
            .expect("account parses"),
        format!("bip122:000000000019d6689c085ae165831e93:{ACCOUNT}")
    );
    assert!(wc_canonical_chain_id("not a chain".to_owned()).is_err());
    assert!(wc_canonical_account_id("eip155:1".to_owned()).is_err());
}

#[test]
fn bitcoin_helpers_build_session_properties_and_address_events() {
    let addresses_json = sample_addresses_json();

    let properties_json =
        wc_bitcoin_session_properties_json(addresses_json.clone()).expect("properties build");
    let properties: Value = serde_json::from_str(&properties_json).expect("json parses");
    let property = properties
        .get("bip122_getAccountAddresses")
        .and_then(Value::as_str)
        .expect("address session property");
    assert!(property.contains(ACCOUNT));
    assert!(property.contains(PUBKEY));

    let event_json = wc_bitcoin_addresses_changed_event_params_json(
        "bip122:000000000019d6689c085ae165831e93".to_owned(),
        addresses_json,
    )
    .expect("event builds");
    let event: Value = serde_json::from_str(&event_json).expect("json parses");
    assert_eq!(event["chainId"], "bip122:000000000019d6689c085ae165831e93");
    assert_eq!(event["event"]["name"], "bip122_addressesChanged");
    assert_eq!(event["event"]["data"][0]["address"], ACCOUNT);
}

#[test]
fn bitcoin_result_validation_binds_addresses_to_scope() {
    let request = BitcoinRequest::GetAccountAddresses(GetAccountAddressesParams {
        account: ACCOUNT.parse().expect("account parses"),
        intentions: Vec::new(),
    });
    let scope = account_scope([ACCOUNT]);

    let valid = validated_bitcoin_result(
        &request,
        &json_string(&json!([{ "address": ACCOUNT }])).expect("json serializes"),
        Some(&scope),
    )
    .expect("result validates");
    assert_eq!(valid[0]["address"], ACCOUNT);

    let leaked = validated_bitcoin_result(
        &request,
        &json_string(&json!([{ "address": ACCOUNT }, { "address": RECIPIENT }]))
            .expect("json serializes"),
        Some(&scope),
    );
    assert!(matches!(leaked, Err(WcUniFfiError::InvalidInput { .. })));
}

#[test]
fn bitcoin_sign_message_result_must_match_requested_address() {
    let request = BitcoinRequest::SignMessage(SignMessageParams {
        account: ACCOUNT.parse().expect("account parses"),
        message: "hello".to_owned(),
        address: Some(RECIPIENT.parse().expect("recipient parses")),
        protocol: None,
    });
    let result = validated_bitcoin_result(
        &request,
        &json_string(&json!({ "address": ACCOUNT, "signature": "abcdef" }))
            .expect("json serializes"),
        None,
    );

    assert!(matches!(result, Err(WcUniFfiError::InvalidInput { .. })));
}

#[test]
fn bitcoin_request_display_explains_user_intent_and_fields() {
    let message = BitcoinRequest::SignMessage(SignMessageParams {
        account: ACCOUNT.parse().expect("account parses"),
        message: "Authorize payout address change".to_owned(),
        address: Some(ACCOUNT.parse().expect("account parses")),
        protocol: None,
    });

    let display = bitcoin_request_display_json_value(&message);

    assert_eq!(display["intent"], "Sign Bitcoin message");
    assert_eq!(display["details"][0]["label"], "Protocol");
    assert!(display["details"].to_string().contains("Authorize payout"));
    assert!(
        display["warnings"][0]
            .as_str()
            .expect("warning")
            .contains("proves control")
    );
}

#[test]
fn bitcoin_sign_psbt_display_explains_outputs_and_fee_visibility() {
    let request = BitcoinRequest::SignPsbt(SignPsbtParams {
        account: ACCOUNT.parse().expect("account parses"),
        psbt: BitcoinPsbt::parse(psbt_without_input_amounts()).expect("psbt parses"),
        sign_inputs: vec![SignPsbtInput {
            address: ACCOUNT.parse().expect("account parses"),
            index: 0,
            sighash_types: None,
        }],
        broadcast: false,
    });

    let display = bitcoin_request_display_json_value(&request);

    assert_eq!(display["intent"], "Sign PSBT");
    assert!(display["details"].to_string().contains("PSBT outputs"));
    assert!(
        display["details"]
            .to_string()
            .contains("Total output amount")
    );
    assert!(
        display["details"]
            .to_string()
            .contains("Known input amounts")
    );
    assert!(
        display["info"]
            .to_string()
            .contains("does not include enough input amount data")
    );
}

#[test]
fn active_session_review_explains_grants_and_actions() {
    let session = serde_json::from_value(json!({
        "topic": "1111111111111111111111111111111111111111111111111111111111111111",
        "pairingTopic": "2222222222222222222222222222222222222222222222222222222222222222",
        "relay": {"protocol": "irn"},
        "expiry": 1780470684_u64,
        "acknowledged": true,
        "controller": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
        "namespaces": {
            "bip122": {
                "accounts": [format!("bip122:000000000019d6689c085ae165831e93:{ACCOUNT}")],
                "chains": ["bip122:000000000019d6689c085ae165831e93"],
                "events": ["bip122_addressesChanged"],
                "methods": ["signMessage", "signPsbt"]
            }
        },
        "requiredNamespaces": {},
        "optionalNamespaces": {},
        "self": {
            "publicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
            "metadata": {
                "name": "Blockstream Green",
                "description": "Wallet",
                "url": "https://blockstream.com/green/",
                "icons": []
            }
        },
        "peer": {
            "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
            "metadata": {
                "name": "Reown Lab",
                "description": "Test dapp",
                "url": "https://lab.reown.com/",
                "icons": []
            }
        },
        "transportType": "relay"
    }))
    .expect("session parses");

    let review_json = active_session_review_json(&session, "Connected").expect("review serializes");
    let review: Value = serde_json::from_str(&review_json).expect("review parses");

    assert_eq!(review["display"]["intent"], "Manage WalletConnect session");
    assert!(
        review["display"]["details"]
            .to_string()
            .contains("Reown Lab")
    );
    assert!(
        review["display"]["details"]
            .to_string()
            .contains("signPsbt")
    );
    assert_eq!(
        review["actions"]["disconnect"]["intent"],
        "Disconnect WalletConnect session"
    );
    assert_eq!(
        review["actions"]["extend"]["intent"],
        "Extend WalletConnect session"
    );
    assert!(
        review["actions"]["extend"]["warnings"]
            .to_string()
            .contains("does not add new chains")
    );
}

#[test]
fn json_object_inputs_fail_closed_for_capability_properties() {
    let capabilities = WcCapabilities {
        chains: vec![WcChainCapability {
            chain_id: "bip122:000000000019d6689c085ae165831e93".to_owned(),
            accounts: vec![format!("bip122:000000000019d6689c085ae165831e93:{ACCOUNT}")],
            methods: vec!["sendTransfer".to_owned()],
            events: vec!["bip122_addressesChanged".to_owned()],
        }],
        session_properties_json: Some("[]".to_owned()),
        scoped_properties_json: None,
    };

    assert!(matches!(
        wallet_capabilities(capabilities),
        Err(WcUniFfiError::InvalidInput { .. })
    ));
}

#[test]
fn wallet_capabilities_convert_to_session_namespaces() {
    let capabilities = WcCapabilities {
        chains: vec![WcChainCapability {
            chain_id: "bip122:000000000019d6689c085ae165831e93".to_owned(),
            accounts: vec![format!("bip122:000000000019d6689c085ae165831e93:{ACCOUNT}")],
            methods: vec!["bip122_signMessage".to_owned()],
            events: vec!["bip122_addressesChanged".to_owned()],
        }],
        session_properties_json: None,
        scoped_properties_json: None,
    };

    let namespaces = required_session_namespaces(capabilities).expect("namespaces build");
    let namespace = namespaces
        .get(&wc_protocol::caip::NamespaceKey::parse("bip122").expect("namespace parses"))
        .expect("bip122 namespace exists");

    assert_eq!(namespace.accounts.len(), 1);
    assert_eq!(namespace.methods[0].as_str(), "bip122_signMessage");
    assert_eq!(namespace.events[0].as_str(), "bip122_addressesChanged");
}

#[test]
fn malformed_bitcoin_session_request_is_unapprovable() {
    let review = session_request_review(
        BITCOIN_MAINNET_CHAIN_ID,
        BitcoinMethod::SendTransfer,
        json!({
            "account": ACCOUNT,
            "recipientAddress": RECIPIENT,
            "amount": "1000",
            "memo": "plain text is not valid memo hex"
        }),
    )
    .with_authorized_accounts([authorized_account()]);

    let review_json = session_request_review_json(&review).expect("review serializes");
    let review: Value = serde_json::from_str(&review_json).expect("review parses");

    assert!(review["bitcoin"].is_null());
    assert_eq!(
        review["display"]["intent"],
        "Unsupported WalletConnect request"
    );
    assert_eq!(review["display"]["approval"]["enabled"], false);
    assert!(
        review["display"]["details"]
            .to_string()
            .contains("malformed sendTransfer params")
    );
    assert!(
        review["display"]["info"]
            .to_string()
            .contains("Clear signing requires")
    );
}

fn sample_addresses_json() -> String {
    json_string(&json!([
        {
            "address": ACCOUNT,
            "publicKey": PUBKEY,
            "path": "m/84'/0'/0'/0/0"
        }
    ]))
    .expect("sample addresses serialize")
}

fn psbt_without_input_amounts() -> String {
    let recipient = Address::from_str(RECIPIENT)
        .expect("recipient address parses")
        .require_network(Network::Bitcoin)
        .expect("recipient is mainnet");
    let psbt = Psbt::from_unsigned_tx(Transaction {
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
    })
    .expect("unsigned tx converts to PSBT");

    BASE64_STANDARD.encode(psbt.serialize())
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
