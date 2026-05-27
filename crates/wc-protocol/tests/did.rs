//! Integration tests for DID primitives.

use serde_json::json;
use wc_protocol::{
    caip::{Caip10AccountId, CaipParseError},
    did::{DidPkh, DidPkhParseError},
};

#[test]
fn parses_did_pkh_examples() {
    let eth = DidPkh::parse("did:pkh:eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a")
        .expect("eth did parses");
    let tezos = DidPkh::parse("did:pkh:tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8")
        .expect("tezos did parses");

    assert_eq!(
        eth.account_id_str(),
        "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
    );
    assert_eq!(eth.account_id().as_str(), eth.account_id_str());
    assert_eq!(eth.chain_id().as_str(), "eip155:1");
    assert_eq!(eth.address(), "0xb9c5714089478a327f09197987f16f9e5d936e8a");
    assert_eq!(tezos.chain_id().as_str(), "tezos:NetXdQprcVkpaWU");
    assert_eq!(tezos.address(), "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8");
}

#[test]
fn builds_from_caip10_account_id() {
    let account = Caip10AccountId::parse("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
        .expect("account parses");
    let did = DidPkh::from_account_id(&account);

    assert_eq!(
        did.as_str(),
        "did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
    );
    assert_eq!(did.account_id(), account);
}

#[test]
fn serializes_and_deserializes_as_string() {
    let did = DidPkh::parse("did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
        .expect("did parses");

    assert_eq!(
        serde_json::to_value(&did).expect("serializes"),
        json!("did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
    );
    assert_eq!(
        serde_json::from_value::<DidPkh>(json!(
            "did:pkh:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
        ))
        .expect("deserializes"),
        did
    );
}

#[test]
fn rejects_non_did_pkh_inputs() {
    assert_eq!(
        DidPkh::parse("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
            .expect_err("missing did prefix rejected"),
        DidPkhParseError::InvalidPrefix
    );
    assert_eq!(
        DidPkh::parse("did:key:eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
            .expect_err("wrong did method rejected"),
        DidPkhParseError::InvalidPrefix
    );
    assert_eq!(
        DidPkh::parse("did:pkh:eip155:1").expect_err("missing CAIP-10 address rejected"),
        DidPkhParseError::InvalidAccount {
            source: CaipParseError::InvalidAccountIdFormat,
        }
    );
}
