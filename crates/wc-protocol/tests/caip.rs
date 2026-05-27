//! Integration tests for CAIP identifier primitives.

use serde_json::json;
use wc_protocol::caip::{
    Caip2ChainId, Caip10AccountId, CaipNamespace, CaipParseError, NamespaceKey,
};

#[test]
fn parses_caip2_spec_examples() {
    let eip155 = Caip2ChainId::parse("eip155:1").expect("eip155 parses");
    let starknet = Caip2ChainId::parse("starknet:SN_GOERLI").expect("starknet parses");
    let max = Caip2ChainId::parse("chainstd:8c3444cf8970a9e41a706fab93e7a6c4")
        .expect("max length parses");

    assert_eq!(eip155.namespace(), "eip155");
    assert_eq!(eip155.reference(), "1");
    assert_eq!(eip155.as_str(), "eip155:1");
    assert_eq!(starknet.reference(), "SN_GOERLI");
    assert_eq!(max.as_str().len(), 41);
}

#[test]
fn rejects_caip2_non_spec_shapes() {
    assert_eq!(
        Caip2ChainId::parse("EIP155:1").expect_err("uppercase namespace rejected"),
        CaipParseError::InvalidNamespaceCharacter {
            index: 0,
            character: 'E',
        }
    );
    assert_eq!(
        Caip2ChainId::parse("eip155:").expect_err("empty reference rejected"),
        CaipParseError::InvalidReferenceLength { actual: 0 }
    );
    assert_eq!(
        Caip2ChainId::parse("eip155:1:extra").expect_err("extra colon rejected"),
        CaipParseError::InvalidChainIdFormat
    );
    assert_eq!(
        Caip2ChainId::parse("ei:1").expect_err("short namespace rejected"),
        CaipParseError::InvalidNamespaceLength { actual: 2 }
    );
    assert_eq!(
        Caip2ChainId::parse("eip155:chain/ref").expect_err("slash rejected"),
        CaipParseError::InvalidReferenceCharacter {
            index: 5,
            character: '/',
        }
    );
}

#[test]
fn parses_caip10_spec_examples() {
    let eip155 = Caip10AccountId::parse("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
        .expect("eip155 account parses");
    let hedera = Caip10AccountId::parse("hedera:mainnet:0.0.1234567890-zbhlt")
        .expect("hedera account parses");
    let encoded = Caip10AccountId::parse("cosmos:cosmoshub-3:cosmos1%2Fpath")
        .expect("percent-encoded account parses");

    assert_eq!(eip155.chain_id_str(), "eip155:1");
    assert_eq!(eip155.chain_id().as_str(), "eip155:1");
    assert_eq!(eip155.namespace(), "eip155");
    assert_eq!(eip155.reference(), "1");
    assert_eq!(
        eip155.address(),
        "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
    );
    assert_eq!(hedera.address(), "0.0.1234567890-zbhlt");
    assert_eq!(encoded.address(), "cosmos1%2Fpath");
}

#[test]
fn rejects_caip10_non_spec_shapes() {
    assert_eq!(
        Caip10AccountId::parse("eip155:1").expect_err("missing address rejected"),
        CaipParseError::InvalidAccountIdFormat
    );
    assert_eq!(
        Caip10AccountId::parse("eip155:1:").expect_err("empty address rejected"),
        CaipParseError::InvalidAddressLength { actual: 0 }
    );
    assert_eq!(
        Caip10AccountId::parse("cosmos:cosmoshub-3:cosmos1/path").expect_err("slash rejected"),
        CaipParseError::InvalidAddressCharacter {
            index: 7,
            character: '/',
        }
    );
    assert_eq!(
        Caip10AccountId::parse("eip155:1:abc:def").expect_err("extra colon rejected"),
        CaipParseError::InvalidAccountIdFormat
    );
}

#[test]
fn builds_from_parts() {
    let namespace = CaipNamespace::parse("eip155").expect("namespace parses");
    let chain = Caip2ChainId::from_parts(namespace.as_str(), "1").expect("chain builds");
    let account = Caip10AccountId::from_parts(&chain, "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
        .expect("account builds");

    assert_eq!(namespace.as_str(), "eip155");
    assert_eq!(chain.as_str(), "eip155:1");
    assert_eq!(
        account.as_str(),
        "eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb"
    );
}

#[test]
fn parses_walletconnect_namespace_keys() {
    let namespace = NamespaceKey::parse("eip155").expect("namespace key parses");
    let chain = NamespaceKey::parse("eip155:1").expect("chain key parses");

    assert_eq!(namespace.as_str(), "eip155");
    assert_eq!(namespace.namespace(), "eip155");
    assert_eq!(namespace.chain_id(), None);
    assert_eq!(chain.as_str(), "eip155:1");
    assert_eq!(chain.namespace(), "eip155");
    assert_eq!(chain.chain_id().map(Caip2ChainId::as_str), Some("eip155:1"));
}

#[test]
fn serializes_and_deserializes_as_strings() {
    let chain = Caip2ChainId::parse("eip155:1").expect("chain parses");
    let account = Caip10AccountId::parse("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
        .expect("account parses");
    let namespace_key = NamespaceKey::parse("eip155:1").expect("key parses");

    assert_eq!(
        serde_json::to_value(&chain).expect("serializes"),
        json!("eip155:1")
    );
    assert_eq!(
        serde_json::to_value(&account).expect("serializes"),
        json!("eip155:1:0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb")
    );
    assert_eq!(
        serde_json::to_value(&namespace_key).expect("serializes"),
        json!("eip155:1")
    );
    assert_eq!(
        serde_json::from_value::<Caip2ChainId>(json!("eip155:1")).expect("deserializes"),
        chain
    );
    assert!(serde_json::from_value::<Caip2ChainId>(json!("EIP155:1")).is_err());
}
