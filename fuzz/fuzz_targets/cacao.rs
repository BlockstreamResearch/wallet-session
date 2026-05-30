#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_protocol::{
    did::DidPkh,
    session::{
        AuthPayload, Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature,
        CacaoSignatureType, CacaoSignatureValue,
    },
};

const MAX_INPUT_BYTES: usize = 16 * 1024;
const SAMPLE_ACCOUNT_ADDRESS: &str = "0xab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb";

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    parse_cacao_object(&value);
    parse_cacao_payload(&value);
    parse_auth_payload(&value);
    validate_cacao_pair(&value);
});

fn parse_cacao_object(value: &Value) {
    let Ok(cacao) = serde_json::from_value::<Cacao>(value.clone()) else {
        return;
    };

    let _ = cacao.format_message();
    assert_json_round_trip(&cacao);
}

fn parse_cacao_payload(value: &Value) {
    let Ok(payload) = serde_json::from_value::<CacaoPayload>(value.clone()) else {
        return;
    };

    let _ = payload.format_message();
    assert_payload_json_round_trip(&payload);
}

fn parse_auth_payload(value: &Value) {
    let Ok(auth_payload) = serde_json::from_value::<AuthPayload>(value.clone()) else {
        return;
    };

    for issuer in issuers_for_auth_payload(&auth_payload) {
        let _ = auth_payload.format_message(&issuer);
        if let Ok(cacao_payload) = auth_payload.to_cacao_payload(&issuer) {
            let signature = sample_signature();
            let cacao = Cacao {
                h: CacaoHeader {
                    kind: CacaoHeaderType::Caip122,
                },
                p: cacao_payload,
                s: signature,
            };

            assert!(cacao.validate_against_auth_payload(&auth_payload).is_ok());
            let _ = cacao.format_message();
            assert_json_round_trip(&cacao);
        }
    }
}

fn validate_cacao_pair(value: &Value) {
    let Some(auth_payload_value) = value.get("authPayload") else {
        return;
    };
    let Some(cacao_value) = value.get("cacao") else {
        return;
    };

    let auth_payload = serde_json::from_value::<AuthPayload>(auth_payload_value.clone());
    let cacao = serde_json::from_value::<Cacao>(cacao_value.clone());

    if let (Ok(auth_payload), Ok(cacao)) = (auth_payload, cacao) {
        let _ = cacao.validate_against_auth_payload(&auth_payload);
        let _ = cacao.format_message();
    }
}

fn issuers_for_auth_payload(auth_payload: &AuthPayload) -> Vec<DidPkh> {
    auth_payload
        .chains
        .iter()
        .take(8)
        .filter_map(|chain| {
            DidPkh::parse(format!(
                "did:pkh:{}:{SAMPLE_ACCOUNT_ADDRESS}",
                chain.as_str()
            ))
            .ok()
        })
        .collect()
}

fn sample_signature() -> CacaoSignature {
    CacaoSignature {
        kind: CacaoSignatureType::Eip191,
        signature: CacaoSignatureValue::from_wire("0x00"),
        meta: None,
    }
}

fn assert_json_round_trip(value: &Cacao) {
    let serialized = serde_json::to_value(value).expect("serializing DTO value should not fail");
    let deserialized =
        serde_json::from_value::<Cacao>(serialized).expect("serialized DTO should deserialize");
    assert_eq!(&deserialized, value);
}

fn assert_payload_json_round_trip(value: &CacaoPayload) {
    let serialized = serde_json::to_value(value).expect("serializing DTO value should not fail");
    let deserialized = serde_json::from_value::<CacaoPayload>(serialized)
        .expect("serialized DTO should deserialize");
    assert_eq!(&deserialized, value);
}
