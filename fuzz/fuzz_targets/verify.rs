#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use wc_protocol::verify::{
    VerifyAttestationHash, VerifyContext, VerifyJwtAttestation, VerifyJwtAttestationJws,
    VerifyJwtPublicKeyResponse,
};

const MAX_INPUT_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(input) = std::str::from_utf8(data) {
        parse_verify_jwt(input);
        parse_attestation_hash(input);
    }

    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return;
    };

    parse_verify_context(&value);
    parse_public_key_response(&value);
    parse_attestation_payload(&value);
    parse_wrapped_strings(&value);
});

fn parse_verify_context(value: &Value) {
    let Ok(context) = serde_json::from_value::<VerifyContext>(value.clone()) else {
        return;
    };

    let serialized =
        serde_json::to_value(&context).expect("serializing verify context should not fail");
    let reparsed =
        serde_json::from_value::<VerifyContext>(serialized).expect("serialized context parses");
    assert_eq!(reparsed, context);
}

fn parse_public_key_response(value: &Value) {
    let Ok(response) = serde_json::from_value::<VerifyJwtPublicKeyResponse>(value.clone()) else {
        return;
    };

    if let Ok(sec1) = response.public_key.sec1_bytes() {
        assert_eq!(sec1.len(), 65);
        assert_eq!(sec1[0], 0x04);
    }

    let serialized =
        serde_json::to_value(&response).expect("serializing verify public key should not fail");
    let reparsed = serde_json::from_value::<VerifyJwtPublicKeyResponse>(serialized)
        .expect("serialized public key parses");
    assert_eq!(reparsed, response);
}

fn parse_attestation_payload(value: &Value) {
    let Ok(payload) = serde_json::from_value::<VerifyJwtAttestation>(value.clone()) else {
        return;
    };

    if payload.exp == 0 {
        assert!(payload.is_expired_at(0));
    } else {
        assert!(!payload.is_expired_at(payload.exp - 1));
        assert!(payload.is_expired_at(payload.exp));
    }
}

fn parse_wrapped_strings(value: &Value) {
    for key in ["jwt", "attestation", "hash", "attestationHash"] {
        if let Some(input) = value.get(key).and_then(Value::as_str) {
            parse_verify_jwt(input);
            parse_attestation_hash(input);
        }
    }
}

fn parse_verify_jwt(input: &str) {
    let Ok(jws) = VerifyJwtAttestationJws::decode(input) else {
        return;
    };

    assert_eq!(jws.signature().len(), 64);
    assert!(jws.signing_input().contains(&b'.'));

    let payload = jws.payload();
    if payload.exp == 0 {
        assert!(payload.is_expired_at(0));
    } else {
        assert!(!payload.is_expired_at(payload.exp - 1));
        assert!(payload.is_expired_at(payload.exp));
    }
}

fn parse_attestation_hash(input: &str) {
    if let Ok(hash) = VerifyAttestationHash::parse(input) {
        assert_eq!(VerifyAttestationHash::parse(hash.as_str()), Ok(hash));
    }
}
