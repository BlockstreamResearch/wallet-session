use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use wc_protocol::{
    pairing::PairingSymKey,
    relay::{RelayAuthToken, RelayRpcId, RelayTopic},
    session::Cacao,
    verify::VerifyAttestationHash,
};

pub const fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub fn print_cacao_summary(prefix: &str, index: usize, cacao: &Cacao) {
    println!(
        "{} cacao index={} header={} signature_type={} iss={} account={} chain={} address={} domain={} aud={} resources={}",
        prefix,
        index,
        cacao.h.kind.as_str(),
        cacao.s.kind.as_str(),
        sensitive_str_for_log(cacao.p.iss.as_str()),
        sensitive_str_for_log(cacao.p.iss.account_id_str()),
        cacao.p.iss.chain_id(),
        sensitive_str_for_log(cacao.p.iss.address()),
        cacao.p.domain,
        cacao.p.aud,
        cacao.p.resources.len()
    );
}
pub fn client_auth_jwt(audience: &str, seed: &[u8; 32]) -> Result<RelayAuthToken> {
    let sub = random_hex(16)?;
    let iat = unix_timestamp();
    RelayAuthToken::sign_with_seed(seed, &sub, audience, iat, 86_400)
        .context("failed to sign relay auth token")
}

pub fn rpc_id() -> Result<RelayRpcId> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = u64::try_from(now.as_millis()).context("epoch millis do not fit in u64")?;
    let entropy = now.subsec_micros() % 1_000_000;

    RelayRpcId::from_millis_entropy(millis, entropy).context("failed to build relay rpc id")
}

pub fn generated_topic() -> Result<RelayTopic> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).context("failed to generate relay topic")?;
    Ok(RelayTopic::from_bytes(bytes))
}

pub fn generated_sym_key() -> Result<PairingSymKey> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).context("failed to generate symmetric key")?;
    PairingSymKey::from_hex(hex_string(&bytes)).context("failed to build symmetric key")
}

fn random_hex(len: usize) -> Result<String> {
    let mut bytes = vec![0_u8; len];
    getrandom::fill(&mut bytes).context("failed to generate random bytes")?;
    Ok(hex_string(&bytes))
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn pairing_uri_wait_timeout() -> Duration {
    env::var("WC_PAIRING_URI_WAIT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(Duration::from_secs(5), Duration::from_secs)
}

pub fn pairing_uri_print_json() -> bool {
    matches!(
        env::var("WC_PAIRING_URI_PRINT_JSON").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

pub fn log_decrypted_payloads() -> bool {
    matches!(
        env::var("WC_LOG_DECRYPTED_PAYLOADS").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

pub fn sensitive_str_for_log(value: &str) -> String {
    if log_decrypted_payloads() {
        value.to_owned()
    } else {
        redact(value)
    }
}

pub fn json_for_log(value: &Value) -> String {
    if log_decrypted_payloads() {
        value.to_string()
    } else {
        redacted_json_summary(value).to_string()
    }
}

pub fn serialize_for_log<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(value) => json_for_log(&value),
        Err(error) => format!(r#"{{"redacted":true,"type":"unserializable","error":"{error}"}}"#),
    }
}

pub fn redacted_json_summary(value: &Value) -> Value {
    let canonical = value.to_string();
    let hash = VerifyAttestationHash::from_message(&canonical);
    match value {
        Value::Object(object) => json!({
            "redacted": true,
            "type": json_kind(value),
            "keys": object.keys().cloned().collect::<Vec<_>>(),
            "len": object.len(),
            "hash": hash.as_str(),
        }),
        Value::Array(array) => json!({
            "redacted": true,
            "type": json_kind(value),
            "len": array.len(),
            "hash": hash.as_str(),
        }),
        Value::String(string) => json!({
            "redacted": true,
            "type": json_kind(value),
            "len": string.len(),
            "hash": hash.as_str(),
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) => json!({
            "redacted": true,
            "type": json_kind(value),
            "hash": hash.as_str(),
        }),
    }
}

pub fn redact(value: &str) -> String {
    let hash = VerifyAttestationHash::from_message(value);
    format!("<redacted len={} hash={}>", value.len(), hash.as_str())
}
