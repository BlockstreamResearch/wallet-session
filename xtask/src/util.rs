use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde_json::Value;
use wc_protocol::{
    pairing::PairingSymKey,
    relay::{RelayAuthToken, RelayRpcId, RelayTopic},
    session::Cacao,
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
        cacao.p.iss.as_str(),
        cacao.p.iss.account_id_str(),
        cacao.p.iss.chain_id(),
        cacao.p.iss.address(),
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

pub fn redact(value: &str) -> String {
    if value.len() <= 8 {
        return "<redacted>".to_owned();
    }

    format!("{}...{}", &value[..4], &value[value.len() - 4..])
}
