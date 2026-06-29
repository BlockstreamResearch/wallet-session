use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    time::{SystemTime, SystemTimeError, UNIX_EPOCH},
};

use serde_json::Value;
use wc_core::{SingleSessionClient, SingleSessionClientConnectionState, WalletRedirectOrigin};
use wc_protocol::{
    relay::RelayTopic,
    session::{Cacao, SessionEventParams},
};

use crate::error::WcUniFfiError;

pub fn parse_redirect_origin(value: &str) -> Result<WalletRedirectOrigin, WcUniFfiError> {
    match value {
        "unknown" | "Unknown" => Ok(WalletRedirectOrigin::Unknown),
        "qr" | "qrCode" | "QrCode" => Ok(WalletRedirectOrigin::QrCode),
        "deepLink" | "DeepLink" => Ok(WalletRedirectOrigin::DeepLink),
        other => Err(invalid_input(format!(
            "unsupported redirect origin: {other}"
        ))),
    }
}

pub const fn connection_state_label(state: SingleSessionClientConnectionState) -> &'static str {
    match state {
        SingleSessionClientConnectionState::Connected => "connected",
        SingleSessionClientConnectionState::Reconnecting => "reconnecting",
        SingleSessionClientConnectionState::DisconnectedByUser => "disconnectedByUser",
        SingleSessionClientConnectionState::Unavailable => "unavailable",
    }
}

pub fn parse_topic(topic: &str) -> Result<RelayTopic, WcUniFfiError> {
    RelayTopic::from_hex(topic.to_owned()).map_err(invalid_error)
}

pub fn parse_json_value(json: &str) -> Result<Value, WcUniFfiError> {
    serde_json::from_str(json).map_err(|error| invalid_input(format!("invalid JSON: {error}")))
}

pub fn parse_json_object(json: &str) -> Result<BTreeMap<String, Value>, WcUniFfiError> {
    let Value::Object(object) = parse_json_value(json)? else {
        return Err(invalid_input("expected a JSON object"));
    };
    Ok(object.into_iter().collect())
}

pub fn json_string<T: serde::Serialize + ?Sized>(value: &T) -> Result<String, WcUniFfiError> {
    serde_json::to_string(value).map_err(operation_error)
}

pub fn now_unix_seconds() -> Result<u64, WcUniFfiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(clock_error)
        .map(|duration| duration.as_secs())
}

pub fn non_empty(name: &str, value: String) -> Result<String, WcUniFfiError> {
    if value.is_empty() {
        return Err(invalid_input(format!("{name} must not be empty")));
    }
    Ok(value)
}

pub fn i64_to_u64(name: &str, value: i64) -> Result<u64, WcUniFfiError> {
    u64::try_from(value).map_err(|_| invalid_input(format!("{name} must be non-negative")))
}

pub fn i64_to_usize(name: &str, value: i64) -> Result<usize, WcUniFfiError> {
    usize::try_from(value).map_err(|_| invalid_input(format!("{name} is out of range")))
}

pub fn u64_to_i64(value: u64) -> Result<i64, WcUniFfiError> {
    i64::try_from(value).map_err(|_| invalid_input("value exceeds signed 64-bit range"))
}

pub fn hex_32(name: &str, value: &str) -> Result<[u8; 32], WcUniFfiError> {
    if value.len() != 64 {
        return Err(invalid_input(format!(
            "{name} must be 64 lowercase hex characters"
        )));
    }
    let mut output = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_value(chunk[0]).ok_or_else(|| {
            invalid_input(format!("{name} has invalid hex at byte {}", index * 2))
        })?;
        let low = hex_value(chunk[1]).ok_or_else(|| {
            invalid_input(format!("{name} has invalid hex at byte {}", index * 2 + 1))
        })?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn parse_cacaos_json(json: &str) -> Result<Vec<Cacao>, WcUniFfiError> {
    serde_json::from_str(json)
        .map_err(|error| invalid_input(format!("invalid CACAO JSON: {error}")))
}

pub fn parse_session_event_params_json(json: &str) -> Result<SessionEventParams, WcUniFfiError> {
    serde_json::from_str(json)
        .map_err(|error| invalid_input(format!("invalid session event params JSON: {error}")))
}

pub fn remember_verify_context_if_present(
    client: &SingleSessionClient,
    topic: &RelayTopic,
    request_id: u64,
    verify_context_json: Option<String>,
) -> Result<(), WcUniFfiError> {
    let _ = (client, topic, request_id);
    if verify_context_json.is_some() {
        return Err(invalid_input(
            "caller-supplied Verify context JSON is not accepted; use Rust-resolved pending approval context",
        ));
    }
    Ok(())
}

pub fn invalid_error(error: impl fmt::Display) -> WcUniFfiError {
    invalid_input(error.to_string())
}

pub fn invalid_input(message: impl Into<String>) -> WcUniFfiError {
    WcUniFfiError::InvalidInput {
        details: message.into(),
    }
}

pub fn state_error(message: impl Into<String>) -> WcUniFfiError {
    WcUniFfiError::State {
        details: message.into(),
    }
}

pub fn operation_error(error: impl Error) -> WcUniFfiError {
    WcUniFfiError::Operation {
        details: error_with_sources(&error),
    }
}

fn error_with_sources(error: &dyn Error) -> String {
    let mut details = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        details.push_str(": ");
        details.push_str(&error.to_string());
        source = error.source();
    }
    details
}

fn clock_error(error: SystemTimeError) -> WcUniFfiError {
    WcUniFfiError::Operation {
        details: format!("system clock before unix epoch: {error}"),
    }
}
