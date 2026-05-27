//! Encoding helpers shared by protocol primitives.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;

pub fn base64url_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
}

pub fn base64url_bytes(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Decodes validated lowercase hex into caller-provided fixed-size storage.
///
/// Fixed-width primitives validate the wire string at construction time. This
/// shared helper keeps their byte accessors small and avoids duplicating
/// nibble decoding in every primitive.
pub fn decode_validated_hex(value: &str, output: &mut [u8]) {
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = hex_pair(chunk[0], chunk[1]);
    }
}

pub fn query_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                escaped.push(char::from(byte));
            }
            _ => push_percent_encoded(&mut escaped, byte),
        }
    }
    escaped
}

fn push_percent_encoded(output: &mut String, byte: u8) {
    // RFC 3986 percent encoding for query parameter values. Keeping this local
    // avoids accepting form-url-encoding semantics such as `+` for spaces.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    output.push('%');
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
}

/// Decodes a validated lowercase hex byte pair.
///
/// Primitive constructors check width and hex alphabet once, so byte accessors
/// can decode without carrying parse errors through every caller.
fn hex_pair(high: u8, low: u8) -> u8 {
    (hex_nibble(high) << 4) | hex_nibble(low)
}

/// Maps one validated lowercase ASCII hex character to its numeric nibble.
fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("protocol primitive constructors validate lowercase hex input"),
    }
}
