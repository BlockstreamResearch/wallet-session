//! Pairing URI parser.

use std::{borrow::Cow, fmt, num::ParseIntError, string::FromUtf8Error};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use serde::Serialize;

use crate::{
    encoding::{decode_validated_hex, hex_lower},
    relay::{RelayTopic, RelayTopicError},
};

/// `WalletConnect` v2 pairing URI.
///
/// <https://github.com/ethereum/ERCs/blob/9b4ffa311293c6f404afc510511b93e1e04011f3/ERCS/erc-1328.md#L21-L29>
///
/// > request       = "wc" ":" topic [ "@" version ][ "?" parameters ]
///
/// <https://github.com/ethereum/ERCs/blob/9b4ffa311293c6f404afc510511b93e1e04011f3/ERCS/erc-1328.md#L40-L46>
///
/// > `symKey` - symmetric key used for encrypting messages over relay
///
/// # Examples
///
/// ```
/// use wc_protocol::pairing::PairingUri;
///
/// let uri = PairingUri::parse(
///     "wc:7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9@2\
///      ?relay-protocol=irn\
///      &symKey=587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303\
///      &methods=wc_sessionPropose,wc_authRequest\
///      &expiryTimestamp=1705934757",
/// )?;
///
/// assert_eq!(uri.topic().as_str(), "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9");
/// assert_eq!(uri.relay().protocol(), "irn");
/// assert_eq!(uri.methods().unwrap(), ["wc_sessionPropose", "wc_authRequest"]);
/// assert!(uri.is_expired_at(1_800_000_000));
/// # Ok::<(), wc_protocol::pairing::PairingUriError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingUri {
    version: PairingVersion,
    topic: RelayTopic,
    sym_key: PairingSymKey,
    relay: PairingRelay,
    methods: Option<Vec<String>>,
    expiry_timestamp: Option<u64>,
}

impl PairingUri {
    /// Parses a `wc:` URI, `wc://` URI, or base64-wrapped URI.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L19-L30>
    ///
    /// > if (!str.includes("wc:")) {
    /// > const parsed = fromBase64(str);
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L39-L49>
    ///
    /// > const methods =
    /// > typeof queryParams.methods === "string" ? queryParams.methods.split(",") : undefined;
    pub fn parse(input: &str) -> Result<Self, PairingUriError> {
        let input = decode_base64_wrapper(input)?;
        let body = input
            .strip_prefix("wc://")
            .or_else(|| input.strip_prefix("wc:"))
            .ok_or(PairingUriError::MissingScheme)?;

        let (path, query) = body.split_once('?').ok_or(PairingUriError::MissingQuery)?;
        let (topic, version) = path
            .rsplit_once('@')
            .ok_or(PairingUriError::MissingVersion)?;
        let topic = topic.strip_prefix("//").unwrap_or(topic);

        let topic = RelayTopic::from_hex(topic)
            .map_err(|source| PairingUriError::InvalidTopic { source })?;
        let version = parse_version(version)?;
        let query = parse_query(query)?;

        Ok(Self {
            version,
            topic,
            sym_key: query.sym_key,
            relay: query.relay,
            methods: query.methods,
            expiry_timestamp: query.expiry_timestamp,
        })
    }

    /// Pairing URI version.
    #[must_use]
    pub const fn version(&self) -> PairingVersion {
        self.version
    }

    /// Relay topic from the URI path.
    #[must_use]
    pub const fn topic(&self) -> &RelayTopic {
        &self.topic
    }

    /// Symmetric key advertised by the dapp.
    #[must_use]
    pub const fn sym_key(&self) -> &PairingSymKey {
        &self.sym_key
    }

    /// Relay transport parameters.
    #[must_use]
    pub const fn relay(&self) -> &PairingRelay {
        &self.relay
    }

    /// JSON-RPC methods advertised for the pairing topic.
    #[must_use]
    pub fn methods(&self) -> Option<&[String]> {
        self.methods.as_deref()
    }

    /// Pairing expiry timestamp in unix seconds.
    #[must_use]
    pub const fn expiry_timestamp(&self) -> Option<u64> {
        self.expiry_timestamp
    }

    /// Compares `expiryTimestamp` to a caller-provided unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.expiry_timestamp
            .is_some_and(|expiry| expiry <= now_unix_seconds)
    }
}

/// Pairing URI version accepted by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PairingVersion {
    /// `WalletConnect` v2.
    V2,
}

impl PairingVersion {
    /// Numeric value serialized in the URI path.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::V2 => 2,
        }
    }
}

impl fmt::Display for PairingVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_u32().fmt(formatter)
    }
}

/// Symmetric key carried in the pairing URI.
///
/// <https://github.com/ethereum/ERCs/blob/9b4ffa311293c6f404afc510511b93e1e04011f3/ERCS/erc-1328.md#L40-L46>
///
/// > `symKey` - symmetric key used for encrypting messages over relay
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PairingSymKey(String);

impl PairingSymKey {
    /// Validates a 32-byte key encoded as 64 hex characters.
    pub fn from_hex(value: impl Into<String>) -> Result<Self, PairingSymKeyError> {
        let value = value.into();
        if value.len() != PAIRING_SYM_KEY_HEX {
            return Err(PairingSymKeyError::InvalidLength {
                actual: value.len(),
            });
        }

        if let Some((index, character)) = value
            .char_indices()
            .find(|(_, character)| !character.is_ascii_hexdigit())
        {
            return Err(PairingSymKeyError::InvalidHexCharacter { index, character });
        }

        Ok(Self(value.to_ascii_lowercase()))
    }

    /// Creates a symmetric key from raw key bytes.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/crypto.ts#L49-L55>
    ///
    /// > const symKey = hkdf(sha256, sharedKey, undefined, undefined, KEY_LENGTH);
    /// > return toString(symKey, BASE16);
    #[must_use]
    pub fn from_bytes(bytes: [u8; PAIRING_SYM_KEY_BYTES]) -> Self {
        Self(hex_lower(&bytes))
    }

    /// Lowercase hex form from the URI query string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decodes the 32-byte key used for symmetric envelope decryption.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/crypto.ts#L96-L100>
    ///
    /// > const key = fromString(params.symKey, BASE16);
    /// > const box = chacha20poly1305(key, iv);
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PAIRING_SYM_KEY_BYTES] {
        let mut bytes = [0_u8; PAIRING_SYM_KEY_BYTES];
        decode_validated_hex(&self.0, &mut bytes);
        bytes
    }
}

/// Relay transport options carried as `relay-*` query parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairingRelay {
    protocol: String,
    data: Option<String>,
}

impl PairingRelay {
    /// Relay transport protocol, currently `irn`.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Optional `relay-data` value.
    #[must_use]
    pub fn data(&self) -> Option<&str> {
        self.data.as_deref()
    }
}

/// Pairing URI parse error.
#[derive(Debug, thiserror::Error)]
pub enum PairingUriError {
    /// URI must start with `wc:` or decode from base64 to a `wc:` URI.
    #[error("missing wc URI scheme")]
    MissingScheme,

    /// Pairing URI path must include `@2`.
    #[error("missing pairing URI version")]
    MissingVersion,

    /// Pairing URI must include query parameters.
    #[error("missing pairing URI query")]
    MissingQuery,

    /// Pairing URI version is not an integer.
    #[error("invalid pairing URI version: {value}")]
    InvalidVersion {
        /// Version value from the URI path.
        value: String,
        /// Integer parse failure.
        #[source]
        source: ParseIntError,
    },

    /// Only `WalletConnect` v2 is accepted.
    #[error("unsupported pairing URI version: {0}")]
    UnsupportedVersion(u32),

    /// Topic failed relay topic validation.
    #[error("invalid pairing URI topic")]
    InvalidTopic {
        /// Relay topic parse failure.
        #[source]
        source: RelayTopicError,
    },

    /// Required query parameter is absent.
    #[error("missing pairing URI query parameter: {0}")]
    MissingParameter(&'static str),

    /// Known query parameters must be unique.
    #[error("duplicate pairing URI query parameter: {0}")]
    DuplicateParameter(&'static str),

    /// `symKey` failed 32-byte hex validation.
    #[error("invalid pairing URI symKey")]
    InvalidSymKey {
        /// Symmetric key parse failure.
        #[source]
        source: PairingSymKeyError,
    },

    /// Only the IRN relay protocol is handled by the current relay harness.
    #[error("unsupported pairing URI relay protocol: {0}")]
    UnsupportedRelayProtocol(String),

    /// `methods` contained an empty comma-separated entry.
    #[error("empty pairing URI method at index {index}")]
    EmptyMethod {
        /// Entry index in `methods`.
        index: usize,
    },

    /// `expiryTimestamp` is not an unsigned integer.
    #[error("invalid pairing URI expiryTimestamp: {value}")]
    InvalidExpiryTimestamp {
        /// Query value.
        value: String,
        /// Integer parse failure.
        #[source]
        source: ParseIntError,
    },

    /// Base64 wrapper decoded to invalid UTF-8.
    #[error("base64 pairing URI is not UTF-8")]
    Base64Utf8 {
        /// UTF-8 conversion failure.
        #[source]
        source: FromUtf8Error,
    },
}

/// Symmetric key parse error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PairingSymKeyError {
    /// Symmetric keys are fixed-width 32-byte values, represented as 64 hex characters.
    #[error("pairing symKey must be 64 hex characters, got {actual}")]
    InvalidLength {
        /// Input length in bytes.
        actual: usize,
    },

    /// Non-hex input cannot map to a 32-byte symmetric key.
    #[error("pairing symKey contains non-hex character {character:?} at byte index {index}")]
    InvalidHexCharacter {
        /// Byte index in the original input.
        index: usize,
        /// Character rejected by ASCII hex validation.
        character: char,
    },
}

/// Pairing `symKey` size before hex encoding.
pub const PAIRING_SYM_KEY_BYTES: usize = 32;

/// Pairing `symKey` size after lowercase hex encoding.
pub const PAIRING_SYM_KEY_HEX: usize = PAIRING_SYM_KEY_BYTES * 2;

/// Query parameter accumulator used before required fields are known.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/types/src/sign-client/engine.ts#L42-L50>
///
/// > interface UriParameters {
/// > symKey: string;
///
/// `form_urlencoded::parse` yields pairs in source order. Keeping every known
/// field optional until the scan is complete lets the parser report duplicate
/// parameters before it reports missing required parameters.
#[derive(Default)]
struct QueryParams {
    /// Raw `symKey` after 32-byte hex validation.
    sym_key: Option<PairingSymKey>,
    /// `relay-protocol`; currently only `irn` is accepted.
    relay_protocol: Option<String>,
    /// Optional `relay-data` value.
    relay_data: Option<String>,
    /// Optional comma-separated `methods` value after splitting.
    methods: Option<Vec<String>>,
    /// Optional unix timestamp from `expiryTimestamp`.
    expiry_timestamp: Option<u64>,
}

/// Fully validated query data promoted into `PairingUri`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L41-L51>
///
/// > const result = {
/// > topic: parseTopic(requiredValues[0]),
///
/// This separates parsing state from the public DTO so `PairingUri` never has
/// optional fields for values that the v2 URI format requires.
struct ParsedQuery {
    /// Required symmetric key.
    sym_key: PairingSymKey,
    /// Required relay protocol plus optional relay data.
    relay: PairingRelay,
    /// Optional pairing-topic methods.
    methods: Option<Vec<String>>,
    /// Optional pairing expiry.
    expiry_timestamp: Option<u64>,
}

/// Decodes the base64 wrapper accepted by the JavaScript implementation.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L19-L25>
///
/// > if (!str.includes("wc:")) {
/// > const parsed = fromBase64(str);
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/misc.ts#L563-L570>
///
/// > const padded = encodedString + "=".repeat((4 - (encodedString.length % 4)) % 4);
/// > const binary = atob(padded);
///
/// Wallet deep-link transports sometimes pass the URI through an outer base64
/// layer. The maintained implementation attempts base64 decoding only when the
/// input does not already contain `wc:`; this mirrors that behavior and keeps
/// normal `wc:` parsing allocation-free by returning a borrowed string.
///
/// Invalid base64 is not treated as its own parse error because non-URI input
/// should still fail at the URI layer with `MissingScheme`.
fn decode_base64_wrapper(input: &str) -> Result<Cow<'_, str>, PairingUriError> {
    if input.contains("wc:") {
        return Ok(Cow::Borrowed(input));
    }

    let Ok(bytes) = STANDARD
        .decode(input)
        .or_else(|_| STANDARD_NO_PAD.decode(input))
    else {
        return Ok(Cow::Borrowed(input));
    };
    let decoded =
        String::from_utf8(bytes).map_err(|source| PairingUriError::Base64Utf8 { source })?;

    Ok(Cow::Owned(decoded))
}

/// Parses the numeric URI version and rejects versions this crate cannot use.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L41-L49>
///
/// > version: parseInt(requiredValues[1], 10),
///
/// Integer parsing and protocol support are separate errors: `@abc` is malformed
/// input, while `@1` is a well-formed URI for a protocol version not implemented
/// by this v2 parser.
fn parse_version(value: &str) -> Result<PairingVersion, PairingUriError> {
    let version = value
        .parse::<u32>()
        .map_err(|source| PairingUriError::InvalidVersion {
            value: value.to_owned(),
            source,
        })?;

    match version {
        2 => Ok(PairingVersion::V2),
        other => Err(PairingUriError::UnsupportedVersion(other)),
    }
}

/// Parses and validates the query string using `URLSearchParams` semantics.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L35-L38>
///
/// > const urlSearchParams = new URLSearchParams(queryString);
/// > const queryParams = Object.fromEntries(urlSearchParams.entries());
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L6-L16>
///
/// > if (key.startsWith(prefix)) {
/// > relay[name] = value;
///
/// The JavaScript implementation builds query parameters with `URLSearchParams`;
/// `form_urlencoded` gives the same pair iteration and percent-decoding behavior
/// without pulling in a full URL parser. That matters here because `wc:` URIs are
/// parsed by their own grammar first, then only the query component is decoded.
///
/// Unknown query parameters are ignored for forward compatibility. Known
/// parameters are rejected when duplicated so malicious or malformed input cannot
/// rely on first-value/last-value differences between implementations.
fn parse_query(query: &str) -> Result<ParsedQuery, PairingUriError> {
    let mut params = QueryParams::default();

    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "symKey" => {
                set_once(
                    &mut params.sym_key,
                    PairingSymKey::from_hex(value.into_owned())
                        .map_err(|source| PairingUriError::InvalidSymKey { source })?,
                    "symKey",
                )?;
            }
            "relay-protocol" => {
                let value = value.into_owned();
                if value != "irn" {
                    return Err(PairingUriError::UnsupportedRelayProtocol(value));
                }
                set_once(&mut params.relay_protocol, value, "relay-protocol")?;
            }
            "relay-data" => {
                set_once(&mut params.relay_data, value.into_owned(), "relay-data")?;
            }
            "methods" => {
                set_once(&mut params.methods, parse_methods(&value)?, "methods")?;
            }
            "expiryTimestamp" => {
                let value = value.into_owned();
                let expiry_timestamp = value
                    .parse::<u64>()
                    .map_err(|source| PairingUriError::InvalidExpiryTimestamp { value, source })?;
                set_once(
                    &mut params.expiry_timestamp,
                    expiry_timestamp,
                    "expiryTimestamp",
                )?;
            }
            _ => {}
        }
    }

    let sym_key = params
        .sym_key
        .ok_or(PairingUriError::MissingParameter("symKey"))?;
    let relay_protocol = params
        .relay_protocol
        .ok_or(PairingUriError::MissingParameter("relay-protocol"))?;

    Ok(ParsedQuery {
        sym_key,
        relay: PairingRelay {
            protocol: relay_protocol,
            data: params.relay_data,
        },
        methods: params.methods,
        expiry_timestamp: params.expiry_timestamp,
    })
}

/// Splits the pairing-topic method list exactly at commas.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L39-L40>
///
/// > typeof queryParams.methods === "string" ? queryParams.methods.split(",") : undefined;
///
/// The maintained JavaScript parser uses `methods.split(",")`; this parser keeps
/// that wire behavior instead of interpreting ERC-1328's bracketed examples as a
/// richer grammar. Empty entries are rejected because they usually indicate a
/// trailing comma or adjacent separators, neither of which names a JSON-RPC
/// method.
fn parse_methods(value: &str) -> Result<Vec<String>, PairingUriError> {
    value
        .split(',')
        .enumerate()
        .map(|(index, method)| {
            if method.is_empty() {
                Err(PairingUriError::EmptyMethod { index })
            } else {
                Ok(method.to_owned())
            }
        })
        .collect()
}

/// Assigns a query parameter that must appear at most once.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/c93ada3d30c178ff43b037c46fd3e9b28f109d91/packages/utils/src/uri.ts#L35-L38>
///
/// > const queryParams = Object.fromEntries(urlSearchParams.entries());
///
/// Query parsing should not silently choose either the first or last value for
/// security-sensitive fields like `symKey` or `relay-protocol`. A small helper
/// keeps that duplicate rejection consistent across all known parameters.
fn set_once<T>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), PairingUriError> {
    if slot.replace(value).is_some() {
        return Err(PairingUriError::DuplicateParameter(key));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    use super::*;

    const TOPIC: &str = "7f6e504bfad60b485450578e05678ed3e8e8c4751d3c6160be17160d63ec90f9";
    const SYM_KEY: &str = "587d5484ce2a2a6ee3ba1962fdd7e8588e06200c46823bd18fbd67def96ad303";

    fn uri() -> String {
        format!(
            "wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}&methods=wc_sessionPropose,wc_authRequest&expiryTimestamp=1705934757"
        )
    }

    #[test]
    fn parses_pairing_uri() {
        let pairing = PairingUri::parse(&uri()).expect("pairing URI parses");

        assert_eq!(pairing.version(), PairingVersion::V2);
        assert_eq!(pairing.topic().as_str(), TOPIC);
        assert_eq!(pairing.sym_key().as_str(), SYM_KEY);
        assert_eq!(pairing.relay().protocol(), "irn");
        assert_eq!(
            pairing.methods(),
            Some(["wc_sessionPropose".to_owned(), "wc_authRequest".to_owned()].as_slice())
        );
        assert_eq!(pairing.expiry_timestamp(), Some(1_705_934_757));
        assert!(pairing.is_expired_at(1_800_000_000));
    }

    #[test]
    fn parses_android_style_prefix() {
        let uri = format!("wc://{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}");
        let pairing = PairingUri::parse(&uri).expect("pairing URI parses");

        assert_eq!(pairing.topic().as_str(), TOPIC);
    }

    #[test]
    fn parses_base64_wrapped_uri() {
        let encoded = STANDARD.encode(uri());
        let pairing = PairingUri::parse(&encoded).expect("base64 URI parses");

        assert_eq!(pairing.topic().as_str(), TOPIC);
        assert_eq!(pairing.sym_key().as_str(), SYM_KEY);
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(matches!(
            PairingUri::parse("https://example.com").expect_err("scheme is invalid"),
            PairingUriError::MissingScheme
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let uri = format!("wc:{TOPIC}@1?relay-protocol=irn&symKey={SYM_KEY}");

        assert!(matches!(
            PairingUri::parse(&uri).expect_err("version is unsupported"),
            PairingUriError::UnsupportedVersion(1)
        ));
    }

    #[test]
    fn rejects_invalid_sym_key() {
        let uri = format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={}", "0".repeat(63));

        assert!(matches!(
            PairingUri::parse(&uri).expect_err("symKey is too short"),
            PairingUriError::InvalidSymKey {
                source: PairingSymKeyError::InvalidLength { actual: 63 }
            }
        ));
    }

    #[test]
    fn rejects_duplicate_known_parameter() {
        let uri = format!("wc:{TOPIC}@2?relay-protocol=irn&relay-protocol=irn&symKey={SYM_KEY}");

        assert!(matches!(
            PairingUri::parse(&uri).expect_err("relay protocol is duplicated"),
            PairingUriError::DuplicateParameter("relay-protocol")
        ));
    }

    #[test]
    fn rejects_empty_method() {
        let uri =
            format!("wc:{TOPIC}@2?relay-protocol=irn&symKey={SYM_KEY}&methods=wc_sessionPropose,");

        assert!(matches!(
            PairingUri::parse(&uri).expect_err("methods contains empty entry"),
            PairingUriError::EmptyMethod { index: 1 }
        ));
    }
}
