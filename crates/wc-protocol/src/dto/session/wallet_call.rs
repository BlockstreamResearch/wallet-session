//! Wallet Call API DTOs.

use std::{collections::BTreeMap, fmt};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned, ser::SerializeSeq,
};
use serde_json::Value;

use super::SessionRequest;

/// Dynamic capability payload keyed by capability name.
///
/// EIP-5792 leaves individual capability schemas to later ERCs, while fixing
/// the surrounding map shape.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls-rpc-specification>
///
/// > Each capability defined in the “capabilities” member can define global or
/// > call specific fields.
pub type WalletCapabilityMap = BTreeMap<String, Value>;

/// `wallet_getCapabilities` result keyed by hex EIP-155 chain ID.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_getcapabilities-rpc-specification>
///
/// > Capabilities are returned in key/value pairs, with the key naming a
/// > capability and a value conforming to a shape defined for that name
pub type WalletGetCapabilitiesResult = BTreeMap<String, WalletCapabilityMap>;

/// EIP-5792 Wallet Call JSON-RPC method.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#specification>
///
/// > Four new JSON-RPC methods are added: three are for handling batches of
/// > onchain calls, and one is for querying support for wallet capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WalletCallMethod {
    /// `wallet_getCapabilities`.
    GetCapabilities,
    /// `wallet_sendCalls`.
    SendCalls,
    /// `wallet_getCallsStatus`.
    GetCallsStatus,
    /// `wallet_showCallsStatus`.
    ShowCallsStatus,
}

impl WalletCallMethod {
    /// Wire method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GetCapabilities => "wallet_getCapabilities",
            Self::SendCalls => "wallet_sendCalls",
            Self::GetCallsStatus => "wallet_getCallsStatus",
            Self::ShowCallsStatus => "wallet_showCallsStatus",
        }
    }

    /// Matches a session request method without allocating.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "wallet_getCapabilities" => Some(Self::GetCapabilities),
            "wallet_sendCalls" => Some(Self::SendCalls),
            "wallet_getCallsStatus" => Some(Self::GetCallsStatus),
            "wallet_showCallsStatus" => Some(Self::ShowCallsStatus),
            _ => None,
        }
    }
}

impl fmt::Display for WalletCallMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Parsed Wallet Call request params.
///
/// `wc_sessionRequest` keeps method params as arbitrary JSON. This enum applies
/// the EIP-5792 method-specific shape after namespace authorization has already
/// accepted the request method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletCallRequest {
    /// `wallet_getCapabilities` params.
    GetCapabilities(WalletGetCapabilitiesParams),
    /// `wallet_sendCalls` params.
    SendCalls(WalletSendCallsParams),
    /// `wallet_getCallsStatus` params.
    GetCallsStatus(WalletGetCallsStatusParams),
    /// `wallet_showCallsStatus` params.
    ShowCallsStatus(WalletShowCallsStatusParams),
}

impl WalletCallRequest {
    /// Parses EIP-5792 params from a generic session request.
    ///
    /// Non-Wallet Call methods return `Ok(None)` so callers can keep a single
    /// session request review path.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_json::json;
    /// use wc_protocol::session::{SessionRequest, WalletCallRequest};
    ///
    /// let request = SessionRequest {
    ///     method: "wallet_sendCalls".parse()?,
    ///     params: json!([{
    ///       "version": "2.0.0",
    ///       "chainId": "0x1",
    ///       "atomicRequired": true,
    ///       "calls": [{"to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567"}]
    ///     }]),
    ///     expiry_timestamp: None,
    /// };
    ///
    /// let wallet_call = WalletCallRequest::from_session_request(&request)?
    ///     .expect("wallet call method");
    /// assert_eq!(wallet_call.method().as_str(), "wallet_sendCalls");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_session_request(
        request: &SessionRequest,
    ) -> Result<Option<Self>, WalletCallRequestError> {
        let Some(method) = WalletCallMethod::from_wire(request.method.as_str()) else {
            return Ok(None);
        };

        let wallet_call = match method {
            WalletCallMethod::GetCapabilities => {
                Self::GetCapabilities(decode_params(method, &request.params)?)
            }
            WalletCallMethod::SendCalls => Self::SendCalls(decode_params(method, &request.params)?),
            WalletCallMethod::GetCallsStatus => {
                Self::GetCallsStatus(decode_params(method, &request.params)?)
            }
            WalletCallMethod::ShowCallsStatus => {
                Self::ShowCallsStatus(decode_params(method, &request.params)?)
            }
        };

        Ok(Some(wallet_call))
    }

    /// EIP-5792 method represented by this parsed request.
    #[must_use]
    pub const fn method(&self) -> WalletCallMethod {
        match self {
            Self::GetCapabilities(_) => WalletCallMethod::GetCapabilities,
            Self::SendCalls(_) => WalletCallMethod::SendCalls,
            Self::GetCallsStatus(_) => WalletCallMethod::GetCallsStatus,
            Self::ShowCallsStatus(_) => WalletCallMethod::ShowCallsStatus,
        }
    }
}

/// Decodes the generic `SessionRequest.params` value into a method DTO.
///
/// `WalletConnect` carries chain-specific params as `any`; the EIP-5792 method
/// name is the discriminator that gives this JSON a concrete shape.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L66-L73>
///
/// > wc_sessionRequest: { request: { method: string; params: any;
fn decode_params<T>(method: WalletCallMethod, params: &Value) -> Result<T, WalletCallRequestError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(params.clone())
        .map_err(|source| WalletCallRequestError::Params { method, source })
}

/// `wallet_getCapabilities` params.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_getcapabilities-rpc-specification>
///
/// > ``type GetCapabilitiesParams = [`0x${string}`, [`0x${string}`]];``
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletGetCapabilitiesParams(
    /// Wallet address.
    pub String,
    /// Optional hex EIP-155 chain IDs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Option<Vec<String>>,
);

/// `wallet_sendCalls` params.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls-rpc-specification>
///
/// > `type SendCallsParams = {`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletSendCallsParams(
    /// Batch call request.
    pub WalletSendCallsRequest,
);

impl Serialize for WalletSendCallsParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_one_param(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for WalletSendCallsParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_one_param(deserializer).map(Self)
    }
}

/// Batch call request for `wallet_sendCalls`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletSendCallsRequest {
    /// Request schema version.
    pub version: String,
    /// Optional app-provided batch identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Optional sender address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Hex EIP-155 chain ID.
    pub chain_id: String,
    /// Whether atomic execution is required.
    pub atomic_required: bool,
    /// Calls to submit in order.
    pub calls: Vec<WalletCall>,
    /// Top-level capability metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeMap<String, WalletCapabilityMap>>,
}

/// One call inside `wallet_sendCalls`.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls-rpc-specification>
///
/// > The items in the `calls` field are simple `{to, data, value}` tuples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCall {
    /// Optional target address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Optional calldata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Optional hex value in wei.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Call-specific capability metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeMap<String, WalletCapabilityMap>>,
}

/// `wallet_sendCalls` result.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls-rpc-specification>
///
/// > ``type SendCallsResult = { id: string; capabilities?: Record<string, any>; };``
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSendCallsResult {
    /// Batch identifier used by `wallet_getCallsStatus` and
    /// `wallet_showCallsStatus`.
    pub id: String,
    /// Optional capability-specific response metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<WalletCapabilityMap>,
}

/// `wallet_getCallsStatus` params.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_getcallsstatus-rpc-specification>
///
/// > `type GetCallsParams = [string];`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletGetCallsStatusParams(
    /// Batch identifier returned from `wallet_sendCalls`.
    pub String,
);

impl Serialize for WalletGetCallsStatusParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_one_param(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for WalletGetCallsStatusParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_one_param(deserializer).map(Self)
    }
}

/// `wallet_getCallsStatus` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletGetCallsStatusResult {
    /// Result schema version.
    pub version: String,
    /// Batch identifier.
    pub id: String,
    /// Hex EIP-155 chain ID.
    pub chain_id: String,
    /// EIP-5792 status code.
    pub status: u16,
    /// Whether calls were executed atomically.
    pub atomic: bool,
    /// Transaction receipts for included calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipts: Option<Vec<WalletCallReceipt>>,
    /// Optional capability-specific response metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<WalletCapabilityMap>,
}

/// Transaction receipt subset returned by `wallet_getCallsStatus`.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_getcallsstatus-rpc-specification>
///
/// > Note that the `receipts` objects of this method’s response is a strict
/// > subset of the object returned by `eth_getTransactionReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletCallReceipt {
    /// Logs relevant to the submitted calls.
    pub logs: Vec<WalletCallReceiptLog>,
    /// Hex receipt status.
    pub status: String,
    /// Block hash.
    pub block_hash: String,
    /// Hex block number.
    pub block_number: String,
    /// Hex gas used.
    pub gas_used: String,
    /// Transaction hash.
    pub transaction_hash: String,
}

/// Log entry inside a Wallet Call receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCallReceiptLog {
    /// Emitting contract address.
    pub address: String,
    /// Log data.
    pub data: String,
    /// Log topics.
    pub topics: Vec<String>,
}

/// `wallet_showCallsStatus` params.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_showcallsstatus-rpc-specification>
///
/// > `type ShowCallsParams = string;`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletShowCallsStatusParams(
    /// Batch identifier returned from `wallet_sendCalls`.
    pub String,
);

impl Serialize for WalletShowCallsStatusParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_one_param(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for WalletShowCallsStatusParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_one_param(deserializer).map(Self)
    }
}

/// JSON-RPC params for these methods are one-element arrays, while serde
/// newtype structs normally encode as the inner value. This helper keeps the
/// public Rust type small without losing the wire shape.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_sendcalls-rpc-specification>
///
/// > `wallet_sendCalls` Example Parameters
fn serialize_one_param<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: Serialize,
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(1))?;
    seq.serialize_element(value)?;
    seq.end()
}

/// Decodes a one-element JSON-RPC params array through the target DTO.
///
/// EIP-5792 uses `[SendCallsParams]`, `[string]`, and `[string]` for these
/// methods. Parsing through `serde_json::from_value` preserves the source
/// error for the caller-facing `WalletCallRequestError`.
///
/// <https://eips.ethereum.org/EIPS/eip-5792#wallet_getcallsstatus-rpc-specification>
///
/// > `type GetCallsParams = [string];`
fn deserialize_one_param<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let mut values = Vec::<Value>::deserialize(deserializer)?;
    if values.len() != 1 {
        return Err(serde::de::Error::invalid_length(
            values.len(),
            &"a one-element JSON-RPC params array",
        ));
    }
    serde_json::from_value(values.remove(0)).map_err(serde::de::Error::custom)
}

/// Parsing error for EIP-5792 params carried in `wc_sessionRequest`.
#[derive(Debug, thiserror::Error)]
pub enum WalletCallRequestError {
    /// The request method is a Wallet Call method, but its params do not match
    /// the method-specific EIP-5792 shape.
    #[error("wallet call params decode failed for {method}")]
    Params {
        /// Wallet Call method being decoded.
        method: WalletCallMethod,
        /// Serde decode source.
        #[source]
        source: serde_json::Error,
    },
}
