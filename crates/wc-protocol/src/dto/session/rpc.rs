//! Sign API JSON-RPC envelopes.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::Value;

use super::SignMethod;
use crate::relay::JSON_RPC_VERSION;

/// JSON-RPC request envelope for Sign API methods.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/engine.ts#L52-L58>
///
/// > interface EventCallback<T extends JsonRpcRequest | JsonRpcResponse> {
/// > payload: T;
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{
///     JsonRpcRequest, SessionProposeParams, SignMethod,
/// };
///
/// let json = r#"{
///   "id": 1,
///   "jsonrpc": "2.0",
///   "method": "wc_sessionPropose",
///   "params": {
///     "id": 1,
///     "pairingTopic": "3c74583111ab5e006b03cbb0f252c667686e9fc01e675dff90aa8b18ec435feb",
///     "expiryTimestamp": 1700000300,
///     "relays": [{"protocol": "irn"}],
///     "proposer": {
///       "publicKey": "a3ad5e26070ddb2809200c6f56e739333512015bceeadbb8ea1731c4c7ddb207",
///       "metadata": {
///         "name": "React App",
///         "description": "React App for WalletConnect",
///         "url": "https://example.com",
///         "icons": ["https://example.com/icon.png"]
///       }
///     },
///     "requiredNamespaces": {},
///     "optionalNamespaces": {
///       "eip155": {
///         "chains": ["eip155:1"],
///         "methods": ["personal_sign"],
///         "events": ["accountsChanged"]
///       }
///     }
///   }
/// }"#;
///
/// let request = serde_json::from_str::<JsonRpcRequest<SessionProposeParams>>(json)?;
/// assert_eq!(request.method, SignMethod::SessionPropose);
/// assert_eq!(request.params.effective_id(request.id), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest<T> {
    /// Request identifier used by the Sign API response.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Sign API method.
    pub method: SignMethod,
    /// Method-specific request payload.
    pub params: T,
}

impl<T> JsonRpcRequest<T> {
    /// Builds a Sign API JSON-RPC request envelope.
    #[must_use]
    pub fn new(id: u64, method: SignMethod, params: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            method,
            params,
        }
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionPropose`.
    #[must_use]
    pub fn is_session_propose(&self) -> bool {
        self.method == SignMethod::SessionPropose
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionSettle`.
    #[must_use]
    pub fn is_session_settle(&self) -> bool {
        self.method == SignMethod::SessionSettle
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionUpdate`.
    #[must_use]
    pub fn is_session_update(&self) -> bool {
        self.method == SignMethod::SessionUpdate
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionExtend`.
    #[must_use]
    pub fn is_session_extend(&self) -> bool {
        self.method == SignMethod::SessionExtend
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionDelete`.
    #[must_use]
    pub fn is_session_delete(&self) -> bool {
        self.method == SignMethod::SessionDelete
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionPing`.
    #[must_use]
    pub fn is_session_ping(&self) -> bool {
        self.method == SignMethod::SessionPing
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionRequest`.
    #[must_use]
    pub fn is_session_request(&self) -> bool {
        self.method == SignMethod::SessionRequest
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionEvent`.
    #[must_use]
    pub fn is_session_event(&self) -> bool {
        self.method == SignMethod::SessionEvent
    }

    /// Classifies an already-deserialized Sign request as `wc_sessionAuthenticate`.
    #[must_use]
    pub fn is_session_authenticate(&self) -> bool {
        self.method == SignMethod::SessionAuthenticate
    }
}

/// JSON-RPC success response envelope for Sign API methods.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L62-L65>
///
/// > interface EventCallback<T extends JsonRpcRequest | JsonRpcResponse> {
/// > topic: string;
/// > payload: T;
///
/// # Examples
///
/// ```
/// use wc_protocol::key::X25519PublicKey;
/// use wc_protocol::did::DidPkh;
/// use wc_protocol::session::{
///     Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature, CacaoSignatureType,
///     DappMetadata, JsonRpcResponse, SessionAuthenticateResult, SessionParticipant,
/// };
///
/// let response = JsonRpcResponse::new(
///     1,
///     SessionAuthenticateResult {
///         responder: SessionParticipant {
///             public_key: X25519PublicKey::from_hex(
///                 "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337",
///             )?,
///             metadata: DappMetadata {
///                 name: "Wallet".to_owned(),
///                 description: "Wallet".to_owned(),
///                 url: "https://example.com/wallet".to_owned(),
///                 icons: vec![],
///                 verify_url: None,
///                 redirect: None,
///             },
///         },
///         cacaos: vec![Cacao {
///             h: CacaoHeader {
///                 kind: CacaoHeaderType::Caip122,
///             },
///             p: CacaoPayload {
///                 iss: DidPkh::parse(
///                     "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87",
///                 )?,
///                 domain: "example.com".to_owned(),
///                 aud: "https://example.com/login".to_owned(),
///                 version: "1".to_owned(),
///                 nonce: "1234567890".to_owned(),
///                 iat: "2026-05-27T06:10:58.791Z".to_owned(),
///                 statement: Some(String::new()),
///                 exp: None,
///                 nbf: None,
///                 request_id: None,
///                 resources: vec![],
///             },
///             s: CacaoSignature {
///                 kind: CacaoSignatureType::Eip191,
///                 signature: "0x00".to_owned(),
///                 meta: None,
///             },
///         }],
///     },
/// );
///
/// let value = serde_json::to_value(response)?;
/// assert_eq!(value["jsonrpc"], "2.0");
/// assert_eq!(value["result"]["cacaos"][0]["h"]["t"], "caip122");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse<T> {
    /// Request identifier from the answered Sign API request.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// Method-specific success payload.
    pub result: T,
}

impl<T> JsonRpcResponse<T> {
    /// Builds a Sign API JSON-RPC success response envelope.
    #[must_use]
    pub fn new(id: u64, result: T) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            result,
        }
    }
}

/// Success payload for Sign RPC methods whose response result is JSON `true`.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionupdate>
///
/// > // Success result
/// > true
///
/// The maintained Sign Client sends the value through the shared JSON-RPC
/// result formatter.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1789-L1792>
///
/// > const payload = formatJsonRpcResult(id, result);
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2322-L2326>
///
/// > await this.sendResult<"wc_sessionUpdate">({
/// > id,
/// > topic,
/// > result: true,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{
///     SessionAck, SessionAckResponse, session_ack_response,
/// };
///
/// let response = session_ack_response(1);
/// let value = serde_json::to_value(response)?;
/// assert_eq!(value["jsonrpc"], "2.0");
/// assert_eq!(value["result"], true);
///
/// let parsed = serde_json::from_value::<SessionAckResponse>(value)?;
/// assert_eq!(parsed.result, SessionAck);
/// assert!(
///     serde_json::from_str::<SessionAckResponse>(
///         r#"{"id":1,"jsonrpc":"2.0","result":false}"#
///     )
///     .is_err()
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SessionAck;

impl Serialize for SessionAck {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for SessionAck {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = bool::deserialize(deserializer)?;
        if value {
            Ok(Self)
        } else {
            Err(de::Error::custom("expected true acknowledgment"))
        }
    }
}

/// JSON-RPC success response for Sign RPC acknowledgements.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L28-L34>
///
/// > id,
/// > jsonrpc: "2.0",
/// > result,
pub type SessionAckResponse = JsonRpcResponse<SessionAck>;

/// `wc_sessionSettle` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionsettle>
///
/// > // Success result
/// > true
pub type SessionSettleResponse = SessionAckResponse;

/// `wc_sessionUpdate` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionupdate>
///
/// > // Success result
/// > true
pub type SessionUpdateResponse = SessionAckResponse;

/// `wc_sessionExtend` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionextend>
///
/// > // Success result
/// > true
pub type SessionExtendResponse = SessionAckResponse;

/// `wc_sessionPing` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionping>
///
/// > // Success result
/// > true
pub type SessionPingResponse = SessionAckResponse;

/// `wc_sessionEvent` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessionevent>
///
/// > // Success result
/// > true
pub type SessionEventResponse = SessionAckResponse;

/// `wc_sessionDelete` success response.
///
/// <https://github.com/WalletConnect/walletconnect-specs/blob/ecbbf6e114687812fd0366fb59dff8c0a8e3c9ec/docs/specs/clients/sign/rpc-methods.md#wc_sessiondelete>
///
/// > // Success result
/// > true
pub type SessionDeleteResponse = SessionAckResponse;

/// Builds a Sign RPC acknowledgement response.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L28-L34>
///
/// > export function formatJsonRpcResult<T = any>(id: number, result: T):
/// > JsonRpcResult<T> {
/// > result,
#[must_use]
pub fn session_ack_response(id: u64) -> SessionAckResponse {
    JsonRpcResponse::new(id, SessionAck)
}

/// JSON-RPC error response envelope for Sign API methods.
///
/// <https://www.jsonrpc.org/specification#response_object>
///
/// > This member is REQUIRED on error.
/// > This member MUST NOT exist if there was no error triggered during invocation.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/jsonrpc/types/src/jsonrpc.ts#L23-L33>
///
/// > export interface JsonRpcError {
/// > id: number;
/// > jsonrpc: string;
/// > error: ErrorResponse;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L1852-L1855>
///
/// > const payload = formatJsonRpcError(id, error);
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{
///     JsonRpcError, JsonRpcErrorCode, JsonRpcErrorResponse,
/// };
///
/// let response = JsonRpcErrorResponse::new(
///     1,
///     JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
/// );
///
/// let value = serde_json::to_value(response)?;
/// assert_eq!(value["jsonrpc"], "2.0");
/// assert_eq!(value["error"]["code"], 5000);
/// assert_eq!(value["error"]["message"], "User rejected.");
/// assert!(value.get("result").is_none());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcErrorResponse {
    /// Request identifier from the failed Sign API request.
    pub id: u64,
    /// JSON-RPC protocol version.
    pub jsonrpc: String,
    /// JSON-RPC error object.
    pub error: JsonRpcError,
}

impl JsonRpcErrorResponse {
    /// Builds a Sign API JSON-RPC error response envelope.
    #[must_use]
    pub fn new(id: u64, error: JsonRpcError) -> Self {
        Self {
            id,
            jsonrpc: JSON_RPC_VERSION.to_owned(),
            error,
        }
    }
}

/// JSON-RPC error object.
///
/// <https://www.jsonrpc.org/specification#error_object>
///
/// > code
/// > A Number that indicates the error type that occurred.
/// > This MUST be an integer.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/48a79efd8c6929fc3421bcb327ae906a197a9837/jsonrpc/types/src/jsonrpc.ts#L29-L33>
///
/// > export interface ErrorResponse {
/// > code: number;
/// > message: string;
/// > data?: string;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Numeric JSON-RPC or `WalletConnect` SDK error code.
    pub code: JsonRpcErrorCode,
    /// Concise error message.
    pub message: String,
    /// Optional error data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Builds a JSON-RPC error object without `data`.
    #[must_use]
    pub fn new(code: JsonRpcErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Builds a JSON-RPC error object with `data`.
    #[must_use]
    pub fn with_data(code: JsonRpcErrorCode, message: impl Into<String>, data: Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

/// Numeric JSON-RPC and `WalletConnect` SDK error code.
///
/// <https://www.jsonrpc.org/specification#error_object>
///
/// > The error codes from and including -32768 to -32000 are reserved for
/// > pre-defined errors.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/utils/src/errors.ts#L10-L100>
///
/// > export const SDK_ERRORS = {
/// > /* ----- INVALID (1xxx) ----- */
/// > INVALID_METHOD: {
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonRpcErrorCode {
    /// JSON-RPC parse error, `-32700`.
    ParseError,
    /// JSON-RPC invalid request, `-32600`.
    InvalidRequest,
    /// JSON-RPC method not found, `-32601`.
    MethodNotFound,
    /// JSON-RPC invalid params, `-32602`.
    InvalidParams,
    /// JSON-RPC internal error, `-32603`.
    InternalError,
    /// `WalletConnect` invalid method, `1001`.
    InvalidMethod,
    /// `WalletConnect` invalid event, `1002`.
    InvalidEvent,
    /// `WalletConnect` invalid update request, `1003`.
    InvalidUpdateRequest,
    /// `WalletConnect` invalid extend request, `1004`.
    InvalidExtendRequest,
    /// `WalletConnect` invalid session settle request, `1005`.
    InvalidSessionSettleRequest,
    /// `WalletConnect` unauthorized method, `3001`.
    UnauthorizedMethod,
    /// `WalletConnect` unauthorized event, `3002`.
    UnauthorizedEvent,
    /// `WalletConnect` unauthorized update request, `3003`.
    UnauthorizedUpdateRequest,
    /// `WalletConnect` unauthorized extend request, `3004`.
    UnauthorizedExtendRequest,
    /// `WalletConnect` user rejection, `5000`.
    UserRejected,
    /// `WalletConnect` user rejected chains, `5001`.
    UserRejectedChains,
    /// `WalletConnect` user rejected methods, `5002`.
    UserRejectedMethods,
    /// `WalletConnect` user rejected events, `5003`.
    UserRejectedEvents,
    /// `WalletConnect` unsupported chains, `5100`.
    UnsupportedChains,
    /// `WalletConnect` unsupported methods, `5101`.
    UnsupportedMethods,
    /// `WalletConnect` unsupported events, `5102`.
    UnsupportedEvents,
    /// `WalletConnect` unsupported accounts, `5103`.
    UnsupportedAccounts,
    /// `WalletConnect` unsupported namespace key, `5104`.
    UnsupportedNamespaceKey,
    /// `WalletConnect` user disconnected, `6000`.
    UserDisconnected,
    /// `WalletConnect` session settlement failed, `7000`.
    SessionSettlementFailed,
    /// `WalletConnect` unsupported `wc_` method, `10001`.
    WcMethodUnsupported,
    /// Unrecognized error code preserved for compatibility.
    Other(i64),
}

impl JsonRpcErrorCode {
    /// Converts a numeric wire code into a known variant or `Other`.
    #[must_use]
    pub const fn from_i64(value: i64) -> Self {
        match value {
            -32700 => Self::ParseError,
            -32600 => Self::InvalidRequest,
            -32601 => Self::MethodNotFound,
            -32602 => Self::InvalidParams,
            -32603 => Self::InternalError,
            1001 => Self::InvalidMethod,
            1002 => Self::InvalidEvent,
            1003 => Self::InvalidUpdateRequest,
            1004 => Self::InvalidExtendRequest,
            1005 => Self::InvalidSessionSettleRequest,
            3001 => Self::UnauthorizedMethod,
            3002 => Self::UnauthorizedEvent,
            3003 => Self::UnauthorizedUpdateRequest,
            3004 => Self::UnauthorizedExtendRequest,
            5000 => Self::UserRejected,
            5001 => Self::UserRejectedChains,
            5002 => Self::UserRejectedMethods,
            5003 => Self::UserRejectedEvents,
            5100 => Self::UnsupportedChains,
            5101 => Self::UnsupportedMethods,
            5102 => Self::UnsupportedEvents,
            5103 => Self::UnsupportedAccounts,
            5104 => Self::UnsupportedNamespaceKey,
            6000 => Self::UserDisconnected,
            7000 => Self::SessionSettlementFailed,
            10001 => Self::WcMethodUnsupported,
            _ => Self::Other(value),
        }
    }

    /// Numeric wire value.
    #[must_use]
    pub const fn as_i64(self) -> i64 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::InvalidMethod => 1001,
            Self::InvalidEvent => 1002,
            Self::InvalidUpdateRequest => 1003,
            Self::InvalidExtendRequest => 1004,
            Self::InvalidSessionSettleRequest => 1005,
            Self::UnauthorizedMethod => 3001,
            Self::UnauthorizedEvent => 3002,
            Self::UnauthorizedUpdateRequest => 3003,
            Self::UnauthorizedExtendRequest => 3004,
            Self::UserRejected => 5000,
            Self::UserRejectedChains => 5001,
            Self::UserRejectedMethods => 5002,
            Self::UserRejectedEvents => 5003,
            Self::UnsupportedChains => 5100,
            Self::UnsupportedMethods => 5101,
            Self::UnsupportedEvents => 5102,
            Self::UnsupportedAccounts => 5103,
            Self::UnsupportedNamespaceKey => 5104,
            Self::UserDisconnected => 6000,
            Self::SessionSettlementFailed => 7000,
            Self::WcMethodUnsupported => 10001,
            Self::Other(value) => value,
        }
    }
}

impl Serialize for JsonRpcErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_i64(self.as_i64())
    }
}

impl<'de> Deserialize<'de> for JsonRpcErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i64::deserialize(deserializer)?;
        Ok(Self::from_i64(value))
    }
}
