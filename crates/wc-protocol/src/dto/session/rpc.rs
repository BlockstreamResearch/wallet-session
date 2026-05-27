//! Sign API JSON-RPC envelopes.

use serde::{Deserialize, Serialize};

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
/// use wc_protocol::session::{
///     Cacao, CacaoHeader, CacaoHeaderType, CacaoPayload, CacaoSignature, CacaoSignatureType,
///     DappMetadata, JsonRpcResponse, SessionAuthenticateResult, SessionParticipant,
/// };
///
/// let response = JsonRpcResponse::new(
///     1,
///     SessionAuthenticateResult {
///         responder: SessionParticipant {
///             public_key: "wallet-public-key".to_owned(),
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
///                 iss: "did:pkh:eip155:1:0xA6872b85a289A6D2c8AD72bb246F6c5CcE37Fc87".to_owned(),
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
