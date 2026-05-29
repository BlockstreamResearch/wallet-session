//! Session proposal DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    AuthPayload, Cacao, CacaoSignatureType, SessionEventName, SessionMethod,
    rpc::{JsonRpcError, JsonRpcErrorResponse},
};
use crate::{
    caip::{Caip2ChainId, NamespaceKey},
    key::X25519PublicKey,
    relay::RelayTopic,
};

/// Decrypted `wc_sessionPropose` params.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L21-L45>
///
/// > export interface Struct {
/// > id: number;
/// > expiryTimestamp: number;
/// > relays: RelayerTypes.ProtocolOptions[];
/// > proposer: {
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L2116-L2125>
///
/// > const proposal: ProposalTypes.Struct = {
/// > id,
/// > pairingTopic: topic,
/// > expiryTimestamp,
/// > ...params,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProposeParams {
    /// Proposal ID as duplicated inside params by deployed clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Pairing topic as duplicated inside params by deployed clients.
    #[serde(
        rename = "pairingTopic",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pairing_topic: Option<RelayTopic>,
    /// Deprecated proposal expiry field still present in older event examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<u64>,
    /// Proposal expiry timestamp in unix seconds.
    #[serde(
        rename = "expiryTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expiry_timestamp: Option<u64>,
    /// Relay protocols the dapp can use for the proposed session.
    pub relays: Vec<RelayProtocolOptions>,
    /// Dapp public key and metadata.
    pub proposer: Proposer,
    /// Proposal namespaces the wallet must satisfy.
    #[serde(rename = "requiredNamespaces", default)]
    pub required_namespaces: ProposalNamespaces,
    /// Proposal namespaces the wallet may satisfy.
    #[serde(rename = "optionalNamespaces", default)]
    pub optional_namespaces: ProposalNamespaces,
    /// Optional string session properties requested by the dapp.
    #[serde(
        rename = "sessionProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_properties: Option<BTreeMap<String, String>>,
    /// Optional namespace-scoped properties requested by the dapp.
    #[serde(
        rename = "scopedProperties",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub scoped_properties: Option<BTreeMap<String, Value>>,
    /// Verify attestation attached by the transport, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    /// Verify encrypted ID attached by the transport, when present.
    #[serde(
        rename = "encryptedId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub encrypted_id: Option<String>,
    /// Experimental proposal subrequests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests: Option<ProposalRequests>,
}

impl SessionProposeParams {
    /// Returns the params ID when present, otherwise the JSON-RPC envelope ID.
    #[must_use]
    pub fn effective_id(&self, request_id: u64) -> u64 {
        self.id.unwrap_or(request_id)
    }

    /// Returns `expiryTimestamp`, falling back to the deprecated `expiry`.
    #[must_use]
    pub const fn effective_expiry_timestamp(&self) -> Option<u64> {
        match self.expiry_timestamp {
            Some(expiry_timestamp) => Some(expiry_timestamp),
            None => self.expiry,
        }
    }

    /// Compares the proposal expiry to a caller-provided unix timestamp.
    #[must_use]
    pub fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        self.effective_expiry_timestamp()
            .is_some_and(|expiry| expiry <= now_unix_seconds)
    }
}

/// Success result for an approved `wc_sessionPropose`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/jsonrpc.ts#L84-L91>
///
/// > wc_sessionPropose: {
/// > relay: RelayerTypes.ProtocolOptions;
/// > responderPublicKey: string;
/// > };
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L528-L537>
///
/// > pairingProposalResponse: {
/// > relay: {
/// > protocol: relayProtocol ?? "irn",
/// > },
/// > responderPublicKey: selfPublicKey,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{JsonRpcResponse, SessionProposeResult};
///
/// let json = r#"{
///   "id": 1779866466221833,
///   "jsonrpc": "2.0",
///   "result": {
///     "relay": {"protocol": "irn"},
///     "responderPublicKey": "0ceffdac17e7dfed1a2a452b699f8e8fe98180c30fb5651c34ac828d61eb5337"
///   }
/// }"#;
///
/// let response = serde_json::from_str::<JsonRpcResponse<SessionProposeResult>>(json)?;
/// assert_eq!(response.result.relay.protocol, "irn");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionProposeResult {
    /// Relay protocol selected by the wallet for the session.
    pub relay: RelayProtocolOptions,
    /// Wallet public key used by the dapp to derive the session topic.
    #[serde(rename = "responderPublicKey")]
    pub responder_public_key: X25519PublicKey,
}

/// JSON-RPC error response for a rejected `wc_sessionPropose`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/engine.ts#L123-L126>
///
/// > interface RejectParams {
/// > id: number;
/// > reason: ErrorResponse;
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L593-L599>
///
/// > await this.sendError({
/// > id,
/// > topic: pairingTopic,
/// > error: reason,
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{
///     JsonRpcError, JsonRpcErrorCode, SessionProposeErrorResponse,
///     session_propose_error_response,
/// };
///
/// let response = session_propose_error_response(
///     1,
///     JsonRpcError::new(JsonRpcErrorCode::UserRejected, "User rejected."),
/// );
/// let value = serde_json::to_value(response)?;
/// assert_eq!(value["jsonrpc"], "2.0");
/// assert_eq!(value["error"]["code"], 5000);
///
/// let parsed = serde_json::from_value::<SessionProposeErrorResponse>(value)?;
/// assert_eq!(parsed.error.code, JsonRpcErrorCode::UserRejected);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub type SessionProposeErrorResponse = JsonRpcErrorResponse;

/// Builds a `wc_sessionPropose` error response.
///
/// <https://github.com/WalletConnect/walletconnect-utils/blob/705f0a894606ca3fb0a750a38dff7bfacf3592b4/jsonrpc/utils/src/format.ts#L36-L45>
///
/// > export function formatJsonRpcError(
/// > error: formatErrorMessage(error, data),
#[must_use]
pub fn session_propose_error_response(id: u64, error: JsonRpcError) -> SessionProposeErrorResponse {
    JsonRpcErrorResponse::new(id, error)
}

/// Proposal namespace map keyed by namespace or CAIP-2 chain ID.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#proposal-namespace>
///
/// > There will be two objects that will be included, `requiredNamespaces` and
/// > `optionalNamespaces`.
pub type ProposalNamespaces = BTreeMap<NamespaceKey, ProposalNamespace>;

/// Methods, events, and optional chains requested for one proposal namespace.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L8-L17>
///
/// > interface BaseRequiredNamespace {
/// > chains?: string[];
/// > methods: string[];
/// > events: string[];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalNamespace {
    /// CAIP-2 chains requested under this namespace key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains: Option<Vec<Caip2ChainId>>,
    /// JSON-RPC methods requested under this namespace key.
    pub methods: Vec<SessionMethod>,
    /// Session events requested under this namespace key.
    pub events: Vec<SessionEventName>,
}

/// Relay protocol option used by the proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/relayer.ts#L10-L14>
///
/// > export interface ProtocolOptions {
/// > protocol: string;
/// > data?: string;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayProtocolOptions {
    /// Relay protocol identifier, usually `irn`.
    pub protocol: String,
    /// Protocol-specific relay data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Dapp key and metadata sent in a session proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L29-L32>
///
/// > proposer: {
/// > publicKey: string;
/// > metadata: SignClientTypes.Metadata;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposer {
    /// Dapp public key used later for session key agreement.
    #[serde(rename = "publicKey")]
    pub public_key: X25519PublicKey,
    /// Dapp metadata suitable for wallet UI.
    pub metadata: DappMetadata,
}

/// Dapp metadata displayed when the wallet asks the user to approve a proposal.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/core.ts#L29-L40>
///
/// > interface Metadata {
/// > name: string;
/// > description: string;
/// > url: string;
/// > icons: string[];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappMetadata {
    /// Dapp display name.
    pub name: String,
    /// Dapp description.
    pub description: String,
    /// Dapp origin URL.
    pub url: String,
    /// Dapp icon URLs.
    pub icons: Vec<String>,
    /// Verify URL advertised by the dapp.
    #[serde(rename = "verifyUrl", default, skip_serializing_if = "Option::is_none")]
    pub verify_url: Option<String>,
    /// Redirect targets advertised by the dapp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<DappRedirect>,
}

/// Optional native or universal redirect targets.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/core/core.ts#L35-L39>
///
/// > redirect?: {
/// > native?: string;
/// > universal?: string;
/// > linkMode?: boolean;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DappRedirect {
    /// Native app redirect URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<String>,
    /// Universal link redirect URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub universal: Option<String>,
    /// Link-mode support flag.
    #[serde(rename = "linkMode", default, skip_serializing_if = "Option::is_none")]
    pub link_mode: Option<bool>,
}

/// Experimental proposal subrequests carried by current TypeScript clients.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L41-L44>
///
/// > requests?: {
/// > authentication?: AuthTypes.AuthenticateParams[];
/// > walletPay?: EngineTypes.WalletPayParams;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRequests {
    /// Authentication subrequests requested before session approval.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/proposal.ts#L41-L44>
    ///
    /// > requests?: {
    /// > authentication?: AuthTypes.AuthenticateParams[];
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<ProposalAuthRequest>>,
    /// `WalletPay` subrequest is preserved as JSON until modeled.
    #[serde(rename = "walletPay", default, skip_serializing_if = "Option::is_none")]
    pub wallet_pay: Option<Value>,
}

/// Authentication subrequest embedded in `wc_sessionPropose`.
///
/// The maintained Sign Client maps public `connect({ authentication })` input
/// into this flat protocol object.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L302-L333>
///
/// > requests: {
/// > authentication: authentication?.map((auth) => {
/// > const protocolParams: AuthTypes.AuthenticateParams = {
/// > domain,
/// > chains,
/// > nonce,
///
/// The extra `signatureTypes` field is part of the auth subrequest type, but
/// not part of `authPayload` sent by `wc_sessionAuthenticate`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L176-L191>
///
/// > interface AuthenticateParams {
/// > domain: string;
/// > chains: string[];
/// > signatureTypes?: Record<string, string[]>;
///
/// # Examples
///
/// ```
/// use wc_protocol::session::{CacaoSignatureType, ProposalAuthRequest};
///
/// let json = r#"{
///   "type": "caip122",
///   "chains": ["eip155:1"],
///   "aud": "https://example.com/login",
///   "domain": "example.com",
///   "version": "1",
///   "nonce": "proposal-auth-nonce-001",
///   "iat": "2026-05-29T11:43:58.877Z",
///   "statement": "Sign in to Example",
///   "resources": ["https://example.com/resource/1"],
///   "signatureTypes": {"eip155:1": ["eip191"]}
/// }"#;
///
/// let request = serde_json::from_str::<ProposalAuthRequest>(json)?;
/// assert_eq!(request.auth_payload.domain, "example.com");
/// let chain = "eip155:1".parse()?;
/// assert_eq!(
///     request.signature_types_for_chain(&chain),
///     Some([CacaoSignatureType::Eip191].as_slice()),
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalAuthRequest {
    /// CAIP-122/CACAO payload that the wallet may sign before approval.
    #[serde(flatten)]
    pub auth_payload: AuthPayload,
    /// Signature types accepted by the dapp, keyed by CAIP-2 chain ID.
    #[serde(
        rename = "signatureTypes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_types: Option<ProposalAuthSignatureTypes>,
}

impl ProposalAuthRequest {
    /// Returns requested signature types for one CAIP-2 chain.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/auth.ts#L188-L190>
    ///
    /// > resources?: string[];
    /// > signatureTypes?: Record<string, string[]>;
    #[must_use]
    pub fn signature_types_for_chain(&self, chain: &Caip2ChainId) -> Option<&[CacaoSignatureType]> {
        self.signature_types
            .as_ref()
            .and_then(|signature_types| signature_types.get(chain).map(Vec::as_slice))
    }
}

/// Proposal authentication signature-type preferences keyed by CAIP-2 chain ID.
pub type ProposalAuthSignatureTypes = BTreeMap<Caip2ChainId, Vec<CacaoSignatureType>>;

/// Responses to proposal subrequests included in `wc_sessionSettle`.
///
/// Current TypeScript clients pass this object through approval into
/// `wc_sessionSettle`, then copy its values into stored session fields.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/types/src/sign-client/engine.ts#L108-L121>
///
/// > type ProposalRequestsResponses = {
/// > authentication?: AuthTypes.Cacao[];
/// > walletPay?: WalletPayResult[];
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L482-L491>
///
/// > const sessionSettle = {
/// > relay: { protocol: relayProtocol ?? "irn" },
/// > namespaces,
/// > proposalRequestsResponses,
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRequestsResponses {
    /// CACAO responses signed for proposal authentication subrequests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Cacao>>,
    /// `WalletPay` results are preserved as JSON until modeled.
    #[serde(rename = "walletPay", default, skip_serializing_if = "Option::is_none")]
    pub wallet_pay: Option<Vec<Value>>,
}
