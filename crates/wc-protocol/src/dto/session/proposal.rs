//! Session proposal DTOs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::relay::RelayTopic;

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

/// Proposal namespace map keyed by namespace or CAIP-2 chain ID.
///
/// <https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces#proposal-namespace>
///
/// > There will be two objects that will be included, `requiredNamespaces` and
/// > `optionalNamespaces`.
pub type ProposalNamespaces = BTreeMap<String, ProposalNamespace>;

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
    pub chains: Option<Vec<String>>,
    /// JSON-RPC methods requested under this namespace key.
    pub methods: Vec<String>,
    /// Session events requested under this namespace key.
    pub events: Vec<String>,
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
    pub public_key: String,
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
    /// Authentication subrequests are preserved as JSON until modeled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<Value>>,
    /// `WalletPay` subrequest is preserved as JSON until modeled.
    #[serde(rename = "walletPay", default, skip_serializing_if = "Option::is_none")]
    pub wallet_pay: Option<Value>,
}
