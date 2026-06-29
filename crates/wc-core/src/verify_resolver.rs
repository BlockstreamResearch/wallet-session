//! Verify API resolver.

use std::{sync::Arc, time::Duration};

use rustls::SignatureScheme;
use serde::Deserialize;
use ureq::tls::{TlsConfig, TlsProvider};
use wc_protocol::{
    session::DappMetadata,
    verify::{
        ALTERNATE_VERIFY_URL, DEFAULT_VERIFY_URL, DEFAULT_VERIFY_V3_URL, VerifyAttestationHash,
        VerifyContext, VerifyJwtAttestationError, VerifyJwtAttestationJws,
        VerifyJwtPublicKeyResponse, VerifyP256PublicKeyError, VerifyValidation,
    },
};

/// Default timeout for one Verify API request.
pub const DEFAULT_VERIFY_RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_VERIFY_ATTESTATION_BYTES: u64 = 64 * 1024;
const MAX_VERIFY_PUBLIC_KEY_BYTES: u64 = 16 * 1024;

/// Native Verify API resolver.
///
/// The maintained SDK resolves hash-based attestations with an HTTPS GET to
/// `/attestation/{hash}?v2Supported=true`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L144-L152>
///
/// > const result = await fetch(`${url}/attestation/${attestationId}?v2Supported=true`, {
/// > return result.status === 200 ? await result.json() : undefined;
///
/// Only the maintained trusted Verify origins are accepted. A dapp-provided
/// `verifyUrl` outside the trusted list falls back to the default server.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L160-L168>
///
/// > if (!TRUSTED_VERIFY_URLS.includes(url)) {
/// > url = VERIFY_SERVER;
#[derive(Debug, Clone)]
pub struct VerifyResolver {
    http: ureq::Agent,
    trusted_urls: Vec<String>,
    verify_v3_url: String,
}

impl VerifyResolver {
    /// Builds a resolver with the default request timeout.
    pub fn new() -> Result<Self, VerifyResolverError> {
        Self::with_timeout(DEFAULT_VERIFY_RESOLVER_TIMEOUT)
    }

    /// Builds a resolver with a caller-provided request timeout.
    pub fn with_timeout(timeout: Duration) -> Result<Self, VerifyResolverError> {
        let tls_config = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        let http = ureq::Agent::config_builder()
            .tls_config(tls_config)
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .user_agent("walletconnect-client-poc")
            .build()
            .new_agent();
        Ok(Self {
            http,
            trusted_urls: vec![
                DEFAULT_VERIFY_URL.to_owned(),
                ALTERNATE_VERIFY_URL.to_owned(),
            ],
            verify_v3_url: DEFAULT_VERIFY_V3_URL.to_owned(),
        })
    }

    #[cfg(test)]
    fn with_timeout_and_trusted_urls(
        timeout: Duration,
        trusted_urls: Vec<String>,
    ) -> Result<Self, VerifyResolverError> {
        let mut resolver = Self::with_timeout(timeout)?;
        resolver.trusted_urls = trusted_urls;
        Ok(resolver)
    }

    #[cfg(test)]
    fn with_timeout_and_trusted_urls_and_verify_v3_url(
        timeout: Duration,
        trusted_urls: Vec<String>,
        verify_v3_url: String,
    ) -> Result<Self, VerifyResolverError> {
        let mut resolver = Self::with_timeout_and_trusted_urls(timeout, trusted_urls)?;
        resolver.verify_v3_url = verify_v3_url;
        Ok(resolver)
    }

    /// Resolves a Verify context from an attestation hash and peer metadata.
    ///
    /// If no attestation exists for the hash, the unresolved `UNKNOWN` context
    /// from metadata is returned. Network and JSON errors are surfaced with
    /// sources so callers can decide whether to retry or keep the unresolved
    /// context.
    pub async fn resolve_hash_for_metadata(
        &self,
        hash: &VerifyAttestationHash,
        metadata: &DappMetadata,
    ) -> Result<VerifyContext, VerifyResolverError> {
        let unresolved = VerifyContext::unresolved_from_metadata(metadata);
        self.resolve_hash_for_context(hash, &unresolved).await
    }

    /// Resolves a Verify context from an attestation hash and unresolved context.
    ///
    /// This is useful for review objects that already carry metadata-derived
    /// Verify context. The unresolved context's `origin` is treated as the
    /// metadata URL for the origin comparison, matching the SDK's
    /// `new URL(metadata.url).origin` check.
    pub async fn resolve_hash_for_context(
        &self,
        hash: &VerifyAttestationHash,
        context: &VerifyContext,
    ) -> Result<VerifyContext, VerifyResolverError> {
        let verify_url = self.trusted_verify_url(Some(&context.verified.verify_url));
        let mut unresolved = context.clone();
        unresolved.verified.verify_url.clone_from(&verify_url);
        let Some(attestation) = self.resolve_attestation_hash(hash, &verify_url).await? else {
            return Ok(unresolved);
        };

        Ok(context_from_attestation(
            unresolved,
            &attestation,
            &context.verified.origin,
        ))
    }

    /// Resolves a Verify context from a relay-carried Verify v3 JWT.
    ///
    /// Use this for events that include both `attestation` and `encryptedId`
    /// beside the encrypted relay payload. The JWT is verified with the Verify
    /// v3 public key before it can change the context.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L117-L137>
    ///
    /// > const { attestationId, hash, encryptedId } = params;
    /// > if (decoded.payload.id !== encryptedId) return;
    /// > const validation = await this.isValidJwtAttestation(attestationId);
    pub async fn resolve_jwt_for_context(
        &self,
        attestation_jwt: &str,
        encrypted_id: &str,
        context: &VerifyContext,
        now_unix_seconds: u64,
    ) -> Result<VerifyContext, VerifyResolverError> {
        let Some(attestation) = self
            .resolve_jwt_attestation(attestation_jwt, encrypted_id, now_unix_seconds)
            .await?
        else {
            return Ok(context.clone());
        };

        Ok(context_from_attestation(
            context.clone(),
            &attestation,
            &context.verified.origin,
        ))
    }

    /// Resolves Verify context from a relay-carried JWT, falling back to the
    /// exact payload hash when the signed JWT is not usable for this message.
    pub async fn resolve_jwt_or_hash_for_context(
        &self,
        attestation_jwt: &str,
        encrypted_id: &str,
        hash: &VerifyAttestationHash,
        context: &VerifyContext,
        now_unix_seconds: u64,
    ) -> Result<VerifyContext, VerifyResolverError> {
        let Some(attestation) = self
            .resolve_jwt_attestation(attestation_jwt, encrypted_id, now_unix_seconds)
            .await?
        else {
            return self.resolve_hash_for_context(hash, context).await;
        };

        Ok(context_from_attestation(
            context.clone(),
            &attestation,
            &context.verified.origin,
        ))
    }

    /// Fetches a hash-based attestation from a trusted Verify endpoint.
    ///
    /// HTTP 404 and other non-200 responses mean the server has no usable
    /// attestation for that hash, matching the SDK's `undefined` branch.
    pub async fn resolve_attestation_hash(
        &self,
        hash: &VerifyAttestationHash,
        verify_url: &str,
    ) -> Result<Option<VerifyAttestation>, VerifyResolverError> {
        let verify_url = self.trusted_verify_url(Some(verify_url));
        let url = format!("{verify_url}/attestation/{hash}?v2Supported=true");
        let http = self.http.clone();

        tokio::task::spawn_blocking(move || fetch_attestation_hash(&http, &url))
            .await
            .map_err(|source| VerifyResolverError::Task { source })?
    }

    /// Resolves a Verify v3 JWT attestation.
    ///
    /// The maintained SDK validates `attestationId` with the Verify v3 public
    /// key and then accepts only verified attestations whose payload `id`
    /// matches the relay-provided `encryptedId`.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L117-L137>
    ///
    /// > const { attestationId, hash, encryptedId } = params;
    /// > if (decoded.payload.id !== encryptedId) return;
    /// > const validation = await this.isValidJwtAttestation(attestationId);
    ///
    /// This implementation verifies the JWT before comparing `id`; the decoded
    /// payload is not trusted until the signature and expiry checks pass.
    pub async fn resolve_jwt_attestation(
        &self,
        attestation_jwt: &str,
        encrypted_id: &str,
        now_unix_seconds: u64,
    ) -> Result<Option<VerifyAttestation>, VerifyResolverError> {
        if attestation_jwt.is_empty() {
            return Ok(None);
        }

        let jws = VerifyJwtAttestationJws::decode(attestation_jwt)
            .map_err(|source| VerifyResolverError::VerifyJwtDecode { source })?;
        let public_key = self.fetch_verify_public_key().await?.public_key;
        let public_key = public_key
            .sec1_bytes()
            .map_err(|source| VerifyResolverError::VerifyPublicKey { source })?;
        verify_p256_jws_signature(&public_key, jws.signing_input(), jws.signature())?;
        let payload = jws.into_payload();
        if payload.is_expired_at(now_unix_seconds) {
            return Err(VerifyResolverError::VerifyJwtExpired {
                exp: payload.exp,
                now_unix_seconds,
            });
        }
        if payload.id != encrypted_id || !payload.is_verified {
            return Ok(None);
        }

        Ok(Some(VerifyAttestation {
            origin: payload.origin,
            is_scam: Some(payload.is_scam),
        }))
    }

    /// Fetches the Verify v3 P-256 public key used for JWT attestations.
    ///
    /// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L171-L178>
    ///
    /// > const url = `${VERIFY_SERVER_V3}/public-key`;
    /// > const response = await fetch(url);
    pub async fn fetch_verify_public_key(
        &self,
    ) -> Result<VerifyJwtPublicKeyResponse, VerifyResolverError> {
        let url = format!("{}/public-key", self.verify_v3_url.trim_end_matches('/'));
        let http = self.http.clone();

        tokio::task::spawn_blocking(move || fetch_verify_public_key_response(&http, &url))
            .await
            .map_err(|source| VerifyResolverError::Task { source })?
    }

    fn trusted_verify_url(&self, verify_url: Option<&str>) -> String {
        let Some(verify_url) = verify_url else {
            return DEFAULT_VERIFY_URL.to_owned();
        };
        if self
            .trusted_urls
            .iter()
            .any(|trusted| trusted == verify_url)
        {
            return verify_url.to_owned();
        }

        DEFAULT_VERIFY_URL.to_owned()
    }
}

/// Hash-based Verify attestation response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct VerifyAttestation {
    /// Origin resolved by the Verify server.
    pub origin: String,
    /// Threat signal returned by the Verify server.
    #[serde(rename = "isScam", default)]
    pub is_scam: Option<bool>,
}

/// Returns a trusted Verify endpoint, falling back to the maintained default.
#[must_use]
pub fn trusted_verify_url(verify_url: Option<&str>) -> &'static str {
    if matches!(verify_url, Some(ALTERNATE_VERIFY_URL)) {
        ALTERNATE_VERIFY_URL
    } else {
        DEFAULT_VERIFY_URL
    }
}

fn context_from_attestation(
    mut context: VerifyContext,
    attestation: &VerifyAttestation,
    metadata_url: &str,
) -> VerifyContext {
    context.verified.origin.clone_from(&attestation.origin);
    context.verified.is_scam = attestation.is_scam;
    context.verified.validation = match metadata_origin(metadata_url) {
        Some(origin) if origin == attestation.origin => VerifyValidation::Valid,
        Some(_) => VerifyValidation::Invalid,
        None => VerifyValidation::Unknown,
    };
    context
}

/// Extracts `scheme://authority` for the SDK's metadata-origin comparison.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/sign-client/src/controllers/engine.ts#L3310-L3314>
///
/// > context.verified.validation =
/// >   result.origin === new URL(metadata.url).origin ? "VALID" : "INVALID";
fn metadata_origin(metadata_url: &str) -> Option<String> {
    let without_fragment = metadata_url
        .split_once('#')
        .map_or(metadata_url, |(url, _fragment)| url);
    let uri: ureq::http::Uri = without_fragment.parse().ok()?;
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = uri.authority()?;
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = match (scheme.as_str(), authority.port_u16()) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(port)) => format!(":{port}"),
    };

    Some(format!("{scheme}://{host}{port}"))
}

/// Performs the SDK's hash-attestation GET and keeps non-200 as `None`.
///
/// <https://github.com/WalletConnect/walletconnect-monorepo/blob/a451d9fb3982b3ad0f1ad09d0bcfb3565cf99ab7/packages/core/src/controllers/verify.ts#L144-L152>
///
/// > const result = await fetch(`${url}/attestation/${attestationId}?v2Supported=true`, {
/// > return result.status === 200 ? await result.json() : undefined;
fn fetch_attestation_hash(
    http: &ureq::Agent,
    url: &str,
) -> Result<Option<VerifyAttestation>, VerifyResolverError> {
    let mut response = http
        .get(url)
        .call()
        .map_err(|source| VerifyResolverError::Http { source })?;
    if response.status().as_u16() != 200 {
        return Ok(None);
    }

    let attestation = serde_json::from_reader(
        response
            .body_mut()
            .with_config()
            .limit(MAX_VERIFY_ATTESTATION_BYTES)
            .reader(),
    )
    .map_err(|source| VerifyResolverError::Json { source })?;

    Ok(Some(attestation))
}

/// Fetches and decodes the Verify v3 public key.
fn fetch_verify_public_key_response(
    http: &ureq::Agent,
    url: &str,
) -> Result<VerifyJwtPublicKeyResponse, VerifyResolverError> {
    let mut response = http
        .get(url)
        .call()
        .map_err(|source| VerifyResolverError::Http { source })?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(VerifyResolverError::PublicKeyStatus { status });
    }

    serde_json::from_reader(
        response
            .body_mut()
            .with_config()
            .limit(MAX_VERIFY_PUBLIC_KEY_BYTES)
            .reader(),
    )
    .map_err(|source| VerifyResolverError::Json { source })
}

/// Verifies the ES256 JWS signature with Rustls' configured AWS-LC provider.
fn verify_p256_jws_signature(
    public_key_sec1: &[u8],
    signing_input: &[u8],
    signature_raw: &[u8],
) -> Result<(), VerifyResolverError> {
    let signature_der = es256_raw_signature_to_der(signature_raw)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let Some((_scheme, algorithms)) = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _algorithms)| *scheme == SignatureScheme::ECDSA_NISTP256_SHA256)
    else {
        return Err(VerifyResolverError::VerifyAlgorithmUnavailable);
    };
    let Some(algorithm) = algorithms.first() else {
        return Err(VerifyResolverError::VerifyAlgorithmUnavailable);
    };

    algorithm
        .verify_signature(public_key_sec1, signing_input, &signature_der)
        .map_err(|_source| VerifyResolverError::VerifySignature)
}

/// Converts ES256 raw `r || s` to DER SEQUENCE(INTEGER r, INTEGER s).
fn es256_raw_signature_to_der(signature_raw: &[u8]) -> Result<Vec<u8>, VerifyResolverError> {
    if signature_raw.len() != 64 {
        return Err(VerifyResolverError::VerifySignatureEncoding);
    }

    let r = der_integer(&signature_raw[..32]);
    let s = der_integer(&signature_raw[32..]);
    let sequence_len = r.len() + s.len();
    if sequence_len > 127 {
        return Err(VerifyResolverError::VerifySignatureEncoding);
    }

    let mut der = Vec::with_capacity(2 + sequence_len);
    der.push(0x30);
    der.push(u8::try_from(sequence_len).map_err(|_| VerifyResolverError::VerifySignatureEncoding)?);
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    Ok(der)
}

/// Encodes one unsigned ECDSA integer for DER.
fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let without_leading_zeroes = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[0_u8][..], |index| &bytes[index..]);
    let needs_positive_padding = without_leading_zeroes[0] & 0x80 != 0;
    let len = without_leading_zeroes.len() + usize::from(needs_positive_padding);

    let mut integer = Vec::with_capacity(2 + len);
    integer.push(0x02);
    integer.push(u8::try_from(len).expect("P-256 integer DER length fits u8"));
    if needs_positive_padding {
        integer.push(0x00);
    }
    integer.extend_from_slice(without_leading_zeroes);
    integer
}

/// Verify resolver error.
#[derive(Debug, thiserror::Error)]
pub enum VerifyResolverError {
    /// Verify blocking HTTP task failed to join.
    #[error("verify HTTP task failed")]
    Task {
        /// Source task join error.
        #[source]
        source: tokio::task::JoinError,
    },

    /// Verify HTTP request failed.
    #[error("verify HTTP request failed")]
    Http {
        /// Source HTTP error.
        #[source]
        source: ureq::Error,
    },

    /// Verify JSON response decoding failed.
    #[error("verify JSON response failed")]
    Json {
        /// Source JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// Verify v3 public-key endpoint returned a non-200 status.
    #[error("verify public key HTTP status failed: {status}")]
    PublicKeyStatus {
        /// HTTP response status.
        status: u16,
    },

    /// Verify JWT compact JWS decoding failed.
    #[error("verify JWT attestation decode failed")]
    VerifyJwtDecode {
        /// Source JWT decode error.
        #[source]
        source: VerifyJwtAttestationError,
    },

    /// Verify JWT public key decoding failed.
    #[error("verify JWT public key failed")]
    VerifyPublicKey {
        /// Source public-key decode error.
        #[source]
        source: VerifyP256PublicKeyError,
    },

    /// Rustls AWS-LC provider did not expose ES256 verification.
    #[error("verify JWT ES256 algorithm is unavailable")]
    VerifyAlgorithmUnavailable,

    /// Raw ES256 signature could not be converted to DER.
    #[error("verify JWT signature encoding failed")]
    VerifySignatureEncoding,

    /// Rustls deliberately returns no source details for invalid signatures.
    #[error("verify JWT P-256 signature or public key is invalid")]
    VerifySignature,

    /// JWT payload is expired at the caller-provided clock value.
    #[error("verify JWT is expired: exp={exp}, now={now_unix_seconds}")]
    VerifyJwtExpired {
        /// Payload expiry timestamp.
        exp: u64,
        /// Caller-provided current unix timestamp.
        now_unix_seconds: u64,
    },
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc,
    };
    use wc_protocol::verify::{
        ALTERNATE_VERIFY_URL, DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext,
    };

    use super::{VerifyResolver, trusted_verify_url};
    use crate::VerifyContextRisk;

    const FIXTURE_PUBLIC_KEY_BODY: &str = r#"{"publicKey":{"x":"yY_MCdoXFra13mJvUo0QUG7U3Xw3TXHZEq8ciltnyGY","y":"_sjhN35PNNKSaf44h0OkfgcXnQDr9bVcfNJc7GWdd-s"},"expiresAt":4102444800}"#;
    const WRONG_PUBLIC_KEY_BODY: &str = r#"{"publicKey":{"x":"CbL4DOYOb1ntd-8OmExO-oS0DWCMC00DntrymJoB8tk","y":"KTFwjHtQxGTDR91VsOypcdBfvbo6sAMj5p4Wb-9hRA0"},"expiresAt":4102444800}"#;
    const FIXTURE_ENCRYPTED_ID: &str = "encrypted-id-fixture";
    const FIXTURE_VERIFIED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.Nn_tdflpG4kmaUhiQvqeWsWA7weNimHGYgfv58t5r01TWQCgRtQJlFEbj_qzQQf81eqsGyVdAyHIF3rFEl9oXA";
    const FIXTURE_UNVERIFIED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQxMDI0NDQ4MDAsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6ZmFsc2V9.g8Yxh5anoCXhJeM1xoIKAtGmJZ_rRdbZIh_fZJEqinOOPEkpMv2KMx3dj9G6Y2Ni47Q_i3WASnlyhhq7BsSCRQ";
    const FIXTURE_EXPIRED_JWT: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEsImlkIjoiZW5jcnlwdGVkLWlkLWZpeHR1cmUiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNTY2FtIjpmYWxzZSwiaXNWZXJpZmllZCI6dHJ1ZX0.fhwRjn-F6zAUUNQYmsddR0z6Z_RysXKP3atkCctychBcXEBCIqLtmwilJ8fe4Q9eZuPQ_bk2VZnqW6Gnf1AJ7A";

    #[test]
    fn trusted_url_policy_matches_sdk_allowlist() {
        assert_eq!(
            trusted_verify_url(Some(DEFAULT_VERIFY_URL)),
            DEFAULT_VERIFY_URL
        );
        assert_eq!(
            trusted_verify_url(Some(ALTERNATE_VERIFY_URL)),
            ALTERNATE_VERIFY_URL
        );
        assert_eq!(
            trusted_verify_url(Some("https://verify.example.com")),
            DEFAULT_VERIFY_URL
        );
        assert_eq!(trusted_verify_url(None), DEFAULT_VERIFY_URL);
    }

    #[test]
    fn metadata_origin_uses_url_origin_normalization() {
        assert_eq!(
            super::metadata_origin("HTTPS://Example.COM:443/path?query#fragment"),
            Some("https://example.com".to_owned())
        );
        assert_eq!(super::metadata_origin("file:///tmp/example"), None);
    }

    #[tokio::test]
    async fn resolver_maps_attestation_to_valid_context() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = VerifyTestServer::new(200, r#"{"origin":"https://example.com"}"#).await?;
        let hash = VerifyAttestationHash::from_message("some");
        let resolver = VerifyResolver::with_timeout_and_trusted_urls(
            std::time::Duration::from_secs(2),
            vec![server.url()],
        )?;

        let context = resolver
            .resolve_hash_for_metadata(&hash, &metadata_with_verify_url(server.url()))
            .await?;

        assert_eq!(context.verified.origin, "https://example.com");
        assert_eq!(
            crate::classify_verify_context(&context),
            VerifyContextRisk::Valid
        );
        assert_eq!(
            server.take_request().await,
            format!("/attestation/{hash}?v2Supported=true")
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolver_maps_attestation_origin_mismatch_to_invalid()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, r#"{"origin":"https://evil.example"}"#).await?;
        let hash = VerifyAttestationHash::from_message("some");
        let resolver = VerifyResolver::with_timeout_and_trusted_urls(
            std::time::Duration::from_secs(2),
            vec![server.url()],
        )?;

        let context = resolver
            .resolve_hash_for_metadata(&hash, &metadata_with_verify_url(server.url()))
            .await?;

        assert_eq!(context.verified.origin, "https://evil.example");
        assert_eq!(
            crate::classify_verify_context(&context),
            VerifyContextRisk::Invalid
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolver_keeps_unknown_context_when_attestation_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(404, "Not Found").await?;
        let hash = VerifyAttestationHash::from_message("some");
        let resolver = VerifyResolver::with_timeout_and_trusted_urls(
            std::time::Duration::from_secs(2),
            vec![server.url()],
        )?;

        let context = resolver
            .resolve_hash_for_metadata(&hash, &metadata_with_verify_url(server.url()))
            .await?;

        assert_eq!(context.verified.origin, "https://example.com/path");
        assert_eq!(
            crate::classify_verify_context(&context),
            VerifyContextRisk::Unknown
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolver_rejects_oversized_attestation_body() -> Result<(), Box<dyn std::error::Error>>
    {
        let padding = "x".repeat(
            usize::try_from(super::MAX_VERIFY_ATTESTATION_BYTES)
                .expect("Verify attestation byte limit fits usize"),
        );
        let server = VerifyTestServer::new(
            200,
            format!(r#"{{"origin":"https://example.com","padding":"{padding}"}}"#),
        )
        .await?;
        let hash = VerifyAttestationHash::from_message("some");
        let resolver = VerifyResolver::with_timeout_and_trusted_urls(
            std::time::Duration::from_secs(2),
            vec![server.url()],
        )?;

        let error = resolver
            .resolve_attestation_hash(&hash, &server.url())
            .await
            .expect_err("oversized attestation body should be rejected");

        assert!(matches!(error, super::VerifyResolverError::Json { .. }));

        Ok(())
    }

    #[tokio::test]
    async fn resolver_fetches_verify_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let response = resolver.fetch_verify_public_key().await?;

        assert_eq!(response.expires_at, 4_102_444_800);
        assert_eq!(
            response.public_key.x,
            "yY_MCdoXFra13mJvUo0QUG7U3Xw3TXHZEq8ciltnyGY"
        );
        assert_eq!(server.take_request().await, "/public-key");

        Ok(())
    }

    #[tokio::test]
    async fn resolver_maps_verified_jwt_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let attestation = resolver
            .resolve_jwt_attestation(FIXTURE_VERIFIED_JWT, FIXTURE_ENCRYPTED_ID, 1_700_000_000)
            .await?
            .expect("valid JWT attestation should resolve");

        assert_eq!(attestation.origin, "https://example.com");
        assert_eq!(attestation.is_scam, Some(false));
        assert_eq!(server.take_request().await, "/public-key");

        Ok(())
    }

    #[tokio::test]
    async fn resolver_maps_verified_jwt_to_context() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;
        let context = VerifyContext::unknown("https://example.com/path", DEFAULT_VERIFY_URL);

        let context = resolver
            .resolve_jwt_for_context(
                FIXTURE_VERIFIED_JWT,
                FIXTURE_ENCRYPTED_ID,
                &context,
                1_700_000_000,
            )
            .await?;

        assert_eq!(context.verified.origin, "https://example.com");
        assert_eq!(
            crate::classify_verify_context(&context),
            VerifyContextRisk::Valid
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolver_rejects_tampered_jwt_signature() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;
        let token = tamper_signature_char(FIXTURE_VERIFIED_JWT);

        let error = resolver
            .resolve_jwt_attestation(&token, FIXTURE_ENCRYPTED_ID, 1_700_000_000)
            .await
            .expect_err("tampered JWT signature should be rejected");

        assert!(matches!(error, super::VerifyResolverError::VerifySignature));

        Ok(())
    }

    #[tokio::test]
    async fn resolver_rejects_wrong_jwt_public_key() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, WRONG_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let error = resolver
            .resolve_jwt_attestation(FIXTURE_VERIFIED_JWT, FIXTURE_ENCRYPTED_ID, 1_700_000_000)
            .await
            .expect_err("wrong public key should reject JWT signature");

        assert!(matches!(error, super::VerifyResolverError::VerifySignature));

        Ok(())
    }

    #[tokio::test]
    async fn resolver_skips_unverified_jwt_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let attestation = resolver
            .resolve_jwt_attestation(FIXTURE_UNVERIFIED_JWT, FIXTURE_ENCRYPTED_ID, 1_700_000_000)
            .await?;

        assert!(attestation.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn resolver_falls_back_to_hash_when_jwt_is_not_usable()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifySequenceServer::new([
            (200, FIXTURE_PUBLIC_KEY_BODY.to_owned()),
            (200, r#"{"origin":"https://example.com"}"#.to_owned()),
        ])
        .await?;
        let hash = VerifyAttestationHash::from_message("fallback payload");
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            vec![server.url()],
            server.url(),
        )?;
        let context = VerifyContext::unknown("https://example.com/path", server.url());

        let context = resolver
            .resolve_jwt_or_hash_for_context(
                FIXTURE_UNVERIFIED_JWT,
                FIXTURE_ENCRYPTED_ID,
                &hash,
                &context,
                1_700_000_000,
            )
            .await?;

        assert_eq!(context.verified.origin, "https://example.com");
        assert_eq!(
            crate::classify_verify_context(&context),
            VerifyContextRisk::Valid
        );
        assert_eq!(
            server.take_requests().await,
            vec![
                "/public-key".to_owned(),
                format!("/attestation/{hash}?v2Supported=true"),
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn resolver_skips_jwt_with_mismatched_encrypted_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let attestation = resolver
            .resolve_jwt_attestation(FIXTURE_VERIFIED_JWT, "different-id", 1_700_000_000)
            .await?;

        assert!(attestation.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn resolver_rejects_expired_jwt_attestation() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(200, FIXTURE_PUBLIC_KEY_BODY).await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let error = resolver
            .resolve_jwt_attestation(FIXTURE_EXPIRED_JWT, FIXTURE_ENCRYPTED_ID, 1_700_000_000)
            .await
            .expect_err("expired JWT should be rejected");

        assert!(matches!(
            error,
            super::VerifyResolverError::VerifyJwtExpired { .. }
        ));

        Ok(())
    }

    #[tokio::test]
    async fn resolver_rejects_failed_public_key_fetch() -> Result<(), Box<dyn std::error::Error>> {
        let server = VerifyTestServer::new(503, "unavailable").await?;
        let resolver = VerifyResolver::with_timeout_and_trusted_urls_and_verify_v3_url(
            std::time::Duration::from_secs(2),
            Vec::new(),
            server.url(),
        )?;

        let error = resolver
            .fetch_verify_public_key()
            .await
            .expect_err("non-200 public-key response should be rejected");

        assert!(matches!(
            error,
            super::VerifyResolverError::PublicKeyStatus { status: 503 }
        ));

        Ok(())
    }

    fn metadata_with_verify_url(verify_url: String) -> wc_protocol::session::DappMetadata {
        wc_protocol::session::DappMetadata {
            name: "Example".to_owned(),
            description: "Example dapp".to_owned(),
            url: "https://example.com/path".to_owned(),
            icons: Vec::new(),
            verify_url: Some(verify_url),
            redirect: None,
        }
    }

    fn tamper_signature_char(token: &str) -> String {
        let mut parts = token.split('.');
        let header = parts.next().expect("fixture has header");
        let payload = parts.next().expect("fixture has payload");
        let mut signature = parts
            .next()
            .expect("fixture has signature")
            .chars()
            .collect::<Vec<_>>();
        signature[4] = if signature[4] == 'A' { 'B' } else { 'A' };
        let signature = signature.into_iter().collect::<String>();
        format!("{header}.{payload}.{signature}")
    }

    struct VerifyTestServer {
        url: String,
        request_rx: tokio::sync::oneshot::Receiver<String>,
    }

    impl VerifyTestServer {
        async fn new(
            status: u16,
            body: impl Into<String>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let address = listener.local_addr()?;
            let (request_tx, request_rx) = tokio::sync::oneshot::channel();
            let body = body.into();

            tokio::spawn(async move {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 2048];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_owned();
                let _ = request_tx.send(path);
                let reason = if status == 200 { "OK" } else { "Not Found" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });

            Ok(Self {
                url: format!("http://{address}"),
                request_rx,
            })
        }

        fn url(&self) -> String {
            self.url.clone()
        }

        async fn take_request(self) -> String {
            self.request_rx.await.expect("request path")
        }
    }

    struct VerifySequenceServer {
        url: String,
        expected_requests: usize,
        request_rx: mpsc::UnboundedReceiver<String>,
    }

    impl VerifySequenceServer {
        async fn new(
            responses: impl IntoIterator<Item = (u16, String)>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let address = listener.local_addr()?;
            let responses = responses.into_iter().collect::<Vec<_>>();
            let expected_requests = responses.len();
            let (request_tx, request_rx) = mpsc::unbounded_channel();

            tokio::spawn(async move {
                for (status, body) in responses {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let mut buffer = [0_u8; 2048];
                    let Ok(read) = stream.read(&mut buffer).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("")
                        .to_owned();
                    let _ = request_tx.send(path);
                    let reason = if status == 200 { "OK" } else { "Not Found" };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            });

            Ok(Self {
                url: format!("http://{address}"),
                expected_requests,
                request_rx,
            })
        }

        fn url(&self) -> String {
            self.url.clone()
        }

        async fn take_requests(mut self) -> Vec<String> {
            let mut requests = Vec::with_capacity(self.expected_requests);
            for _ in 0..self.expected_requests {
                requests.push(self.request_rx.recv().await.expect("request path"));
            }
            requests
        }
    }
}
