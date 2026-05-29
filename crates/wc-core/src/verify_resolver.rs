//! Verify API resolver.

use std::{sync::Arc, time::Duration};

use serde::Deserialize;
use ureq::tls::{TlsConfig, TlsProvider};
use wc_protocol::{
    session::DappMetadata,
    verify::{
        ALTERNATE_VERIFY_URL, DEFAULT_VERIFY_URL, VerifyAttestationHash, VerifyContext,
        VerifyValidation,
    },
};

/// Default timeout for one Verify API request.
pub const DEFAULT_VERIFY_RESOLVER_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_VERIFY_ATTESTATION_BYTES: u64 = 64 * 1024;

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
}

#[cfg(test)]
mod tests {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use wc_protocol::verify::{ALTERNATE_VERIFY_URL, DEFAULT_VERIFY_URL, VerifyAttestationHash};

    use super::{VerifyResolver, trusted_verify_url};
    use crate::VerifyContextRisk;

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
}
