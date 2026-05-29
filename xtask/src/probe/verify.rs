use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use wc_core::{VerifyResolver, classify_verify_context};
use wc_protocol::{
    session::DappMetadata,
    verify::{VerifyAttestationHash, VerifyValidation},
};

/// Runs a live Verify API hash-resolution probe.
pub async fn run(args: VerifyProbeArgs) -> Result<()> {
    let resolver = VerifyResolver::new().context("failed to build Verify resolver")?;
    let hash_requested =
        args.hash.is_some() || args.metadata_url.is_some() || args.verify_url.is_some();

    if args.public_key {
        let response = resolver
            .fetch_verify_public_key()
            .await
            .context("Verify public key fetch failed")?;
        println!(
            "verify-probe public_key=true expires_at={} x={} y={}",
            response.expires_at, response.public_key.x, response.public_key.y
        );
        if !hash_requested && args.attestation_jwt.is_none() {
            return Ok(());
        }
    }

    if let Some(attestation_jwt) = args.attestation_jwt {
        let encrypted_id = args
            .encrypted_id
            .as_deref()
            .context("--encrypted-id is required with --attestation-jwt")?;
        let now_unix_seconds = match args.now_unix_seconds {
            Some(now_unix_seconds) => now_unix_seconds,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before unix epoch")?
                .as_secs(),
        };
        let attestation = resolver
            .resolve_jwt_attestation(&attestation_jwt, encrypted_id, now_unix_seconds)
            .await
            .context("Verify JWT resolver failed")?;
        match attestation {
            Some(attestation) => println!(
                "verify-probe jwt_resolved=true origin={} is_scam={}",
                attestation.origin,
                attestation.is_scam.unwrap_or(false)
            ),
            None => println!("verify-probe jwt_resolved=false"),
        }
        return Ok(());
    }

    if args.encrypted_id.is_some() || args.now_unix_seconds.is_some() {
        bail!("--encrypted-id and --now-unix-seconds require --attestation-jwt");
    }

    let metadata_url = args
        .metadata_url
        .unwrap_or_else(|| "https://example.com".to_owned());
    let hash = match args.hash {
        Some(hash) => VerifyAttestationHash::parse(hash).context("invalid verify hash")?,
        None => VerifyAttestationHash::from_message("some"),
    };
    let metadata = DappMetadata {
        name: "Verify probe".to_owned(),
        description: "Verify resolver probe".to_owned(),
        url: metadata_url,
        icons: Vec::new(),
        verify_url: args.verify_url,
        redirect: None,
    };
    let context = resolver
        .resolve_hash_for_metadata(&hash, &metadata)
        .await
        .context("Verify resolver failed")?;
    let risk = classify_verify_context(&context);

    println!(
        "verify-probe hash={} metadata_url={} verify_url={} origin={} validation={} risk={risk:?} is_scam={}",
        hash,
        metadata.url,
        context.verified.verify_url,
        context.verified.origin,
        context.verified.validation,
        context.verified.is_scam()
    );

    if context.verified.validation == VerifyValidation::Unknown {
        println!("verify-probe resolved=false");
    } else {
        println!("verify-probe resolved=true");
    }

    Ok(())
}

/// Verify probe CLI args.
#[derive(Debug, Clone)]
pub struct VerifyProbeArgs {
    /// Optional attestation hash. Defaults to `hashMessage("some")`.
    pub hash: Option<String>,
    /// Fetches the live Verify v3 public key.
    pub public_key: bool,
    /// Optional JWT attestation to verify through the live Verify v3 key.
    pub attestation_jwt: Option<String>,
    /// Relay-provided encrypted ID matched against the JWT payload `id`.
    pub encrypted_id: Option<String>,
    /// Optional unix timestamp for deterministic JWT expiry checks.
    pub now_unix_seconds: Option<u64>,
    /// Dapp metadata URL used for origin comparison.
    pub metadata_url: Option<String>,
    /// Optional dapp-provided Verify URL.
    pub verify_url: Option<String>,
}
