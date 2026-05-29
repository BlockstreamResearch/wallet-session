use anyhow::{Context, Result};
use wc_core::{VerifyResolver, classify_verify_context};
use wc_protocol::{
    session::DappMetadata,
    verify::{VerifyAttestationHash, VerifyValidation},
};

/// Runs a live Verify API hash-resolution probe.
pub async fn run(args: VerifyProbeArgs) -> Result<()> {
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
    let resolver = VerifyResolver::new().context("failed to build Verify resolver")?;
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
    /// Dapp metadata URL used for origin comparison.
    pub metadata_url: Option<String>,
    /// Optional dapp-provided Verify URL.
    pub verify_url: Option<String>,
}
