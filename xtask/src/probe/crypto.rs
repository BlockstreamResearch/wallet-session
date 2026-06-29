use anyhow::{Context, Result, bail};
use wc_protocol::key::{
    X25519KeyPair, X25519PrivateKey, X25519PublicKey, derive_shared_sym_key,
    derive_topic_from_sym_key,
};

use crate::util::redact;

const LIVE_JS_A_PRIVATE_KEY: &str =
    "3afc2a18c0b229afd47e0509fc6543c1c547ba3f93da0cb9a8d3f4e7cee4e7ce";
const LIVE_JS_A_PUBLIC_KEY: &str =
    "5c26bac1fda7c2bf9835b15b2452cf4d4313098ee491465f4904d05225b2d026";
const LIVE_JS_B_PRIVATE_KEY: &str =
    "ffba1f1cec7c9841ad0edf9c8dc0bde4bcbb429204bc63abcd67066f35ee5714";
const LIVE_JS_B_PUBLIC_KEY: &str =
    "80dd64bd6e4c3612ff0f5ccbe9282f1f11ba56ada6a2f9740da063d1ed1f2b20";
const LIVE_JS_SHARED_SYM_KEY: &str =
    "81b30968ad471e842d9936c567429a0ce7c04787ed8d103143cdba785be7ba1a";
const LIVE_JS_DERIVED_TOPIC: &str =
    "e2b00edc48dfe17b2bb8f9eabe52ba1ada4f2a3a651c6b01cb873f74cecfec82";

pub fn run() -> Result<()> {
    let generated = X25519KeyPair::generate().context("failed to generate X25519 key pair")?;
    println!(
        "crypto-probe generated public_key={} private_key_len={}",
        generated.public_key(),
        generated.private_key().as_str().len()
    );

    let a_private = X25519PrivateKey::from_hex(LIVE_JS_A_PRIVATE_KEY)
        .context("invalid vector private key A")?;
    let a_public =
        X25519PublicKey::from_hex(LIVE_JS_A_PUBLIC_KEY).context("invalid vector public key A")?;
    let b_private = X25519PrivateKey::from_hex(LIVE_JS_B_PRIVATE_KEY)
        .context("invalid vector private key B")?;
    let b_public =
        X25519PublicKey::from_hex(LIVE_JS_B_PUBLIC_KEY).context("invalid vector public key B")?;

    if a_private.public_key() != a_public {
        bail!("crypto-probe vector A public key mismatch");
    }
    if b_private.public_key() != b_public {
        bail!("crypto-probe vector B public key mismatch");
    }

    let ab =
        derive_shared_sym_key(&a_private, &b_public).context("failed to derive A->B symKey")?;
    let ba =
        derive_shared_sym_key(&b_private, &a_public).context("failed to derive B->A symKey")?;
    if ab != ba {
        bail!("crypto-probe derived asymmetric symKeys");
    }
    if ab.as_str() != LIVE_JS_SHARED_SYM_KEY {
        bail!("crypto-probe derived symKey does not match WalletConnect JS vector");
    }

    let topic = derive_topic_from_sym_key(&ab);
    if topic.as_str() != LIVE_JS_DERIVED_TOPIC {
        bail!("crypto-probe derived topic does not match WalletConnect JS vector");
    }

    println!(
        "crypto-probe live_vector sym_key={} topic={} symmetric=true",
        redact(ab.as_str()),
        topic
    );

    Ok(())
}
