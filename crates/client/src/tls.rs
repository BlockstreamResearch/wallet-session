//! TLS provider setup for `wss://` relay connections.
//!
//! `tokio-tungstenite` enables rustls without selecting a crypto provider.
//! Enabling the `ring` feature on our direct rustls dependency gives rustls
//! exactly one provider feature, and this module installs it before the first
//! connection. If the embedding application already installed a provider, that
//! choice is kept.

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the default rustls provider once per process.
pub(crate) fn ensure_crypto_provider() {
    INSTALL.call_once(|| {
        // An application may have installed its own provider already; in that
        // case rustls returns it as an error and we leave it in place.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_a_process_default() {
        ensure_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
