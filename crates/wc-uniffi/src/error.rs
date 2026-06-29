use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
/// Error type exposed through the `UniFFI` wallet client bindings.
pub enum WcUniFfiError {
    /// A caller-supplied value was invalid.
    #[error("invalid input: {details}")]
    InvalidInput {
        /// Human-readable diagnostic.
        details: String,
    },
    /// The client is not connected or has already been shut down.
    #[error("client state error: {details}")]
    State {
        /// Human-readable diagnostic.
        details: String,
    },
    /// A protocol, relay, or wallet policy operation failed.
    #[error("walletconnect operation failed: {details}")]
    Operation {
        /// Human-readable diagnostic.
        details: String,
    },
}
