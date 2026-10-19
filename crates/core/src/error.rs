#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid base64url: {0}")]
    Decode(#[from] base64::DecodeError),

    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
}
