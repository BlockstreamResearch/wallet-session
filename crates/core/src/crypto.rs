/// Seals application payloads for the wire and opens received ones.
pub trait MessageCipher: Send {
    /// Cipher-specific sealed representation.
    type Sealed;

    /// Cipher failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encrypt `plaintext`, returning the sealed representation.
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Self::Sealed, Self::Error>;

    /// Decrypt a received sealed representation.
    fn open(&self, aad: &[u8], sealed: &Self::Sealed) -> Result<Vec<u8>, Self::Error>;

    /// Create a fresh cipher for a new 32-byte key.
    ///
    /// Implementations must start with fresh nonce state: the sender prefix
    /// must be regenerated and the counter must start at zero.
    fn for_key(&self, key: &[u8; 32]) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
