/// Seals application payloads for the wire and opens received ones.
pub trait MessageCipher: Send {
    /// Cipher-specific sealed representation written to the wire.
    type Sealed;

    /// Cipher failure type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encrypt `plaintext`, returning the sealed representation.
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Self::Sealed, Self::Error>;

    /// Decrypt a received sealed representation.
    fn open(&self, aad: &[u8], sealed: &Self::Sealed) -> Result<Vec<u8>, Self::Error>;
}
