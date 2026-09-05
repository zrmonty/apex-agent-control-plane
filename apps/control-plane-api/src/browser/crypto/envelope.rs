use super::{CryptoError, ENVELOPE_VERSION, MAX_PLAINTEXT_BYTES, TAG_BYTES};
use std::fmt;

/// Validated storage shape; authenticity is established only by `open`.
///
/// There is deliberately no unchecked deserializer. Restore binary database
/// fields through `from_storage`, which bounds inputs before copying them.
/// The immutable binding is supplied separately from trusted record context.
pub struct TokenEnvelope {
    pub(super) version: u32,
    pub(super) key_id: String,
    pub(super) nonce: [u8; 24],
    pub(super) ciphertext: Vec<u8>,
}

impl TokenEnvelope {
    /// Restore version 1, a valid key ID, a 24-byte nonce, and 16..=65,552
    /// ciphertext bytes. This is storage ingestion, never a seal nonce override.
    pub fn from_storage(
        version: u32,
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Self, CryptoError> {
        validate_fields(version, key_id, ciphertext.len())?;
        let nonce = nonce.try_into().map_err(|_| CryptoError::InvalidEnvelope)?;
        Ok(Self {
            version,
            key_id: key_id.to_owned(),
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub(super) fn validate(&self) -> Result<(), CryptoError> {
        validate_fields(self.version, &self.key_id, self.ciphertext.len())
    }

    /// Envelope storage version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Exact key identifier for storage; opening never falls back to another key.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Fresh OS-generated nonce for storage.
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Authenticated ciphertext including its trailing authentication tag.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

fn validate_fields(version: u32, key_id: &str, ciphertext_len: usize) -> Result<(), CryptoError> {
    if version != ENVELOPE_VERSION {
        return Err(CryptoError::UnsupportedVersion);
    }
    super::keyring::validate_key_id(key_id).map_err(|_| CryptoError::InvalidEnvelope)?;
    if ciphertext_len > MAX_PLAINTEXT_BYTES + TAG_BYTES {
        return Err(CryptoError::InputTooLarge);
    }
    if ciphertext_len < TAG_BYTES {
        return Err(CryptoError::InvalidEnvelope);
    }
    Ok(())
}

impl fmt::Debug for TokenEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenEnvelope([REDACTED])")
    }
}
