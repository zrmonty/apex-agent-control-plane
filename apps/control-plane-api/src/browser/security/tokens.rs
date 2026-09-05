use super::SecurityError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 32;
pub(super) const TOKEN_WIRE_BYTES: usize = 43;

/// A canonical 32-byte URL-safe, unpadded opaque value with redacted Debug.
/// Owned plaintext and temporary decoded bytes are zeroized on drop.
pub struct OpaqueToken(Zeroizing<String>);

impl OpaqueToken {
    /// Generate from fallible OS randomness; entropy failure must fail closed.
    pub fn generate() -> Result<Self, SecurityError> {
        let mut bytes = Zeroizing::new([0_u8; TOKEN_BYTES]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| SecurityError::Unavailable)?;
        Ok(Self(Zeroizing::new(
            URL_SAFE_NO_PAD.encode(bytes.as_slice()),
        )))
    }

    /// Reject noncanonical, malformed and oversized values before allocation.
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        if value.len() != TOKEN_WIRE_BYTES {
            return Err(SecurityError::InvalidToken);
        }
        let mut decoded = Zeroizing::new([0_u8; TOKEN_BYTES]);
        // This engine requires no padding and rejects nonzero unused bits.
        // The slice decoder bounds writes and allocates no input-sized buffer.
        let length = URL_SAFE_NO_PAD
            .decode_slice(value, decoded.as_mut_slice())
            .map_err(|_| SecurityError::InvalidToken)?;
        if length != TOKEN_BYTES {
            return Err(SecurityError::InvalidToken);
        }
        Ok(Self(Zeroizing::new(value.to_owned())))
    }

    /// Explicit wire disclosure for cookie emission; never log or persist it.
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }

    /// SHA-256 of canonical ASCII wire bytes, for durable lookup only.
    pub fn lookup_digest(&self) -> LookupDigest {
        LookupDigest(Sha256::digest(self.0.as_bytes()).into())
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpaqueToken([REDACTED])")
    }
}

/// A cookie lookup digest, never an authentication or authorization decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LookupDigest([u8; 32]);

impl LookupDigest {
    /// Restore fixed-width bytes from trusted durable storage.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Fixed-width digest for a database key; do not use as a bearer credential.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for LookupDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LookupDigest([REDACTED])")
    }
}
