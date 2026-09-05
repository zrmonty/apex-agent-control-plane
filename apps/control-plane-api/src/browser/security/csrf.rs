use super::{OpaqueToken, SecurityError, tokens::TOKEN_WIRE_BYTES};
use axum::http::HeaderMap;
use std::fmt;
use subtle::ConstantTimeEq;

/// A separate CSRF token type prevents confusing a cookie ID with CSRF evidence.
pub struct CsrfToken(OpaqueToken);

impl CsrfToken {
    /// Generate an independent canonical 32-byte token using fallible OS entropy.
    pub fn generate() -> Result<Self, SecurityError> {
        OpaqueToken::generate().map(Self)
    }

    /// Parse canonical wire bytes (including restoration from protected storage).
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        OpaqueToken::parse(value).map(Self)
    }

    /// Explicit disclosure only for the authenticated `GET /api/session` body.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    /// SHA-256 of canonical ASCII wire bytes for the stored session binding.
    pub fn binding(&self) -> CsrfBinding {
        CsrfBinding(*self.0.lookup_digest().as_bytes())
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken([REDACTED])")
    }
}

/// Session-specific CSRF digest; equality is only exposed through `verify_csrf`.
#[derive(Clone)]
pub struct CsrfBinding([u8; 32]);

impl CsrfBinding {
    /// Restore exactly 32 bytes from the durable session's binding column.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Persist fixed-width binding bytes; never expose them as a CSRF token.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CsrfBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfBinding([REDACTED])")
    }
}

/// Require exactly one canonical `x-apex-csrf` value and compare SHA-256 digests
/// in constant time. This has no session side effects and grants no access.
pub fn verify_csrf(headers: &HeaderMap, binding: &CsrfBinding) -> Result<(), SecurityError> {
    let mut values = headers.get_all("x-apex-csrf").iter();
    let value = values.next().ok_or(SecurityError::MissingCsrf)?;
    if values.next().is_some() || value.as_bytes().len() != TOKEN_WIRE_BYTES {
        return Err(SecurityError::InvalidCsrf);
    }
    let wire = value.to_str().map_err(|_| SecurityError::InvalidCsrf)?;
    let supplied = CsrfToken::parse(wire).map_err(|_| SecurityError::InvalidCsrf)?;
    // Both operands always contain exactly 32 bytes. No string equality,
    // prefix comparison or early exit based on digest contents is used.
    if bool::from(supplied.binding().0.ct_eq(&binding.0)) {
        Ok(())
    } else {
        Err(SecurityError::CsrfMismatch)
    }
}
