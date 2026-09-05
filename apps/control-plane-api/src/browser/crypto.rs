//! Bounded token-envelope primitive for trusted browser-edge callers.
//!
//! This module does not authenticate operators, select scopes, load keys, or
//! persist sessions. Callers supply verified identity metadata, the immutable
//! absolute record expiry, and the current Unix time in seconds on every use.
//! Key material comes from deployment configuration, never startup generation.
//!
//! Version 1 authenticates a fixed domain label, envelope version and key ID,
//! purpose, record digest, exact issuer/client/subject, and absolute expiry.
//! Variable-length fields use byte lengths; absent subjects have a distinct tag.

use std::fmt;

mod binding;
mod envelope;
mod keyring;

pub use binding::{EnvelopePurpose, RecordDigest, TokenBinding};
pub use envelope::TokenEnvelope;
pub use keyring::{SecretBytes, TokenKey, TokenKeyring};

/// Maximum opaque plaintext length; the AEAD adds a 16-byte authentication tag.
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1_024;
/// Maximum bytes in a record identifier before SHA-256 hashing.
pub const MAX_RECORD_ID_BYTES: usize = 1_024;
/// Maximum ASCII bytes in a key identifier.
pub const MAX_KEY_ID_BYTES: usize = 64;
/// Maximum total number of active and retired keys.
pub const MAX_KEYS: usize = 4;
/// Maximum bytes in the exact configured issuer string.
pub const MAX_ISSUER_BYTES: usize = 2_048;
/// Maximum bytes in the exact configured client identifier.
pub const MAX_CLIENT_BYTES: usize = 256;
/// Maximum bytes in the exact subject string.
pub const MAX_SUBJECT_BYTES: usize = 512;

const ENVELOPE_VERSION: u32 = 1;
const TAG_BYTES: usize = 16;

/// Static, redacted failure categories; no key, token, binding, or source error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidBinding,
    InvalidKey,
    InvalidKeyring,
    InvalidEnvelope,
    UnsupportedVersion,
    UnknownKey,
    ExpiredBinding,
    ExpiredKey,
    InputTooLarge,
    AuthenticationFailed,
    EntropyUnavailable,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("browser token envelope operation failed")
    }
}

impl std::error::Error for CryptoError {}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod validation_tests;
