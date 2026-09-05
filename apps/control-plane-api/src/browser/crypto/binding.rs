use super::{
    CryptoError, MAX_CLIENT_BYTES, MAX_ISSUER_BYTES, MAX_KEY_ID_BYTES, MAX_RECORD_ID_BYTES,
    MAX_SUBJECT_BYTES,
};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const AAD_DOMAIN: &[u8] = b"apex.browser.token-envelope\0";
// Domain, version, four length-prefixed fields, purpose, digest, subject tag,
// and expiry. All variable fields are validated before building this buffer.
const MAX_AAD_BYTES: usize = AAD_DOMAIN.len()
    + 4
    + 4 * 4
    + MAX_KEY_ID_BYTES
    + MAX_ISSUER_BYTES
    + MAX_CLIENT_BYTES
    + MAX_SUBJECT_BYTES
    + 1
    + 32
    + 1
    + 8;

/// Cryptographically separated envelope domains; this grants no authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopePurpose {
    LoginAttempt,
    OperatorSession,
}

/// SHA-256 lookup digest of the exact opaque record identifier bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecordDigest([u8; 32]);

impl RecordDigest {
    /// Hash a nonempty identifier of at most `MAX_RECORD_ID_BYTES` bytes.
    pub fn of_record_id(record_id: &[u8]) -> Result<Self, CryptoError> {
        if record_id.is_empty() {
            return Err(CryptoError::InvalidBinding);
        }
        if record_id.len() > MAX_RECORD_ID_BYTES {
            return Err(CryptoError::InputTooLarge);
        }
        Ok(Self(Sha256::digest(record_id).into()))
    }

    /// Restore a persisted digest, requiring exactly 32 bytes.
    pub fn from_sha256(digest: &[u8]) -> Result<Self, CryptoError> {
        let bytes = digest.try_into().map_err(|_| CryptoError::InvalidBinding)?;
        Ok(Self(bytes))
    }

    /// Explicit access for persistence and lookup; do not log this value.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RecordDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordDigest([REDACTED])")
    }
}

/// Immutable, bounded identity and record context authenticated with ciphertext.
///
/// Strings are preserved exactly, never URL-normalized or case-folded. Metadata
/// must be nonempty, contain no control characters or surrounding whitespace,
/// and satisfy the exported byte limits. Session bindings require a subject;
/// login attempts may use `None` before an operator has been identified.
#[derive(Clone, Copy)]
pub struct TokenBinding<'a> {
    purpose: EnvelopePurpose,
    record_digest: RecordDigest,
    issuer: &'a str,
    client_id: &'a str,
    subject: Option<&'a str>,
    absolute_expires_at_unix_seconds: i64,
}

impl<'a> TokenBinding<'a> {
    /// Validate context; expiry is a positive absolute Unix timestamp in seconds.
    /// Time-based expiry is rechecked by both `TokenKeyring::seal` and `open`.
    pub fn new(
        purpose: EnvelopePurpose,
        record_digest: RecordDigest,
        issuer: &'a str,
        client_id: &'a str,
        subject: Option<&'a str>,
        absolute_expires_at_unix_seconds: i64,
    ) -> Result<Self, CryptoError> {
        validate_metadata(issuer, MAX_ISSUER_BYTES)?;
        validate_metadata(client_id, MAX_CLIENT_BYTES)?;
        if let Some(subject) = subject {
            validate_metadata(subject, MAX_SUBJECT_BYTES)?;
        } else if purpose == EnvelopePurpose::OperatorSession {
            return Err(CryptoError::InvalidBinding);
        }
        if absolute_expires_at_unix_seconds <= 0 {
            return Err(CryptoError::InvalidBinding);
        }
        Ok(Self {
            purpose,
            record_digest,
            issuer,
            client_id,
            subject,
            absolute_expires_at_unix_seconds,
        })
    }

    pub(super) fn check_at(&self, now_unix_seconds: i64) -> Result<(), CryptoError> {
        if now_unix_seconds < 0 {
            return Err(CryptoError::InvalidBinding);
        }
        if now_unix_seconds >= self.absolute_expires_at_unix_seconds {
            return Err(CryptoError::ExpiredBinding);
        }
        Ok(())
    }

    /// Version 1 wire order: domain bytes; u32 version; key ID; u8 purpose;
    /// 32-byte digest; issuer; client; u8 subject presence and optional subject;
    /// i64 absolute expiry. Integers and u32 byte-length prefixes are big-endian.
    pub(super) fn associated_data(
        &self,
        version: u32,
        key_id: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // Callers already validate these envelope fields; keep the encoding
        // boundary bounded even if another internal caller is added later.
        super::keyring::validate_key_id(key_id)?;
        let mut aad = Zeroizing::new(Vec::with_capacity(MAX_AAD_BYTES));
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(&version.to_be_bytes());
        push_field(&mut aad, key_id.as_bytes())?;
        aad.push(match self.purpose {
            EnvelopePurpose::LoginAttempt => 1,
            EnvelopePurpose::OperatorSession => 2,
        });
        aad.extend_from_slice(self.record_digest.as_bytes());
        push_field(&mut aad, self.issuer.as_bytes())?;
        push_field(&mut aad, self.client_id.as_bytes())?;
        match self.subject {
            None => aad.push(0),
            Some(subject) => {
                aad.push(1);
                push_field(&mut aad, subject.as_bytes())?;
            }
        }
        aad.extend_from_slice(&self.absolute_expires_at_unix_seconds.to_be_bytes());
        Ok(aad)
    }
}

fn validate_metadata(value: &str, max_bytes: usize) -> Result<(), CryptoError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(CryptoError::InvalidBinding);
    }
    Ok(())
}

fn push_field(aad: &mut Vec<u8>, bytes: &[u8]) -> Result<(), CryptoError> {
    let length = u32::try_from(bytes.len()).map_err(|_| CryptoError::InvalidBinding)?;
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(bytes);
    Ok(())
}

impl fmt::Debug for TokenBinding<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenBinding([REDACTED])")
    }
}
