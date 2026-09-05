//! Durable browser sessions. This synchronous store belongs to a bounded
//! blocking worker, never a Tokio request task. HTTP session orchestration,
//! token verification and provider I/O are separate responsibilities.

use super::{
    crypto::TokenEnvelope,
    errors::BrowserError,
    security::{CsrfBinding, LookupDigest},
};

mod store;
pub use store::PostgresSessionStore;
mod actor;
pub use actor::BrowserSessionStore;

/// A durably admitted login's fixed database-clock expiry; never extend it.
pub struct LoginAdmission {
    pub expires_at: i64,
}

impl std::fmt::Debug for LoginAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginAdmission([REDACTED])")
    }
}

pub struct SessionIdentity {
    pub digest: LookupDigest,
    pub issuer: String,
    pub client_id: String,
    pub subject: String,
    pub absolute_expires_at: i64,
}

pub struct NewLoginAttempt {
    pub state: LookupDigest,
    pub browser: LookupDigest,
    pub issuer: String,
    pub client_id: String,
    pub expires_at: i64,
    pub envelope: TokenEnvelope,
}

pub struct NewSession {
    pub identity: SessionIdentity,
    pub csrf_binding: CsrfBinding,
    pub envelope: TokenEnvelope,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub idle_timeout_secs: u32,
}

pub struct StoredSession {
    pub identity: SessionIdentity,
    pub csrf_binding: CsrfBinding,
    pub envelope: TokenEnvelope,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
    pub idle_expires_at: i64,
    pub generation: u64,
    /// Present only after a refresh claim; an expired claim cannot be retried.
    pub refresh_deadline: Option<i64>,
}

pub struct RefreshCommit {
    pub digest: LookupDigest,
    pub generation: u64,
    pub envelope: TokenEnvelope,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}

impl SessionIdentity {
    pub fn token_binding(&self) -> Result<super::crypto::TokenBinding<'_>, BrowserError> {
        use super::crypto::{EnvelopePurpose, RecordDigest, TokenBinding};
        TokenBinding::new(
            EnvelopePurpose::OperatorSession,
            RecordDigest::from_sha256(self.digest.as_bytes())
                .map_err(|_| BrowserError::Unavailable)?,
            &self.issuer,
            &self.client_id,
            Some(&self.subject),
            self.absolute_expires_at,
        )
        .map_err(|_| BrowserError::Unavailable)
    }
}
