use std::time::Duration;

/// Scoped rate-limit bucket. Keys must be derived outside this store from
/// already-validated scope/identity material; raw tokens are never accepted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    pub namespace: String,
    pub bucket: String,
}

/// Fingerprint counter for redacted security/abuse aggregation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FingerprintCounterKey {
    pub namespace: String,
    pub fingerprint_hex: String,
}

/// Short-lived revocation/deny acceleration hint (never authoritative alone).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DenyHintKey {
    pub namespace: String,
    pub identity_fingerprint_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub remaining: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralErrorCode {
    InvalidKey,
    Capacity,
    Unavailable,
}

impl EphemeralErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidKey => "EPHEMERAL_INVALID_KEY",
            Self::Capacity => "EPHEMERAL_CAPACITY",
            Self::Unavailable => "EPHEMERAL_UNAVAILABLE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralError {
    pub code: EphemeralErrorCode,
    pub summary: &'static str,
}

impl EphemeralError {
    pub fn invalid_key() -> Self {
        Self {
            code: EphemeralErrorCode::InvalidKey,
            summary: "The ephemeral key is missing or violates the safe identifier contract.",
        }
    }

    pub fn capacity() -> Self {
        Self {
            code: EphemeralErrorCode::Capacity,
            summary: "The ephemeral store refused the write because it is at capacity.",
        }
    }

    pub fn unavailable() -> Self {
        Self {
            code: EphemeralErrorCode::Unavailable,
            summary: "The ephemeral acceleration layer is unavailable.",
        }
    }
}

impl std::fmt::Display for EphemeralError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.summary)
    }
}

impl std::error::Error for EphemeralError {}

pub(crate) const MAX_FINGERPRINT_HEX: usize = 64;
#[cfg(feature = "valkey")]
pub(crate) const KEY_PREFIX: &str = "apex:ingest";

pub(crate) fn validate_rate_key(key: &RateLimitKey) -> Result<(), EphemeralError> {
    if !crate::is_scope_identifier(&key.namespace) || !crate::is_scope_identifier(&key.bucket) {
        return Err(EphemeralError::invalid_key());
    }
    Ok(())
}

pub(crate) fn validate_fingerprint_key(key: &FingerprintCounterKey) -> Result<(), EphemeralError> {
    if !crate::is_scope_identifier(&key.namespace)
        || key.fingerprint_hex.is_empty()
        || key.fingerprint_hex.len() > MAX_FINGERPRINT_HEX
        || !key
            .fingerprint_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EphemeralError::invalid_key());
    }
    Ok(())
}

pub(crate) fn validate_deny_key(key: &DenyHintKey) -> Result<(), EphemeralError> {
    if !crate::is_scope_identifier(&key.namespace)
        || key.identity_fingerprint_hex.is_empty()
        || key.identity_fingerprint_hex.len() > MAX_FINGERPRINT_HEX
        || !key
            .identity_fingerprint_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(EphemeralError::invalid_key());
    }
    Ok(())
}

/// Hex-encodes one variable key component so it cannot contain the `:`
/// separator used between components.
///
/// `is_scope_identifier` deliberately permits `:` inside a workspace or
/// namespace, so interpolating two such components raw would let distinct
/// scopes collapse onto one Valkey key -- for example `("a:b", "c")` and
/// `("a", "b:c")`. These keys carry per-tenant rate-limit counters and deny
/// hints, so a collision is a cross-tenant isolation failure: one workspace
/// could spend another's admission budget, or trip another's deny hint.
/// Mirrors the same defence `publisher/jetstream.rs` applies to JetStream
/// subject components.
#[cfg(feature = "valkey")]
fn encode_key_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        encoded.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    encoded
}

#[cfg(feature = "valkey")]
pub(crate) fn rate_limit_redis_key(key: &RateLimitKey) -> String {
    format!(
        "{KEY_PREFIX}:rl:{}:{}",
        encode_key_component(&key.namespace),
        encode_key_component(&key.bucket)
    )
}

#[cfg(feature = "valkey")]
pub(crate) fn fingerprint_redis_key(key: &FingerprintCounterKey) -> String {
    format!(
        "{KEY_PREFIX}:fp:{}:{}",
        encode_key_component(&key.namespace),
        encode_key_component(&key.fingerprint_hex)
    )
}

#[cfg(feature = "valkey")]
pub(crate) fn deny_hint_redis_key(key: &DenyHintKey) -> String {
    format!(
        "{KEY_PREFIX}:deny:{}:{}",
        encode_key_component(&key.namespace),
        encode_key_component(&key.identity_fingerprint_hex)
    )
}

pub(crate) fn window_secs(window: Duration) -> Result<u64, EphemeralError> {
    let secs = window
        .as_secs()
        .max(if window.subsec_nanos() > 0 { 1 } else { 0 });
    if secs == 0 {
        return Err(EphemeralError::invalid_key());
    }
    Ok(secs)
}

/// Capability-specific ephemeral operations. Product code must not obtain a
/// generic key-value client through this boundary.
///
/// Methods take `&mut self` so remote adapters can use a single connection
/// without interior mutability.
pub trait EphemeralStore: Send {
    /// Whether a fallback wrapper is currently skipping its remote primary.
    /// Plain stores are always healthy from the wrapper's perspective.
    fn accelerator_sidelined(&self) -> bool {
        false
    }

    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError>;

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError>;

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError>;

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError>;

    /// Absence means "no accelerated deny," not "authorized."
    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError>;
}
