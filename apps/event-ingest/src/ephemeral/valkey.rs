//! Valkey (Redis-protocol) adapter for non-authoritative acceleration.
//!
//! Uses only allowlisted commands (PING/INCR/GET/SET/EXPIRE). No
//! SCRIPT/EVAL/FLUSH/CONFIG. Values are counters and presence flags only.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use redis::Commands;

use super::types::{
    DenyHintKey, EphemeralError, EphemeralStore, FingerprintCounterKey, RateLimitDecision,
    RateLimitKey, deny_hint_redis_key, fingerprint_redis_key, rate_limit_redis_key,
    validate_deny_key, validate_fingerprint_key, validate_rate_key, window_secs,
};
use crate::is_scope_identifier;

/// Connection settings for the optional Valkey accelerator.
#[derive(Debug, Clone)]
pub struct ValkeyConfig {
    /// Host only (no credentials). Example: `valkey`.
    pub host: String,
    /// TLS port (plaintext is refused at the deployment profile).
    pub port: u16,
    /// ACL username (for example `apex-ingest`).
    pub username: String,
    pub password_file: PathBuf,
    pub ca_file: PathBuf,
    pub client_cert_file: PathBuf,
    pub client_key_file: PathBuf,
    /// Trusted base for secret material (same model as NATS/HTTP sinks).
    pub trusted_base: PathBuf,
}

impl ValkeyConfig {
    pub fn validate(&self) -> Result<(), EphemeralError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.contains('/')
            || self.host.contains('\\')
            || self.host.contains('@')
            || self.host.contains(':')
            || !self.host.is_ascii()
        {
            return Err(EphemeralError::invalid_key());
        }
        if self.port == 0 {
            return Err(EphemeralError::invalid_key());
        }
        if !is_scope_identifier(&self.username) {
            return Err(EphemeralError::invalid_key());
        }
        let base = self
            .trusted_base
            .canonicalize()
            .map_err(|_| EphemeralError::invalid_key())?;
        for path in [
            &self.password_file,
            &self.ca_file,
            &self.client_cert_file,
            &self.client_key_file,
        ] {
            ensure_under_base(path, &base)?;
        }
        Ok(())
    }
}

fn ensure_under_base(path: &Path, base: &Path) -> Result<(), EphemeralError> {
    let parent = path
        .parent()
        .ok_or_else(EphemeralError::invalid_key)?
        .canonicalize()
        .map_err(|_| EphemeralError::invalid_key())?;
    if !parent.starts_with(base) || path.file_name().is_none() {
        return Err(EphemeralError::invalid_key());
    }
    if path.exists() {
        let meta = fs::metadata(path).map_err(|_| EphemeralError::unavailable())?;
        if !meta.is_file() {
            return Err(EphemeralError::invalid_key());
        }
    }
    Ok(())
}

fn read_password(path: &Path) -> Result<String, EphemeralError> {
    let raw = fs::read_to_string(path).map_err(|_| EphemeralError::unavailable())?;
    let password = raw.trim();
    if password.is_empty() || password.len() > 512 || !password.is_ascii() {
        return Err(EphemeralError::invalid_key());
    }
    if password.bytes().any(|byte| byte < 0x20) {
        return Err(EphemeralError::invalid_key());
    }
    Ok(password.to_owned())
}

/// Live Valkey-backed store. Connection failures surface as `Unavailable`.
pub struct ValkeyEphemeralStore {
    connection: redis::Connection,
}

impl ValkeyEphemeralStore {
    pub fn connect(config: &ValkeyConfig) -> Result<Self, EphemeralError> {
        config.validate()?;
        let password = read_password(&config.password_file)?;
        let ca = fs::read(&config.ca_file).map_err(|_| EphemeralError::unavailable())?;
        let cert = fs::read(&config.client_cert_file).map_err(|_| EphemeralError::unavailable())?;
        let key = fs::read(&config.client_key_file).map_err(|_| EphemeralError::unavailable())?;

        // ConnectionInfo must request TLS (`rediss` scheme semantics) before
        // certificates are attached. Credentials stay out of logs and process
        // listing by loading the password from a mounted secret file.
        let connection_info = redis::ConnectionInfo {
            addr: redis::ConnectionAddr::TcpTls {
                host: config.host.clone(),
                port: config.port,
                insecure: false,
                tls_params: None,
            },
            redis: redis::RedisConnectionInfo {
                db: 0,
                username: Some(config.username.clone()),
                password: Some(password),
                protocol: Default::default(),
            },
        };
        let client = redis::Client::build_with_tls(
            connection_info,
            redis::TlsCertificates {
                client_tls: Some(redis::ClientTlsConfig {
                    client_cert: cert,
                    client_key: key,
                }),
                root_cert: Some(ca),
            },
        )
        .map_err(|_| EphemeralError::unavailable())?;
        let mut connection = client
            .get_connection_with_timeout(Duration::from_secs(3))
            .map_err(|_| EphemeralError::unavailable())?;
        let _: String = redis::cmd("PING")
            .query(&mut connection)
            .map_err(|_| EphemeralError::unavailable())?;
        Ok(Self { connection })
    }

    fn incr_with_ttl(&mut self, key: &str, ttl_secs: u64) -> Result<u64, EphemeralError> {
        // redis-rs maps INCR to INCRBY; ACL must allow both.
        let count: u64 = self
            .connection
            .incr(key, 1u64)
            .map_err(|_| EphemeralError::unavailable())?;
        if count == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query(&mut self.connection)
                .map_err(|_| EphemeralError::unavailable())?;
        }
        Ok(count)
    }
}

impl EphemeralStore for ValkeyEphemeralStore {
    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        validate_rate_key(key)?;
        if limit == 0 {
            return Err(EphemeralError::invalid_key());
        }
        let ttl = window_secs(window)?;
        let redis_key = rate_limit_redis_key(key);
        let count = self.incr_with_ttl(&redis_key, ttl)?;
        if count > u64::from(limit) {
            return Ok(RateLimitDecision {
                allowed: false,
                remaining: 0,
            });
        }
        Ok(RateLimitDecision {
            allowed: true,
            remaining: limit.saturating_sub(count as u32),
        })
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        let ttl = window_secs(window)?;
        let redis_key = fingerprint_redis_key(key);
        self.incr_with_ttl(&redis_key, ttl)
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        let redis_key = fingerprint_redis_key(key);
        let value: Option<u64> = self
            .connection
            .get(redis_key)
            .map_err(|_| EphemeralError::unavailable())?;
        Ok(value.unwrap_or(0))
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        validate_deny_key(key)?;
        let secs = window_secs(ttl)?;
        let redis_key = deny_hint_redis_key(key);
        let _: () = self
            .connection
            .set_ex(redis_key, 1u8, secs)
            .map_err(|_| EphemeralError::unavailable())?;
        Ok(())
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        validate_deny_key(key)?;
        let redis_key = deny_hint_redis_key(key);
        let value: Option<u8> = self
            .connection
            .get(redis_key)
            .map_err(|_| EphemeralError::unavailable())?;
        Ok(value.is_some())
    }
}

/// Command-level mock surface for unit tests without a live Valkey process.
#[cfg(test)]
pub(crate) trait ValkeyCommandSink {
    fn incr(&mut self, key: &str) -> Result<u64, EphemeralError>;
    fn expire(&mut self, key: &str, ttl_secs: u64) -> Result<(), EphemeralError>;
    fn get_u64(&mut self, key: &str) -> Result<Option<u64>, EphemeralError>;
    fn set_ex(&mut self, key: &str, ttl_secs: u64) -> Result<(), EphemeralError>;
    fn get_flag(&mut self, key: &str) -> Result<bool, EphemeralError>;
}

/// Test double that implements EphemeralStore over an in-process map with Redis key shapes.
#[cfg(test)]
pub(crate) struct ScriptedValkeyStore<S> {
    sink: S,
}

#[cfg(test)]
impl<S: ValkeyCommandSink> ScriptedValkeyStore<S> {
    pub(crate) fn new(sink: S) -> Self {
        Self { sink }
    }
}

#[cfg(test)]
impl<S: ValkeyCommandSink + Send> EphemeralStore for ScriptedValkeyStore<S> {
    fn check_rate_limit(
        &mut self,
        key: &RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> Result<RateLimitDecision, EphemeralError> {
        validate_rate_key(key)?;
        if limit == 0 {
            return Err(EphemeralError::invalid_key());
        }
        let ttl = window_secs(window)?;
        let redis_key = rate_limit_redis_key(key);
        let count = self.sink.incr(&redis_key)?;
        if count == 1 {
            self.sink.expire(&redis_key, ttl)?;
        }
        if count > u64::from(limit) {
            return Ok(RateLimitDecision {
                allowed: false,
                remaining: 0,
            });
        }
        Ok(RateLimitDecision {
            allowed: true,
            remaining: limit.saturating_sub(count as u32),
        })
    }

    fn increment_fingerprint(
        &mut self,
        key: &FingerprintCounterKey,
        window: Duration,
    ) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        let ttl = window_secs(window)?;
        let redis_key = fingerprint_redis_key(key);
        let count = self.sink.incr(&redis_key)?;
        if count == 1 {
            self.sink.expire(&redis_key, ttl)?;
        }
        Ok(count)
    }

    fn fingerprint_count(&mut self, key: &FingerprintCounterKey) -> Result<u64, EphemeralError> {
        validate_fingerprint_key(key)?;
        Ok(self.sink.get_u64(&fingerprint_redis_key(key))?.unwrap_or(0))
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        validate_deny_key(key)?;
        let secs = window_secs(ttl)?;
        self.sink.set_ex(&deny_hint_redis_key(key), secs)
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        validate_deny_key(key)?;
        self.sink.get_flag(&deny_hint_redis_key(key))
    }
}
