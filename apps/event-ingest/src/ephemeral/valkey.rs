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
        for (path, private) in [
            (&self.password_file, true),
            (&self.ca_file, false),
            (&self.client_cert_file, false),
            (&self.client_key_file, true),
        ] {
            ensure_under_base(path, &base, private)?;
        }
        Ok(())
    }
}

fn ensure_under_base(path: &Path, base: &Path, private: bool) -> Result<(), EphemeralError> {
    #[cfg(not(unix))]
    let _ = private;
    if path.is_symlink() {
        return Err(EphemeralError::invalid_key());
    }
    let parent = path
        .parent()
        .ok_or_else(EphemeralError::invalid_key)?
        .canonicalize()
        .map_err(|_| EphemeralError::invalid_key())?;
    if !parent.starts_with(base) || path.file_name().is_none() {
        return Err(EphemeralError::invalid_key());
    }
    let meta = fs::metadata(path).map_err(|_| EphemeralError::unavailable())?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > 1024 * 1024 {
        return Err(EphemeralError::invalid_key());
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(EphemeralError::invalid_key());
        }
    }
    Ok(())
}

fn read_password(path: &Path) -> Result<String, EphemeralError> {
    if path.is_symlink() {
        return Err(EphemeralError::invalid_key());
    }
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
    config: ValkeyConfig,
}

impl ValkeyEphemeralStore {
    pub fn connect(config: &ValkeyConfig) -> Result<Self, EphemeralError> {
        let connection = Self::build_connection(config)?;
        Ok(Self {
            connection,
            config: config.clone(),
        })
    }

    fn build_connection(config: &ValkeyConfig) -> Result<redis::Connection, EphemeralError> {
        config.validate()?;
        let password = read_password(&config.password_file)?;
        let ca = fs::read(&config.ca_file).map_err(|_| EphemeralError::unavailable())?;
        let cert = fs::read(&config.client_cert_file).map_err(|_| EphemeralError::unavailable())?;
        let key = fs::read(&config.client_key_file).map_err(|_| EphemeralError::unavailable())?;

        // ConnectionInfo must request TLS (`rediss` scheme semantics) before
        // certificates are attached. Credentials stay out of logs and process
        // listing by loading the password from a mounted secret file.
        // `ConnectionInfo`/`RedisConnectionInfo` are builder-only as of redis
        // 1.0 (their fields are private), hence `into_connection_info()` +
        // `set_redis_settings()` rather than a struct literal.
        use redis::IntoConnectionInfo;
        let connection_info = redis::ConnectionAddr::TcpTls {
            host: config.host.clone(),
            port: config.port,
            insecure: false,
            tls_params: None,
        }
        .into_connection_info()
        .map_err(|_| EphemeralError::unavailable())?
        .set_redis_settings(
            redis::RedisConnectionInfo::default()
                .set_username(&config.username)
                .set_password(&password),
        );
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
        // The connect timeout above only bounds the initial handshake. Without
        // read/write timeouts, a network blackhole (not a clean refusal) on any
        // later command blocks this connection's request thread forever while
        // holding the store's shared mutex, livelocking every caller in the
        // process. Bound every subsequent command the same way the HTTP sinks
        // bound theirs.
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| EphemeralError::unavailable())?;
        connection
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| EphemeralError::unavailable())?;
        let _: String = redis::cmd("PING")
            .query(&mut connection)
            .map_err(|_| EphemeralError::unavailable())?;
        Ok(connection)
    }

    /// A read/write timeout (or any other I/O error) can fire mid-command,
    /// leaving that command's reply unread on the wire. Reusing the same
    /// connection afterward risks a *silent* protocol desync: the next
    /// command would read the previous command's stale reply instead of its
    /// own, corrupting a rate-limit decision rather than erroring visibly.
    /// Treat every command error as poisoning the connection and reconnect
    /// before the next call. Best-effort: if reconnecting also fails, the
    /// caller's current error still surfaces as `Unavailable` and the next
    /// call tries again.
    fn reconnect(&mut self) {
        if let Ok(connection) = Self::build_connection(&self.config) {
            self.connection = connection;
        }
    }

    /// Runs one Valkey command, reconnecting on any failure so the
    /// connection is never reused in a possibly-desynced state.
    fn run<T>(
        &mut self,
        op: impl FnOnce(&mut redis::Connection) -> redis::RedisResult<T>,
    ) -> Result<T, EphemeralError> {
        match op(&mut self.connection) {
            Ok(value) => Ok(value),
            Err(_) => {
                self.reconnect();
                Err(EphemeralError::unavailable())
            }
        }
    }

    fn incr_with_ttl(&mut self, key: &str, ttl_secs: u64) -> Result<u64, EphemeralError> {
        // Establish the key's expiry before it is ever incremented, not after.
        // `SET key 0 NX EX ttl` is a single atomic round trip that only takes
        // effect the first time (a no-op once the key exists), so it never
        // resets an in-progress window. The previous order — INCR first,
        // EXPIRE only when count==1 — left a window where a crash or dropped
        // connection between the two calls created a counter with no TTL,
        // which then rate-limited its identity forever until manually cleared.
        self.run(|connection| {
            redis::cmd("SET")
                .arg(key)
                .arg(0u64)
                .arg("NX")
                .arg("EX")
                .arg(ttl_secs)
                .query::<()>(connection)
        })?;
        // redis-rs maps INCR to INCRBY; ACL must allow both.
        self.run(|connection| connection.incr(key, 1u64))
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
        let value: Option<u64> = self.run(|connection| connection.get(&redis_key))?;
        Ok(value.unwrap_or(0))
    }

    fn set_deny_hint(&mut self, key: &DenyHintKey, ttl: Duration) -> Result<(), EphemeralError> {
        validate_deny_key(key)?;
        let secs = window_secs(ttl)?;
        let redis_key = deny_hint_redis_key(key);
        self.run(|connection| connection.set_ex(&redis_key, 1u8, secs))
    }

    fn is_denied(&mut self, key: &DenyHintKey) -> Result<bool, EphemeralError> {
        validate_deny_key(key)?;
        let redis_key = deny_hint_redis_key(key);
        let value: Option<u8> = self.run(|connection| connection.get(&redis_key))?;
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
