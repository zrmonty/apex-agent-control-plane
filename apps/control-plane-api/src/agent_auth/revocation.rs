//! Background-refreshed revocation of agent workload credentials. See the
//! "Revocation" section of [`super`]'s module doc for why this exists
//! alongside the immutable static credential table.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use apex_auth::{BearerTokenResolver, Caller, GatewayError, PeerIdentity};

use super::parse_certificate_sha256;

/// How many `\n`-separated fingerprint entries [`parse_revocation_list`]
/// accepts before refusing the file outright. Sized to
/// `crate::MAX_AGENT_REVOCATION_FILE_BYTES` divided by roughly 65 bytes per
/// line (64 hex characters plus a newline), the same way `MAX_AGENT_TOKEN_ENTRIES`
/// is sized against `MAX_AGENT_TABLE_BYTES` for the credential table.
const MAX_REVOCATION_ENTRIES: usize = 4096;

/// Retry sooner than the configured refresh interval after a failed read,
/// mirroring `keycloak::JWKS_RETRY_DELAY` -- so a transient failure (an
/// operator's editor doing a non-atomic save, or the file being briefly
/// absent mid-rotation) does not have to wait a full interval before trying
/// again.
const REVOCATION_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Background-refreshed cache of revoked agent certificate fingerprints.
///
/// # Why this exists
///
/// [`StaticAgentWorkloadResolver`]/[`parse_agent_token_table`] build a table
/// exactly once, at process startup, from `APEX_CONTROL_AGENT_TOKENS[_FILE]`.
/// That table never changes for the life of the process. If one agent's mTLS
/// client key and bearer token are compromised -- the host it runs on is
/// compromised, which is precisely the class of incident this gateway's
/// cooperative controls exist to let an operator respond to -- the only way
/// to revoke *that one credential* today is to edit the env var and
/// restart/redeploy the whole process. For a control plane whose purpose is
/// "regain control of a compromised or misbehaving agent quickly", a
/// revocation path bounded by a redeploy cycle is the gap this type closes.
///
/// # Shape
///
/// Structurally the mirror of [`crate::keycloak`]'s `JwksCache` /
/// `spawn_jwks_refresher`, deliberately: a background thread re-reads a file
/// on a short interval, and every successful read **replaces** the cached set
/// wholesale rather than merging into it. A fingerprint an operator removes
/// from the file -- un-revoking a credential, or cleaning the file up after an
/// incident -- stops being revoked one refresh later; it is never "sticky"
/// from an earlier read the way a merge would leave it.
///
/// # Fail-closed direction
///
/// This is the judgment call that matters most here, and it points the
/// *opposite* way from "just stop checking revocation". Once the cache is
/// older than `max_age` -- because the file became unreadable or the
/// refresher thread died -- [`RevocationAwareAgentResolver`] refuses **every**
/// agent credential, not only the ones that were ever listed.
///
/// A stale cache does not mean "no revocations are known"; it means
/// "revocations of unknown recency are known", and those are not the same
/// thing to trust. Treating a stale cache as equivalent to "nothing is
/// revoked" would silently reopen the exact gap this feature exists to close:
/// a credential revoked five minutes ago, while refreshes were failing, would
/// keep authenticating as if the incident had never been reported. Trusting
/// the last known-good set forever has the same flaw on a longer timer.
/// Refusing everyone is *stricter* than "revocation checking is off" --
/// an agent whose credential was never revoked is refused too, for as long as
/// the cache stays stale -- and that asymmetry is deliberate: a gateway whose
/// entire purpose is regaining control of a compromised agent quickly must
/// bias toward wrongly refusing a clean agent during an outage over wrongly
/// admitting a revoked one, because only the second failure is the one an
/// attacker benefits from. This is exactly the rule
/// `keycloak::jwks::JwksCache::fresh` already applies to operator credentials;
/// nothing about the reasoning changes for agent ones.
pub struct AgentRevocationList {
    cache: Arc<RwLock<RevocationCache>>,
    max_age: Duration,
}

#[derive(Debug, Default)]
struct RevocationCache {
    fingerprints: Option<HashSet<[u8; 32]>>,
    fetched_at: Option<Instant>,
}

impl RevocationCache {
    fn store(&mut self, fingerprints: HashSet<[u8; 32]>) {
        self.fingerprints = Some(fingerprints);
        self.fetched_at = Some(Instant::now());
    }

    /// The cached set, or `None` when it is absent or older than `max_age`.
    /// Absence is what makes [`AgentRevocationList`] fail closed -- see its
    /// doc for why that is the correct direction here.
    fn fresh(&self, max_age: Duration) -> Option<&HashSet<[u8; 32]>> {
        match (&self.fingerprints, self.fetched_at) {
            (Some(set), Some(at)) if at.elapsed() <= max_age => Some(set),
            _ => None,
        }
    }
}

/// Why an `APEX_CONTROL_AGENT_REVOCATION_FILE` could not be started, or its
/// tuning was refused. Static reasons only -- the configured path never
/// appears, the same redaction discipline `KeycloakConfigError` follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRevocationError(&'static str);

impl std::fmt::Display for AgentRevocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "agent revocation list configuration was refused: {}",
            self.0
        )
    }
}

impl std::error::Error for AgentRevocationError {}

/// Parses the revocation file body: one hex-encoded SHA-256 certificate
/// fingerprint per line -- the same 64-character hex form
/// `parse_certificate_sha256` already accepts for `expected_peer_certificate`
/// in the `APEX_CONTROL_AGENT_TOKENS` table, so revoking a credential is
/// "copy the fingerprint you already have into this file".
///
/// Blank lines are skipped. That is also how an operator represents "the
/// feature is armed, nothing is currently revoked" -- a genuinely empty
/// (zero-byte) file is refused before this function ever runs, by the
/// `trusted_secret_path` check `startup::service` applies to every configured
/// secret path, because a zero-byte file at a configured path reads the same
/// as a secret mount that was never actually populated, and this feature must
/// not silently no-op in that case.
///
/// Any other malformed line is a hard error, never a skip. `parse_agent_token_table`
/// follows the same rule for the credential table, and it matters even more
/// here: silently dropping one bad line out of many would leave an operator
/// believing a specific credential had been revoked when it had not.
pub(super) fn parse_revocation_list(raw: &str) -> Result<HashSet<[u8; 32]>, AgentRevocationError> {
    let mut fingerprints = HashSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if fingerprints.len() >= MAX_REVOCATION_ENTRIES {
            return Err(AgentRevocationError(
                "the revocation file lists too many fingerprints",
            ));
        }
        let fingerprint = parse_certificate_sha256(line).ok_or(AgentRevocationError(
            "the revocation file contains a line that is not a 64-character hexadecimal SHA-256 fingerprint",
        ))?;
        fingerprints.insert(fingerprint);
    }
    Ok(fingerprints)
}

/// Reads and parses the revocation file. Bounded the same way every other
/// secret/config file this crate reads is: `max_bytes + 1` are read so an
/// over-limit file is detected instead of silently truncated into something
/// that still parses.
fn read_revocation_file(
    path: &Path,
    max_bytes: usize,
) -> Result<HashSet<[u8; 32]>, AgentRevocationError> {
    let file = std::fs::File::open(path)
        .map_err(|_| AgentRevocationError("unable to read the configured agent revocation file"))?;
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AgentRevocationError("unable to read the configured agent revocation file"))?;
    if bytes.len() > max_bytes {
        return Err(AgentRevocationError(
            "the configured agent revocation file exceeds the size ceiling",
        ));
    }
    let raw = String::from_utf8(bytes)
        .map_err(|_| AgentRevocationError("the configured agent revocation file is not UTF-8"))?;
    parse_revocation_list(&raw)
}

impl AgentRevocationList {
    /// Validates the refresh/staleness relationship, performs the
    /// **required** first read, and starts the background refresher.
    ///
    /// Unlike `KeycloakOperatorCredentialResolver::start`, whose first JWKS
    /// fetch is a warning rather than a startup failure -- Keycloak is a
    /// network dependency this gateway must tolerate being briefly
    /// unreachable, per ADR-0006 -- the revocation file is local,
    /// operator-owned configuration, not an external service. There is no
    /// "briefly unreachable" case to tolerate here, only "the path is wrong"
    /// or "the file was never actually provisioned". A configured-but-unreadable
    /// path must therefore fail startup loudly rather than silently come up
    /// with revocation disabled: an operator who believes they turned on a
    /// safety feature must never discover, mid-incident, that a typo silently
    /// turned it off instead.
    pub fn start(
        path: PathBuf,
        refresh: Duration,
        max_age: Duration,
    ) -> Result<Self, AgentRevocationError> {
        if refresh.is_zero() {
            return Err(AgentRevocationError(
                "the revocation refresh interval must be positive",
            ));
        }
        if max_age < refresh {
            return Err(AgentRevocationError(
                "the revocation staleness ceiling must be at least the refresh interval",
            ));
        }
        let initial = read_revocation_file(&path, crate::MAX_AGENT_REVOCATION_FILE_BYTES)?;
        let cache = Arc::new(RwLock::new(RevocationCache::default()));
        {
            let mut guard = cache.write().map_err(|_| {
                AgentRevocationError("could not initialize the agent revocation cache")
            })?;
            guard.store(initial);
        }
        spawn_revocation_refresher(path, refresh, Arc::downgrade(&cache));
        Ok(Self { cache, max_age })
    }

    /// Builds a list over an already-known set, with no background thread and
    /// no file. Tests only -- a deployment must be able to pick up a file edit
    /// without a restart.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_static_revocations(
        fingerprints: impl IntoIterator<Item = [u8; 32]>,
        max_age: Duration,
    ) -> Self {
        let mut cache = RevocationCache::default();
        cache.store(fingerprints.into_iter().collect());
        Self {
            cache: Arc::new(RwLock::new(cache)),
            max_age,
        }
    }

    /// True once fingerprints have been loaded and the cache is still inside
    /// its staleness ceiling. Exposed for the same reason
    /// `KeycloakOperatorCredentialResolver::keys_are_fresh` is: so a test can
    /// wait for readiness instead of racing the first read.
    pub fn is_fresh(&self) -> bool {
        self.cache
            .read()
            .is_ok_and(|cache| cache.fresh(self.max_age).is_some())
    }

    /// Checks one certificate fingerprint against the current revocation set.
    ///
    /// `Err(())` means "the cache is stale or unreadable, so this question
    /// cannot be answered right now" -- see this type's doc for why every
    /// caller must treat that as a refusal, never as "not revoked".
    pub(super) fn check(&self, fingerprint: &[u8; 32]) -> Result<bool, ()> {
        let cache = self.cache.read().map_err(|_| ())?;
        let fresh = cache.fresh(self.max_age).ok_or(())?;
        Ok(fresh.contains(fingerprint))
    }
}

/// Replaces the whole cached set on every successful refresh -- never merges.
/// See [`AgentRevocationList`]'s doc for why replacement, not merge, is the
/// point: an un-revoked (removed) fingerprint must stop being refused one
/// refresh later, the same way a rotated-away JWKS key stops verifying one
/// refresh later.
fn spawn_revocation_refresher(
    path: PathBuf,
    refresh: Duration,
    cache: Weak<RwLock<RevocationCache>>,
) {
    let mut delay = refresh;
    let spawned = std::thread::Builder::new()
        .name("apex-control-agent-revocation".to_owned())
        .spawn(move || {
            loop {
                std::thread::sleep(delay);
                // The list has been dropped: stop, rather than keep a
                // process-lifetime thread alive per constructed list.
                let Some(cache) = cache.upgrade() else {
                    return;
                };
                match read_revocation_file(&path, crate::MAX_AGENT_REVOCATION_FILE_BYTES) {
                    Ok(fingerprints) => {
                        if let Ok(mut guard) = cache.write() {
                            guard.store(fingerprints);
                        }
                        delay = refresh;
                    }
                    Err(reason) => {
                        eprintln!(
                            "control-plane-api: agent revocation file refresh failed ({reason}); cached revocations expire at the configured max age"
                        );
                        delay = REVOCATION_RETRY_DELAY.min(refresh);
                    }
                }
            }
        });
    if spawned.is_err() {
        eprintln!(
            "control-plane-api: could not start the agent revocation refresher; cached revocations will expire and every agent credential will then be refused"
        );
    }
}

/// Applies [`AgentRevocationList`] to any agent workload resolver, checked
/// **in addition to**, never instead of, every existing check the wrapped
/// resolver performs (peer certificate presence, the token-digest lookup, the
/// pinned-certificate match). Deliberately a wrapper rather than a change to
/// [`StaticAgentWorkloadResolver`] itself: the static table stays exactly what
/// it always was, and every one of its existing tests keeps testing exactly
/// what it always tested.
pub struct RevocationAwareAgentResolver<R: BearerTokenResolver> {
    inner: R,
    revocations: AgentRevocationList,
}

impl<R: BearerTokenResolver> RevocationAwareAgentResolver<R> {
    pub fn new(inner: R, revocations: AgentRevocationList) -> Self {
        Self { inner, revocations }
    }
}

impl<R: BearerTokenResolver> BearerTokenResolver for RevocationAwareAgentResolver<R> {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
        // No peer certificate means nothing to check revocation against, and
        // every resolver in this crate already refuses peer-less resolution
        // outright -- delegating preserves that rather than reimplementing it.
        self.inner.resolve(token)
    }

    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        // Every existing check runs first and unmodified: an unregistered
        // token, a token presented with the wrong certificate, and a missing
        // peer identity all still refuse exactly as they did before this
        // wrapper existed. Revocation is checked in addition to those, never
        // instead of them.
        let caller = self.inner.resolve_with_peer(token, peer)?;
        let Some(peer) = peer else {
            // Unreachable in practice: `inner.resolve_with_peer` above already
            // refuses a caller with no peer identity, for every resolver this
            // crate ships. Kept explicit and fail-closed rather than
            // `unreachable!()`, so a future resolver that forgets that rule
            // fails safely here too instead of skipping the revocation check.
            return Err(GatewayError::unauthenticated());
        };
        match self.revocations.check(&peer.certificate_sha256) {
            Ok(false) => Ok(caller),
            Ok(true) => Err(GatewayError::unauthenticated()),
            // The cache is stale: fail closed. See `AgentRevocationList`'s doc
            // for why this is the correct direction.
            Err(()) => Err(GatewayError::unauthenticated()),
        }
    }
}
