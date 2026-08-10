//! Agent-workload authentication for `PollCommands`.
//!
//! This is a **third** credential space in this process, and that is the
//! point. `auth.rs` verifies an *operator* -- the principal authorized to
//! issue a `stop`. This module verifies an *agent workload* -- the principal
//! authorized to retrieve the commands issued against it, and nothing else.
//! ADR-0006 draws exactly this line, and reusing `OperatorCredentialResolver`
//! here would erase it: an operator token would become a way to read every
//! agent's pending commands, and an agent credential would become a way to
//! issue them.
//!
//! **Reused, not forked.** The verification stack is `apex_event_ingest`'s
//! own workload-identity model, unmodified:
//!
//! - [`apex_event_ingest::BearerTokenVerifier`] in *strict* mode does the
//!   `authorization` header parsing, the fail-closed check that a TLS peer
//!   certificate is present at all, and the per-(token, peer-certificate)
//!   failure budget.
//! - [`apex_event_ingest::BearerTokenResolver::resolve_with_peer`] is the seam
//!   a resolver implements, and its default implementation *refuses* any
//!   resolver that has not explicitly opted into certificate binding -- so a
//!   resolver that forgets to pin cannot silently be used on the strict path.
//! - [`apex_event_ingest::Caller::authenticated_for_agent`] is what produces
//!   the bound identity, applying the same `is_scope_identifier` grammar to
//!   the agent id and scopes that the ingest data path applies.
//!
//! The only thing written here is the credential *table* (this crate's own
//! configuration surface, keyed by this crate's own environment variables) and
//! the peer-certificate extraction, which `event-ingest` keeps `pub(crate)`.
//! See the module note on [`peer_identity_from_request`].
//!
//! # Revocation
//!
//! The table above is immutable for the life of the process: it is built
//! exactly once, at startup, from `APEX_CONTROL_AGENT_TOKENS[_FILE]`, and
//! never changes afterward. [`AgentRevocationList`] closes the gap that
//! leaves: if one agent's mTLS client key and bearer token are compromised --
//! the host running that agent is compromised, precisely the incident this
//! gateway's `stop`/`pause`/`inject` controls exist to respond to -- an
//! operator needs to revoke *that one credential* faster than an env-var edit
//! plus a redeploy. It background-refreshes a set of revoked certificate
//! fingerprints from a file, structurally the same shape as
//! [`crate::keycloak`]'s `JwksCache`/`spawn_jwks_refresher`: wholesale
//! replacement on every successful read, and fail-closed once the cache is
//! older than a configured ceiling. [`RevocationAwareAgentResolver`] applies
//! it to any [`BearerTokenResolver`] -- including
//! [`StaticAgentWorkloadResolver`] -- without changing that type.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use apex_event_ingest::{
    BearerTokenResolver, BearerTokenVerifier, Caller, CallerVerifier, GatewayError,
    GatewayErrorCode, PeerIdentity,
};
use sha2::{Digest, Sha256};

use crate::errors::CommandError;

/// Field separator inside one `APEX_CONTROL_AGENT_TOKENS` entry.
///
/// Same character and the same reasoning as `auth.rs`'s operator table: the
/// three fields to the right of the token (certificate fingerprint, agent id,
/// scopes) are drawn from grammars that provably cannot contain `|`, so
/// splitting from the right recovers a token containing the separator intact
/// rather than silently registering a truncated secret.
const AGENT_ENTRY_SEPARATOR: char = '|';
const MIN_AGENT_TOKEN_BYTES: usize = 16;
const MAX_AGENT_TOKEN_BYTES: usize = 4096;
const MAX_AGENT_TOKEN_ENTRIES: usize = 1024;
const MAX_AGENT_SCOPES: usize = 64;

/// One registered agent workload credential.
#[derive(Debug, Clone)]
struct AgentWorkloadEntry {
    /// SHA-256 of the DER client certificate this credential is pinned to. A
    /// bearer token alone is not sufficient: a leaked token is unusable
    /// without the matching mTLS client key, which is the property
    /// `event-ingest`'s file bearer already relies on.
    expected_peer_certificate: [u8; 32],
    subject: String,
    agent_id: String,
    scopes: Vec<String>,
}

/// A static, in-process agent workload credential table.
///
/// The lab/CI seam, exactly as `StaticOperatorTokenResolver` is for operators.
/// A production deployment issues these through the same workload-identity
/// machinery that mints the ingest workload's credential; this crate's
/// verification boundary is unchanged either way, because it is
/// `event-ingest`'s.
pub struct StaticAgentWorkloadResolver {
    entries: HashMap<[u8; 32], AgentWorkloadEntry>,
}

impl StaticAgentWorkloadResolver {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Registers one credential. The raw token is hashed immediately; only the
    /// digest is retained.
    pub fn with_credential(
        mut self,
        token: &str,
        expected_peer_certificate: [u8; 32],
        subject: impl Into<String>,
        agent_id: impl Into<String>,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.entries.insert(
            Sha256::digest(token.as_bytes()).into(),
            AgentWorkloadEntry {
                expected_peer_certificate,
                subject: subject.into(),
                agent_id: agent_id.into(),
                scopes: scopes.into_iter().map(Into::into).collect(),
            },
        );
        self
    }
}

impl Default for StaticAgentWorkloadResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BearerTokenResolver for StaticAgentWorkloadResolver {
    /// Peer-less resolution is refused outright.
    ///
    /// `BearerTokenResolver`'s default `resolve_with_peer` already fails
    /// closed when a peer identity is present and the resolver has not
    /// implemented binding; this closes the other direction, so a resolver
    /// wired into a non-TLS seam by mistake authenticates nobody rather than
    /// degrading to bearer-only.
    fn resolve(&self, _token: &str) -> Result<Caller, GatewayError> {
        Err(GatewayError::unauthenticated())
    }

    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        let peer = peer.ok_or_else(GatewayError::unauthenticated)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let entry = self
            .entries
            .get(&digest)
            .ok_or_else(GatewayError::unauthenticated)?;
        // Constant-time-ish: both operands are fixed-size digests and the
        // comparison is over public certificate material, not the secret. The
        // secret comparison already happened as a hash-map lookup on a
        // SHA-256 digest.
        if entry.expected_peer_certificate != peer.certificate_sha256 {
            return Err(GatewayError::unauthenticated());
        }
        Caller::authenticated_for_agent(
            entry.subject.clone(),
            entry.agent_id.clone(),
            entry.scopes.iter().cloned(),
        )
    }
}

/// Why an `APEX_CONTROL_AGENT_TOKENS` value was refused. The entry index is
/// included so an operator can find the bad entry; the token itself never
/// appears in this type, its `Debug`, or its `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentTokenTableError {
    pub entry_index: usize,
    pub reason: &'static str,
}

impl std::fmt::Display for AgentTokenTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "APEX_CONTROL_AGENT_TOKENS entry {}: {}",
            self.entry_index, self.reason
        )
    }
}

impl std::error::Error for AgentTokenTableError {}

/// The subject an agent workload credential authenticates as.
///
/// Deliberately the same spelling `event-ingest`'s file bearer produces for
/// the same workload (`startup/auth.rs::default_bearer_subject`), so one agent
/// reads identically in the ingest audit trail and in this gateway's poll
/// rate-limit accounting rather than appearing as two unrelated principals.
pub fn agent_workload_subject(agent_id: &str) -> String {
    format!("spiffe://apex/workload/{agent_id}")
}

/// Parses the `APEX_CONTROL_AGENT_TOKENS` credential table:
/// `token|cert_sha256|agent_id|workspace/ns[,workspace/ns...];...`
///
/// Every malformed entry is a hard error, the same rule the operator table
/// follows: silently skipping one would leave an agent unable to receive a
/// `stop` while the gateway still starts and reports healthy, which is the
/// precise failure this whole work item exists to remove.
///
/// There is no `*` wildcard here and there must never be one. A global
/// operator scope is a break-glass concept for a human; an agent workload has
/// exactly one agent id and a bounded set of scopes, and a wildcard would make
/// one compromised agent credential able to retrieve every other agent's
/// commands.
pub fn parse_agent_token_table(
    raw: &str,
) -> Result<StaticAgentWorkloadResolver, AgentTokenTableError> {
    let mut resolver = StaticAgentWorkloadResolver::new();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for (entry_index, entry) in raw
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .enumerate()
    {
        let fail = |reason: &'static str| AgentTokenTableError {
            entry_index,
            reason,
        };
        if entry_index >= MAX_AGENT_TOKEN_ENTRIES {
            return Err(fail("too many agent token entries"));
        }
        // Split from the right three times: the certificate fingerprint is
        // hex, the agent id and scopes are drawn from the identifier grammar
        // plus `/` and `,`, and none of those can contain the separator. So
        // whatever remains on the left is the whole token, separators and all.
        let mut fields = entry.rsplitn(4, AGENT_ENTRY_SEPARATOR);
        let scopes = fields.next().unwrap_or_default().trim();
        let Some(agent_id) = fields.next().map(str::trim) else {
            return Err(fail(
                "expected token|cert_sha256|agent_id|scopes",
            ));
        };
        let Some(certificate_hex) = fields.next().map(str::trim) else {
            return Err(fail(
                "expected token|cert_sha256|agent_id|scopes",
            ));
        };
        let Some(token) = fields.next() else {
            return Err(fail(
                "expected token|cert_sha256|agent_id|scopes",
            ));
        };
        if token.len() < MIN_AGENT_TOKEN_BYTES {
            return Err(fail("agent token is shorter than 16 bytes"));
        }
        if token.len() > MAX_AGENT_TOKEN_BYTES {
            return Err(fail("agent token is longer than 4096 bytes"));
        }
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(fail(
                "agent token must be printable ASCII with no whitespace",
            ));
        }
        let expected_peer_certificate = parse_certificate_sha256(certificate_hex)
            .ok_or_else(|| fail("cert_sha256 must be exactly 64 hexadecimal characters"))?;
        if scopes.contains('*') || agent_id.contains('*') {
            return Err(fail(
                "an agent workload credential has no wildcard form; list the agent id and its scopes explicitly",
            ));
        }
        let parsed_scopes: Vec<&str> = scopes
            .split(',')
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .collect();
        if parsed_scopes.is_empty() {
            return Err(fail("no scopes listed"));
        }
        if parsed_scopes.len() > MAX_AGENT_SCOPES {
            return Err(fail("too many scopes for one agent credential"));
        }
        // `Caller::authenticated_for_agent` applies `event-ingest`'s own
        // `is_scope_identifier` grammar to the agent id and every scope, so a
        // credential that could never produce a usable identity is refused
        // here rather than at every poll.
        Caller::authenticated_for_agent(
            agent_workload_subject(agent_id),
            agent_id,
            parsed_scopes.iter().copied(),
        )
        .map_err(|_| fail("invalid agent_id or scope; expected workspace/namespace pairs"))?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if !seen.insert(digest) {
            return Err(fail("duplicate agent token"));
        }
        resolver = resolver.with_credential(
            token,
            expected_peer_certificate,
            agent_workload_subject(agent_id),
            agent_id,
            parsed_scopes,
        );
    }
    Ok(resolver)
}

/// Naming convention for a process supervisor's own agent-workload identity.
///
/// `apps/agent-supervisor` wraps and spawns one agent (`agent_id`) as its OS
/// child, and separately polls `PollCommands` for `force_stop` using its
/// *own* credential -- registered in `APEX_CONTROL_AGENT_TOKENS` under this
/// derived agent_id, with its own token and its own pinned client
/// certificate, never the wrapped agent's.
///
/// This function does not gate or enforce anything here; the table format
/// already supports an arbitrary `agent_id` with its own credential, so no
/// change to [`parse_agent_token_table`] was needed to give the supervisor a
/// distinct identity. What this function fixes is the *naming convention*
/// deployments should use when provisioning that second credential, so a
/// supervisor's identity is recognizable as "the supervisor for run X" at a
/// glance in the credential table, the audit trail, and the
/// `APEX_CONTROL_AGENT_TOKENS` file -- rather than each deployment inventing
/// its own ad hoc suffix.
///
/// **Why the identity must be distinct at all**, not merely differently
/// named: if the supervisor authenticated `PollCommands` with the *same*
/// credential as the agent it wraps, a fully compromised agent process (the
/// AMSI-bypass scenario `Defense-Evasion Interception.md` documents) could
/// read that credential out of its own environment or process memory and
/// poll-and-ack its own `force_stop` before the supervisor's poll loop ever
/// saw it -- exactly the finding
/// `OOB Control Gateway — Command Delivery Gap.md` describes for the
/// cooperative `stop` on a host an attacker already controls. A `force_stop`
/// is only a real backstop if the credential that can retrieve it is one the
/// agent process this is meant to kill never has access to. See
/// `apps/agent-supervisor`'s crate docs for how that separation is enforced
/// on the spawn side (`env_clear()` plus an explicit re-add allowlist).
///
/// A single `.` separator, not `:` or `/`: `is_identifier` (this module) and
/// the ingest boundary's `is_scope_identifier` both accept `.` in an agent
/// id, and `is_identifier` refuses `".."`, so `"{agent_id}.supervisor"` can
/// never collide with a legitimate two-segment identifier scheme an operator
/// might otherwise choose for `agent_id` itself.
pub fn supervisor_agent_id(agent_id: &str) -> String {
    format!("{agent_id}.supervisor")
}

fn parse_certificate_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

/// The runtime-selected agent resolver a deployment ends up with, erased the
/// same way `BoxedOperatorCredentialResolver` is and for the same reason: the
/// implementations are different types, and `ControlGatewayService` must not
/// grow a second type parameter for a choice made once at startup.
///
/// A newtype rather than a bare `Box<dyn BearerTokenResolver>` because
/// `BearerTokenResolver` is `event-ingest`'s trait and `Box` is `std`'s, so the
/// orphan rule forbids implementing one for the other from here. The operator
/// side gets away with a plain alias only because its trait is local.
pub struct BoxedAgentWorkloadResolver(Box<dyn BearerTokenResolver>);

impl BoxedAgentWorkloadResolver {
    pub fn new<R: BearerTokenResolver>(resolver: R) -> Self {
        Self(Box::new(resolver))
    }
}

impl BearerTokenResolver for BoxedAgentWorkloadResolver {
    fn resolve(&self, token: &str) -> Result<Caller, GatewayError> {
        self.0.resolve(token)
    }

    fn resolve_with_peer(
        &self,
        token: &str,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, GatewayError> {
        self.0.resolve_with_peer(token, peer)
    }
}

/// Verifies an agent workload's credential on the `PollCommands` path.
///
/// A thin adapter over `event-ingest`'s `BearerTokenVerifier` in strict mode:
/// this type owns no verification logic of its own, only the translation of
/// `GatewayError` into this crate's redacted `CommandError` taxonomy.
pub struct AgentWorkloadAuthenticator<R: BearerTokenResolver> {
    verifier: BearerTokenVerifier<R>,
}

impl<R: BearerTokenResolver> AgentWorkloadAuthenticator<R> {
    /// Strict by construction. There is no non-strict constructor: this
    /// gateway serves mTLS with `client_auth_optional(false)` and has no
    /// plaintext mode, so a verifier that would accept a caller with no peer
    /// certificate could only ever be a mistake.
    pub fn new(resolver: R) -> Self {
        Self {
            verifier: BearerTokenVerifier::new_strict(resolver),
        }
    }

    pub fn authenticate(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        peer: Option<&PeerIdentity>,
    ) -> Result<Caller, CommandError> {
        self.verifier
            .verify_with_peer(metadata, peer)
            .map_err(|error| map_agent_auth_error(&error))
    }
}

/// Maps `event-ingest`'s auth taxonomy onto this crate's.
///
/// Not `CommandError::from_gateway_error`: that function's fallback arm is
/// `InvalidCommand`, which is the right default for an envelope-validation
/// failure and exactly the wrong one for an authentication failure -- it would
/// turn "your credential is not valid" into "your request was malformed" and
/// hand a prober a distinguishable response.
fn map_agent_auth_error(error: &GatewayError) -> CommandError {
    match error.code {
        GatewayErrorCode::InvalidAuthorization => CommandError::invalid_authorization(),
        GatewayErrorCode::RateLimited | GatewayErrorCode::AdmissionBusy => {
            CommandError::rate_limited()
        }
        GatewayErrorCode::Internal => CommandError::internal(),
        // Everything else on this path is "the credential did not check out".
        // Deliberately uniform: an unknown token, a token presented with the
        // wrong client certificate, and a token whose entry is malformed must
        // be indistinguishable from outside.
        _ => CommandError::unauthenticated(),
    }
}

/// Derives the TLS peer identity of an incoming request.
///
/// `apex_event_ingest::PeerIdentity::from_request` does exactly this, but is
/// `pub(crate)` there, and these passes deliberately only *read*
/// `apps/event-ingest`. The public `PeerIdentity` type it produces is reused
/// verbatim, so the fingerprint this returns is the same value
/// `BearerTokenVerifier` and every `BearerTokenResolver` already reason about
/// -- only the extraction is restated.
///
/// **Flagged for the owner:** widening `PeerIdentity::from_request` to `pub`
/// would remove this restatement. Not done here for the same reason
/// `PostgresOutbox`'s fixed table name was left alone: it means editing
/// `event-ingest`.
pub fn peer_identity_from_request<T>(request: &tonic::Request<T>) -> Option<PeerIdentity> {
    // Test seam, compiled out of the released binary. `TlsConnectInfo` is
    // populated by tonic's TLS acceptor and cannot be constructed by a test,
    // so an in-process test of the poll path would otherwise have no way to
    // present a client certificate at all -- and the scoping assertions are
    // worth more than the absence of this branch. It is not reachable from the
    // wire: request extensions are set by the transport, never by a client.
    #[cfg(feature = "test-support")]
    if let Some(injected) = request.extensions().get::<PeerIdentity>() {
        return Some(injected.clone());
    }
    let certs = request
        .extensions()
        .get::<tonic::transport::server::TlsConnectInfo<tonic::transport::server::TcpConnectInfo>>()?
        .peer_certs()?;
    let leaf = certs.first()?;
    Some(PeerIdentity {
        certificate_sha256: Sha256::digest(leaf.as_ref()).into(),
    })
}

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
/// `keycloak::JwksCache::fresh` already applies to operator credentials;
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
        write!(f, "agent revocation list configuration was refused: {}", self.0)
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
fn parse_revocation_list(raw: &str) -> Result<HashSet<[u8; 32]>, AgentRevocationError> {
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
    let file = std::fs::File::open(path).map_err(|_| {
        AgentRevocationError("unable to read the configured agent revocation file")
    })?;
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
    fn check(&self, fingerprint: &[u8; 32]) -> Result<bool, ()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata_with_auth(value: &str) -> tonic::metadata::MetadataMap {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("authorization", value.parse().unwrap());
        metadata
    }

    fn peer(byte: u8) -> PeerIdentity {
        PeerIdentity {
            certificate_sha256: [byte; 32],
        }
    }

    fn hex32(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    fn table() -> StaticAgentWorkloadResolver {
        parse_agent_token_table(&format!(
            "agent-a-token-abcdefgh|{}|agent-a|acme/prod;agent-b-token-abcdefgh|{}|agent-b|acme/prod",
            hex32(0xaa),
            hex32(0xbb)
        ))
        .expect("well-formed agent table must parse")
    }

    #[test]
    fn authenticates_an_agent_and_binds_it_to_its_own_identity() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let caller = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xaa)),
            )
            .expect("a registered agent credential must authenticate");
        assert_eq!(caller.bound_agent_id(), Some("agent-a"));
        assert_eq!(caller.subject(), Some("spiffe://apex/workload/agent-a"));
        assert!(caller.allows_scope("acme/prod"));
        assert!(!caller.allows_scope("acme/staging"));
    }

    /// The token alone is not the credential. A leaked agent token presented
    /// from a connection holding a different client certificate must not
    /// authenticate -- this is the property that makes the mTLS layer
    /// load-bearing rather than decorative.
    #[test]
    fn refuses_a_valid_token_presented_with_the_wrong_client_certificate() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let error = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xbb)),
            )
            .expect_err("a token must not authenticate off its pinned certificate");
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
    }

    /// Agent B's certificate plus agent B's token authenticates as agent B and
    /// nothing else. Combined with the `PollCommands` scoping test in
    /// `service.rs`, this is the cross-tenant isolation claim.
    #[test]
    fn each_credential_authenticates_as_exactly_one_agent() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let caller = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-b-token-abcdefgh"),
                Some(&peer(0xbb)),
            )
            .unwrap();
        assert_eq!(caller.bound_agent_id(), Some("agent-b"));
    }

    #[test]
    fn refuses_a_caller_with_no_peer_certificate() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let error = auth
            .authenticate(&metadata_with_auth("Bearer agent-a-token-abcdefgh"), None)
            .expect_err("strict mode must refuse a caller with no client certificate");
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
    }

    #[test]
    fn refuses_an_unregistered_token() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let error = auth
            .authenticate(&metadata_with_auth("Bearer not-a-real-token"), Some(&peer(0xaa)))
            .unwrap_err();
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
    }

    #[test]
    fn refuses_missing_and_duplicate_authorization_headers() {
        let auth = AgentWorkloadAuthenticator::new(table());
        let empty = tonic::metadata::MetadataMap::new();
        assert_eq!(
            auth.authenticate(&empty, Some(&peer(0xaa))).unwrap_err().code,
            crate::errors::CommandErrorCode::Unauthenticated
        );
        let mut duplicate = tonic::metadata::MetadataMap::new();
        duplicate.append("authorization", "Bearer a-token-abcdefghij".parse().unwrap());
        duplicate.append("authorization", "Bearer b-token-abcdefghij".parse().unwrap());
        assert_eq!(
            auth.authenticate(&duplicate, Some(&peer(0xaa)))
                .unwrap_err()
                .code,
            crate::errors::CommandErrorCode::InvalidAuthorization
        );
    }

    /// The verifier's per-identity failure budget has to actually be reached
    /// through this adapter, or a credential-stuffing attempt against the poll
    /// endpoint is unthrottled.
    #[test]
    fn rate_limits_repeated_failures_for_the_same_credential() {
        let auth = AgentWorkloadAuthenticator::new(StaticAgentWorkloadResolver::new());
        let mut saw_rate_limit = false;
        for _ in 0..256 {
            if auth
                .authenticate(&metadata_with_auth("Bearer guess-guess-guess"), Some(&peer(1)))
                .unwrap_err()
                .code
                == crate::errors::CommandErrorCode::RateLimited
            {
                saw_rate_limit = true;
                break;
            }
        }
        assert!(
            saw_rate_limit,
            "repeated agent auth failures must eventually be rate-limited"
        );
    }

    #[test]
    fn table_preserves_a_token_that_contains_the_separator_character() {
        let token = "abcdefgh|ijklmnop|qrstuvwx";
        let resolver =
            parse_agent_token_table(&format!("{token}|{}|agent-a|acme/prod", hex32(0x11)))
                .expect("entry must parse");
        assert!(
            resolver
                .resolve_with_peer(token, Some(&peer(0x11)))
                .is_ok(),
            "the whole token must resolve"
        );
        // No prefix of the token may authenticate.
        assert!(resolver.resolve_with_peer("abcdefgh", Some(&peer(0x11))).is_err());
        assert!(
            resolver
                .resolve_with_peer("abcdefgh|ijklmnop", Some(&peer(0x11)))
                .is_err()
        );
    }

    #[test]
    fn table_fails_closed_on_every_malformed_entry() {
        let good = hex32(0x22);
        for (raw, why) in [
            ("no-separators-at-all".to_owned(), "missing separators"),
            (format!("short|{good}|agent-a|acme/prod"), "token under the floor"),
            (
                format!("agent-token-abcdefgh|{good}|agent-a|not-a-scope"),
                "scope without a '/'",
            ),
            (
                format!("agent-token-abcdefgh|{good}|agent-a|"),
                "no scopes listed",
            ),
            (
                format!("agent-token-abcdefgh|{good}|agent a|acme/prod"),
                "agent id with whitespace",
            ),
            (
                "agent-token-abcdefgh|deadbeef|agent-a|acme/prod".to_owned(),
                "short certificate fingerprint",
            ),
            (
                format!("agent-token-abcdefgh|{good}|*|acme/prod"),
                "wildcard agent id",
            ),
            (
                format!("agent-token-abcdefgh|{good}|agent-a|*"),
                "wildcard scope",
            ),
            (
                format!(
                    "agent-token-abcdefgh|{good}|agent-a|acme/prod;agent-token-abcdefgh|{good}|agent-b|acme/prod"
                ),
                "duplicate token",
            ),
            (
                format!("token with spaces|{good}|agent-a|acme/prod"),
                "token that could never be sent in a bearer header",
            ),
        ] {
            assert!(
                parse_agent_token_table(&raw).is_err(),
                "{why}: {raw:?} must be refused, not silently skipped"
            );
        }
    }

    #[test]
    fn an_empty_table_authenticates_nobody() {
        let resolver = parse_agent_token_table("").expect("an empty table is valid");
        assert!(
            resolver
                .resolve_with_peer("anything-at-all-here", Some(&peer(3)))
                .is_err()
        );
    }

    /// A resolver reached without a peer identity must refuse rather than
    /// degrade to bearer-only, whichever entry point is used.
    #[test]
    fn bare_resolve_never_authenticates() {
        assert!(table().resolve("agent-a-token-abcdefgh").is_err());
    }

    // -- Revocation ----------------------------------------------------

    /// A certificate whose fingerprint is in the revocation list is refused
    /// even though its token and certificate still match the credential table
    /// exactly -- revocation is checked in addition to, not instead of, every
    /// existing check. An unrelated, never-revoked credential is unaffected.
    #[test]
    fn a_revoked_certificate_is_refused_even_with_a_valid_token_and_matching_certificate() {
        let revocations = AgentRevocationList::with_static_revocations(
            [peer(0xaa).certificate_sha256],
            Duration::from_secs(60),
        );
        let auth =
            AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
        let error = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xaa)),
            )
            .expect_err("a revoked certificate must be refused even with a valid token");
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);

        assert!(
            auth.authenticate(
                &metadata_with_auth("Bearer agent-b-token-abcdefgh"),
                Some(&peer(0xbb)),
            )
            .is_ok(),
            "revocation must be scoped to the listed fingerprint, not every credential"
        );
    }

    /// An empty (nothing revoked) but fresh revocation list changes nothing
    /// about which credentials authenticate -- the wrapper is only ever a
    /// narrowing of what the inner resolver already allows.
    #[test]
    fn an_empty_revocation_list_does_not_affect_authentication() {
        let revocations =
            AgentRevocationList::with_static_revocations(std::iter::empty(), Duration::from_secs(60));
        let auth =
            AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
        let caller = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xaa)),
            )
            .expect("an unrevoked credential must still authenticate");
        assert_eq!(caller.bound_agent_id(), Some("agent-a"));
    }

    /// The fail-closed direction is the whole point of this feature (see
    /// `AgentRevocationList`'s doc for the full reasoning): once the cache
    /// ages past its staleness ceiling, every agent credential is refused,
    /// including one that was never revoked at all.
    #[test]
    fn a_stale_revocation_cache_refuses_every_agent_credential() {
        // One second, not one millisecond -- the same reasoning
        // `keycloak::tests::a_stale_key_cache_fails_closed_rather_than_trusting_keys_of_unknown_age`
        // gives: the first assertion below has to land *inside* the window,
        // and that has to be reliable on a loaded CI runner, not just locally.
        let revocations =
            AgentRevocationList::with_static_revocations(std::iter::empty(), Duration::from_secs(1));
        assert!(revocations.is_fresh());
        let auth =
            AgentWorkloadAuthenticator::new(RevocationAwareAgentResolver::new(table(), revocations));
        assert!(
            auth.authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xaa)),
            )
            .is_ok(),
            "a fresh, empty revocation cache must not refuse an unrevoked agent"
        );
        std::thread::sleep(Duration::from_millis(1_400));
        let error = auth
            .authenticate(
                &metadata_with_auth("Bearer agent-a-token-abcdefgh"),
                Some(&peer(0xaa)),
            )
            .expect_err("a stale revocation cache must refuse even an agent that was never revoked");
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
    }

    #[test]
    fn revocation_file_parsing_skips_blank_lines_and_hard_fails_on_malformed_ones() {
        let good = hex32(0xaa);
        let parsed = parse_revocation_list(&format!("\n  \n{good}\n\n"))
            .expect("blank lines must be skipped");
        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains(&[0xaa; 32]));

        let too_short = &good[..63];
        for bad in ["not-hex-at-all", "deadbeef", too_short] {
            assert!(
                parse_revocation_list(bad).is_err(),
                "{bad:?} must be refused, not silently skipped"
            );
        }
    }

    #[test]
    fn revocation_file_parsing_deduplicates_repeated_fingerprints() {
        let good = hex32(0xaa);
        let parsed = parse_revocation_list(&format!("{good}\n{good}\n")).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    /// A configured-but-missing revocation file must fail startup loudly, not
    /// silently come up with revocation disabled -- see `AgentRevocationList::start`'s
    /// doc for why this differs from the Keycloak JWKS "warn, don't fail"
    /// split.
    #[test]
    fn revocation_list_start_fails_loudly_on_a_missing_file() {
        let missing = std::env::temp_dir().join(format!(
            "apex-control-agent-revocation-missing-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        assert!(
            AgentRevocationList::start(missing, Duration::from_secs(5), Duration::from_secs(15))
                .is_err(),
            "a configured but unreadable revocation file must fail startup"
        );
    }

    /// The staleness ceiling must be at least the refresh interval, the same
    /// cross-check `KeycloakConfig::validate` applies to its own JWKS
    /// refresh/max-age pair.
    #[test]
    fn revocation_list_start_refuses_a_ceiling_below_the_refresh_interval() {
        let dir = std::env::temp_dir().join(format!(
            "apex-control-agent-revocation-ceiling-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.txt");
        std::fs::write(&path, "\n").unwrap();
        assert!(
            AgentRevocationList::start(path, Duration::from_secs(10), Duration::from_secs(5))
                .is_err()
        );
    }

    /// The background refresher replaces the cached set wholesale rather than
    /// merging: a fingerprint removed from the file stops being revoked after
    /// the next refresh, and a newly added one starts being revoked after it.
    #[test]
    fn revocation_list_background_refresh_replaces_the_set_wholesale() {
        let dir = std::env::temp_dir().join(format!(
            "apex-control-agent-revocation-refresh-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("revoked.txt");
        let fingerprint = peer(0xaa).certificate_sha256;
        std::fs::write(&path, format!("{}\n", hex32(0xaa))).unwrap();

        let list = AgentRevocationList::start(
            path.clone(),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .expect("a well-formed, readable revocation file must start");
        assert_eq!(
            list.check(&fingerprint),
            Ok(true),
            "the fingerprint present at startup must be revoked immediately"
        );

        // Un-revoke by rewriting the file with no entries.
        std::fs::write(&path, "\n").unwrap();
        std::thread::sleep(Duration::from_millis(1_000));
        assert_eq!(
            list.check(&fingerprint),
            Ok(false),
            "removing a fingerprint from the file must un-revoke it, not leave it \
             stuck from an earlier read"
        );
    }

    /// The supervisor identity is a distinct, valid agent_id -- registerable
    /// in the same credential table as the agent it supervises, with its own
    /// entry -- and is never equal to the agent_id it is derived from. Equal
    /// would mean "the same identity", which is precisely the property this
    /// convention exists to avoid.
    #[test]
    fn supervisor_agent_id_is_distinct_and_registerable() {
        let agent_id = "agent-1";
        let supervisor_id = supervisor_agent_id(agent_id);
        assert_ne!(supervisor_id, agent_id);
        assert_eq!(supervisor_id, "agent-1.supervisor");
        let table = parse_agent_token_table(&format!(
            "agent-token-abcdefgh|{}|{agent_id}|acme/prod;supervisor-token-abcdefgh|{}|{supervisor_id}|acme/prod",
            hex32(0xaa),
            hex32(0xcc)
        ))
        .expect("an agent entry and its supervisor entry must both parse");
        let agent_caller = table
            .resolve_with_peer("agent-token-abcdefgh", Some(&peer(0xaa)))
            .expect("the agent's own credential must authenticate");
        let supervisor_caller = table
            .resolve_with_peer("supervisor-token-abcdefgh", Some(&peer(0xcc)))
            .expect("the supervisor's own, separate credential must authenticate");
        assert_eq!(agent_caller.bound_agent_id(), Some(agent_id));
        assert_eq!(supervisor_caller.bound_agent_id(), Some(supervisor_id.as_str()));
        // Neither credential authenticates as the other's identity: the
        // supervisor's token is pinned to its own certificate, distinct from
        // the agent's.
        assert!(
            table
                .resolve_with_peer("agent-token-abcdefgh", Some(&peer(0xcc)))
                .is_err()
        );
    }
}
