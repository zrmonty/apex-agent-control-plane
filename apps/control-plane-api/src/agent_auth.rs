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

use std::collections::HashMap;
use std::collections::HashSet;

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
