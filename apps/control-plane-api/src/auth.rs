//! Independent operator authentication for the OOB control gateway.
//!
//! This is a deliberately separate trust boundary from `event-ingest`'s
//! workload bearer/mTLS auth (`apex_event_ingest::auth`): different
//! credential type, different resolver, different rate-limit bucket space.
//! An ingest workload token must never be usable here, and an operator
//! command token must never be usable on the ingest data path -- reusing one
//! token for both would collapse the two channels ADR-0006 requires to stay
//! independent.
//!
//! Per [[Authentication and Identity]] in the product vault, human operators
//! ultimately authenticate through Keycloak-issued OIDC tokens exchanged for
//! a short-lived, scope-bound operator credential; this module is the
//! verification boundary that credential is checked against. `Keycloak`
//! issuance/exchange is deployment-owned and out of scope for this crate --
//! [`OperatorCredentialResolver`] is the seam a deployment wires that up
//! through.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::errors::CommandError;

/// An authenticated operator identity, scoped to the workspace/namespace
/// pairs it may issue commands into. Unlike `event-ingest`'s `Caller`, this
/// never carries a `bound_agent_id` -- an operator is never mistaken for the
/// agent workload it is commanding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorCaller {
    subject: String,
    allowed_scopes: OperatorScopes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OperatorScopes {
    /// Break-glass / platform-operator credential. Still audited: every
    /// accepted command records the operator subject in the resulting
    /// `control` event's actor.
    Global,
    Scoped(std::collections::HashSet<String>),
}

const MAX_SUBJECT_BYTES: usize = 256;
const MAX_ALLOWED_SCOPES: usize = 256;

impl OperatorCaller {
    pub fn global(subject: impl Into<String>) -> Result<Self, CommandError> {
        let subject = subject.into();
        if !is_valid_subject(&subject) {
            return Err(CommandError::invalid_authorization());
        }
        Ok(Self {
            subject,
            allowed_scopes: OperatorScopes::Global,
        })
    }

    pub fn scoped(
        subject: impl Into<String>,
        allowed_scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, CommandError> {
        let subject = subject.into();
        if !is_valid_subject(&subject) {
            return Err(CommandError::invalid_authorization());
        }
        let mut scopes = std::collections::HashSet::new();
        for raw in allowed_scopes {
            let scope: String = raw.into();
            let Some((workspace, namespace)) = scope.split_once('/') else {
                return Err(CommandError::invalid_authorization());
            };
            if !is_identifier(workspace) || !is_identifier(namespace) {
                return Err(CommandError::invalid_authorization());
            }
            // Bound before inserting: checking afterwards admits one scope
            // past the ceiling.
            if !scopes.contains(&scope) && scopes.len() >= MAX_ALLOWED_SCOPES {
                return Err(CommandError::invalid_authorization());
            }
            scopes.insert(scope);
        }
        Ok(Self {
            subject,
            allowed_scopes: OperatorScopes::Scoped(scopes),
        })
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn allows_scope(&self, workspace_id: &str, namespace_id: &str) -> bool {
        if !is_identifier(workspace_id) || !is_identifier(namespace_id) {
            return false;
        }
        match &self.allowed_scopes {
            OperatorScopes::Global => true,
            OperatorScopes::Scoped(scopes) => {
                scopes.contains(&format!("{workspace_id}/{namespace_id}"))
            }
        }
    }
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// An operator subject is stamped verbatim into the emitted `control`
/// event's `actor.id`, where `event-ingest`'s admission gate applies its
/// `is_scope_identifier` grammar. Enforcing the same grammar here means a
/// subject that could never produce an admissible event is rejected when the
/// credential is constructed, rather than turning every command that
/// operator submits into an opaque `INVALID_COMMAND` at request time.
fn is_valid_subject(subject: &str) -> bool {
    subject.len() <= MAX_SUBJECT_BYTES && is_identifier(subject)
}

/// Deployment-provided operator token resolution. Implementations receive
/// the raw bearer token exactly once per call and must not log it.
pub trait OperatorCredentialResolver: Send + Sync + 'static {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError>;
}

/// The runtime-selected resolver a deployment ends up with.
///
/// `startup::service::resolvers::build_operator_resolver` now chooses between three
/// implementations (static file, static inline, Keycloak) and
/// `ControlGatewayService` is generic over the resolver, so the choice has to
/// be erased somewhere. Doing it behind this alias -- rather than making the
/// service take `&dyn` -- keeps every in-process test monomorphised over the
/// concrete resolver it actually uses.
pub type BoxedOperatorCredentialResolver = Box<dyn OperatorCredentialResolver>;

/// So `Box<dyn OperatorCredentialResolver>` satisfies the trait bound itself.
/// Without this the erased resolver could not be handed to
/// `OperatorTokenAuthenticator<R>`.
impl OperatorCredentialResolver for BoxedOperatorCredentialResolver {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError> {
        (**self).resolve(token)
    }
}

/// A static, in-process token table. Suitable for local/lab deployments and
/// as the target of a Keycloak token-exchange sidecar that periodically
/// rotates the table. Tokens are stored and compared only as SHA-256
/// digests -- the raw token bytes never live longer than the resolve call.
pub struct StaticOperatorTokenResolver {
    tokens: HashMap<[u8; 32], OperatorCaller>,
}

impl StaticOperatorTokenResolver {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
        }
    }

    /// Registers a token. The raw token is hashed immediately; only the
    /// digest is retained.
    pub fn with_token(mut self, token: &str, caller: OperatorCaller) -> Self {
        self.tokens.insert(Sha256::digest(token.as_bytes()).into(), caller);
        self
    }
}

impl Default for StaticOperatorTokenResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorCredentialResolver for StaticOperatorTokenResolver {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.tokens
            .get(&digest)
            .cloned()
            .ok_or_else(CommandError::unauthenticated)
    }
}

/// Field separator inside one `APEX_CONTROL_OPERATOR_TOKENS` entry.
///
/// Deliberately a character that cannot appear on the *scope* side of an
/// entry: scopes are `*` or `workspace/namespace` pairs drawn from
/// [`is_identifier`]'s grammar plus `/` and `,`. Because the right-hand side
/// provably never contains `|`, [`parse_operator_token_table`] can split from
/// the right and recover the token intact even when the token itself
/// contains the separator.
///
/// A `:` separator (the original form) cannot offer that property, because
/// `is_identifier` accepts `:` inside a workspace or namespace. Splitting
/// `token:scopes` on the first `:` silently truncates any token containing a
/// colon down to its prefix -- registering a shorter secret than the operator
/// configured -- and folds the remainder into the scope string, where it
/// validates as a *different*, unintended workspace.
const OPERATOR_ENTRY_SEPARATOR: char = '|';
/// Refuse to register a credential short enough to be brute-forcible, and
/// refuse an implausibly long one.
const MIN_OPERATOR_TOKEN_BYTES: usize = 16;
const MAX_OPERATOR_TOKEN_BYTES: usize = 4096;
const MAX_OPERATOR_TOKEN_ENTRIES: usize = 256;

/// Why an `APEX_CONTROL_OPERATOR_TOKENS` value was refused. The entry index
/// is included so an operator can find the bad entry; the token itself never
/// appears in this type, its `Debug`, or its `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorTokenTableError {
    pub entry_index: usize,
    pub reason: &'static str,
}

impl std::fmt::Display for OperatorTokenTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "APEX_CONTROL_OPERATOR_TOKENS entry {}: {}",
            self.entry_index, self.reason
        )
    }
}

impl std::error::Error for OperatorTokenTableError {}

/// Parses the `APEX_CONTROL_OPERATOR_TOKENS` credential table:
/// `token|workspace/ns[,workspace/ns...];token|*;...`, where `*` grants a
/// global break-glass operator scope.
///
/// Every malformed entry is a hard error. Silently skipping one would let a
/// typo quietly drop an operator's credential (or, worse, register a
/// mis-parsed one) while the gateway still starts and reports healthy.
pub fn parse_operator_token_table(
    raw: &str,
) -> Result<StaticOperatorTokenResolver, OperatorTokenTableError> {
    let mut resolver = StaticOperatorTokenResolver::new();
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for (entry_index, entry) in raw
        .split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .enumerate()
    {
        let fail = |reason: &'static str| OperatorTokenTableError {
            entry_index,
            reason,
        };
        if entry_index >= MAX_OPERATOR_TOKEN_ENTRIES {
            return Err(fail("too many operator token entries"));
        }
        // Split from the right: the scope side cannot contain the separator,
        // so this recovers the whole token even if it contains one.
        let Some((token, scopes)) = entry.rsplit_once(OPERATOR_ENTRY_SEPARATOR) else {
            return Err(fail(
                "expected token|scopes (use '|', not ':', between the token and its scopes)",
            ));
        };
        if token.len() < MIN_OPERATOR_TOKEN_BYTES {
            return Err(fail("operator token is shorter than 16 bytes"));
        }
        if token.len() > MAX_OPERATOR_TOKEN_BYTES {
            return Err(fail("operator token is longer than 4096 bytes"));
        }
        // Must be presentable in an `authorization: Bearer <token>` header:
        // `extract_bearer_token` rejects anything else, so accepting it here
        // would register a credential that can never authenticate.
        if !token.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(fail(
                "operator token must be printable ASCII with no whitespace",
            ));
        }
        let scopes = scopes.trim();
        let caller = if scopes == "*" {
            OperatorCaller::global(format!("operator:static:{entry_index}"))
        } else {
            let parsed = scopes
                .split(',')
                .map(str::trim)
                .filter(|scope| !scope.is_empty())
                .collect::<Vec<_>>();
            if parsed.is_empty() {
                return Err(fail("no scopes listed; use '*' for a global operator"));
            }
            OperatorCaller::scoped(format!("operator:static:{entry_index}"), parsed)
        }
        .map_err(|_| fail("invalid scope; expected '*' or workspace/namespace"))?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        if !seen.insert(digest) {
            return Err(fail("duplicate operator token"));
        }
        resolver = resolver.with_token(token, caller);
    }
    Ok(resolver)
}

const AUTH_FAILURES_PER_WINDOW: u32 = 20;
const AUTH_WINDOW: Duration = Duration::from_secs(1);
const MAX_TRACKED_IDENTITIES: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct FailureBucket {
    window_started: Instant,
    failures: u32,
}

/// Verifies the `authorization` metadata of an incoming control request
/// against an [`OperatorCredentialResolver`] and applies a process-local
/// failure-rate ceiling, isolated from `event-ingest`'s own auth rate-limit
/// buckets (separate struct, separate lock, separate token-hash keyspace).
pub struct OperatorTokenAuthenticator<R: OperatorCredentialResolver> {
    resolver: R,
    failures: Mutex<HashMap<[u8; 32], FailureBucket>>,
}

impl<R: OperatorCredentialResolver> OperatorTokenAuthenticator<R> {
    pub fn new(resolver: R) -> Self {
        Self {
            resolver,
            failures: Mutex::new(HashMap::new()),
        }
    }

    pub fn authenticate(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<OperatorCaller, CommandError> {
        let token = extract_bearer_token(metadata)?;
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.check_and_record_attempt(digest)?;
        match self.resolver.resolve(&token) {
            Ok(caller) => Ok(caller),
            Err(error) => {
                self.record_failure(digest);
                Err(error)
            }
        }
    }

    fn check_and_record_attempt(&self, digest: [u8; 32]) -> Result<(), CommandError> {
        let Ok(mut buckets) = self.failures.lock() else {
            // A poisoned lock must fail closed, not fail open into an
            // unthrottled auth path.
            return Err(CommandError::internal());
        };
        let now = Instant::now();
        if !buckets.contains_key(&digest) && buckets.len() >= MAX_TRACKED_IDENTITIES {
            // Bounded memory: evict nothing selectively (that would let an
            // attacker choose what survives), just refuse new buckets under
            // pressure. Existing identities keep working.
            return Err(CommandError::rate_limited());
        }
        let bucket = buckets.entry(digest).or_insert(FailureBucket {
            window_started: now,
            failures: 0,
        });
        if bucket.window_started.elapsed() >= AUTH_WINDOW {
            *bucket = FailureBucket {
                window_started: now,
                failures: 0,
            };
        }
        if bucket.failures >= AUTH_FAILURES_PER_WINDOW {
            return Err(CommandError::rate_limited());
        }
        Ok(())
    }

    fn record_failure(&self, digest: [u8; 32]) {
        if let Ok(mut buckets) = self.failures.lock()
            && let Some(bucket) = buckets.get_mut(&digest)
        {
            bucket.failures = bucket.failures.saturating_add(1);
        }
    }
}

fn extract_bearer_token(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<String, CommandError> {
    let mut values = metadata.get_all("authorization").iter();
    let Some(value) = values.next() else {
        return Err(CommandError::unauthenticated());
    };
    if values.next().is_some() {
        // More than one authorization header is ambiguous; never pick one.
        return Err(CommandError::invalid_authorization());
    }
    let value = value
        .to_str()
        .map_err(|_| CommandError::invalid_authorization())?;
    if !value.is_ascii() {
        return Err(CommandError::invalid_authorization());
    }
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(CommandError::invalid_authorization)?;
    if token.is_empty() || token.len() > 4096 || token.contains(char::is_whitespace) {
        return Err(CommandError::invalid_authorization());
    }
    Ok(token.to_owned())
}

#[cfg(test)]
mod tests;
