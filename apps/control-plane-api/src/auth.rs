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
            scopes.insert(scope);
            if scopes.len() > MAX_ALLOWED_SCOPES {
                return Err(CommandError::invalid_authorization());
            }
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

fn is_valid_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_SUBJECT_BYTES
        && subject.is_ascii()
        && !subject.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

/// Deployment-provided operator token resolution. Implementations receive
/// the raw bearer token exactly once per call and must not log it.
pub trait OperatorCredentialResolver: Send + Sync + 'static {
    fn resolve(&self, token: &str) -> Result<OperatorCaller, CommandError>;
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
mod tests {
    use super::*;

    fn metadata_with_auth(value: &str) -> tonic::metadata::MetadataMap {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("authorization", value.parse().unwrap());
        metadata
    }

    #[test]
    fn authenticate_accepts_a_registered_token_and_scope() {
        let resolver = StaticOperatorTokenResolver::new().with_token(
            "secret-token",
            OperatorCaller::scoped("operator:zack", ["acme/prod"]).unwrap(),
        );
        let auth = OperatorTokenAuthenticator::new(resolver);
        let caller = auth
            .authenticate(&metadata_with_auth("Bearer secret-token"))
            .unwrap();
        assert!(caller.allows_scope("acme", "prod"));
        assert!(!caller.allows_scope("acme", "staging"));
    }

    #[test]
    fn authenticate_rejects_an_unregistered_token() {
        let resolver = StaticOperatorTokenResolver::new();
        let auth = OperatorTokenAuthenticator::new(resolver);
        let error = auth
            .authenticate(&metadata_with_auth("Bearer nope"))
            .unwrap_err();
        assert_eq!(error.code, crate::errors::CommandErrorCode::Unauthenticated);
    }

    #[test]
    fn authenticate_rejects_a_missing_authorization_header() {
        let resolver = StaticOperatorTokenResolver::new();
        let auth = OperatorTokenAuthenticator::new(resolver);
        let metadata = tonic::metadata::MetadataMap::new();
        assert!(auth.authenticate(&metadata).is_err());
    }

    #[test]
    fn authenticate_rejects_duplicate_authorization_headers() {
        let resolver = StaticOperatorTokenResolver::new().with_token(
            "secret-token",
            OperatorCaller::global("operator:break-glass").unwrap(),
        );
        let auth = OperatorTokenAuthenticator::new(resolver);
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.append("authorization", "Bearer secret-token".parse().unwrap());
        metadata.append("authorization", "Bearer secret-token".parse().unwrap());
        let error = auth.authenticate(&metadata).unwrap_err();
        assert_eq!(
            error.code,
            crate::errors::CommandErrorCode::InvalidAuthorization
        );
    }

    #[test]
    fn authenticate_rate_limits_repeated_failures_for_the_same_token() {
        let resolver = StaticOperatorTokenResolver::new();
        let auth = OperatorTokenAuthenticator::new(resolver);
        for _ in 0..AUTH_FAILURES_PER_WINDOW {
            let _ = auth.authenticate(&metadata_with_auth("Bearer guess"));
        }
        let error = auth
            .authenticate(&metadata_with_auth("Bearer guess"))
            .unwrap_err();
        assert_eq!(error.code, crate::errors::CommandErrorCode::RateLimited);
    }

    #[test]
    fn global_operator_allows_every_well_formed_scope() {
        let caller = OperatorCaller::global("operator:break-glass").unwrap();
        assert!(caller.allows_scope("acme", "prod"));
        assert!(caller.allows_scope("other", "staging"));
        assert!(!caller.allows_scope("bad scope", "prod"));
    }

    #[test]
    fn scoped_construction_rejects_malformed_scope_strings() {
        assert!(OperatorCaller::scoped("operator:zack", ["not-a-scope"]).is_err());
        assert!(OperatorCaller::scoped("operator:zack", ["ac me/prod"]).is_err());
    }
}
