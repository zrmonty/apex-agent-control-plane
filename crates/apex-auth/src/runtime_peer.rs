//! Runtime peer policy prerequisite, not operation authority or enrollment.
//!
//! Strict policy parsing and actual TLS leaf checks implement only role and
//! exact-grant authentication. No runtime operation is implemented here.
//! The owner must supply the current deployment policy on each check;
//! this immutable snapshot does not fetch revocations or grant a current lease.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::PeerIdentity;

mod decode;
mod pair;

pub use pair::RuntimePeerPair;

/// The two explicitly registered runtime roles; no operator/workload inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePeerRole {
    /// A control-plane runtime controller.
    Controller,
    /// A restricted runtime host agent.
    Agent,
}

/// Static refusals. No original policy, certificate or parser source is retained.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RuntimePeerError {
    /// Invalid original JSON, shape, bounds or policy relationships.
    InvalidPolicy,
    /// A claimed installation or exact scope selector is malformed.
    InvalidSelector,
    /// Actual TLS leaf evidence is absent.
    Unauthenticated,
    /// The actual leaf is unknown/revoked or its role/exact grant differs.
    Denied,
    /// Local check time is before validity or at/after expiration.
    PolicyNotCurrent,
    /// The local clock cannot be represented as checked Unix microseconds.
    ClockUnavailable,
}

impl RuntimePeerError {
    /// Stable redacted code, safe without an underlying error chain.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidPolicy => "RUNTIME_PEER_INVALID_POLICY",
            Self::InvalidSelector => "RUNTIME_PEER_INVALID_SELECTOR",
            Self::Unauthenticated => "RUNTIME_PEER_UNAUTHENTICATED",
            Self::Denied => "RUNTIME_PEER_DENIED",
            Self::PolicyNotCurrent => "RUNTIME_PEER_POLICY_NOT_CURRENT",
            Self::ClockUnavailable => "RUNTIME_PEER_CLOCK_UNAVAILABLE",
        }
    }
}

impl fmt::Display for RuntimePeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl fmt::Debug for RuntimePeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for RuntimePeerError {}

/// Immutable deployment-owned policy. It has no file/environment loader.
/// Parsing establishes structure only, not enrollment or current operation proof.
pub struct RuntimePeerPolicy {
    version: String,
    valid_from_unix_us: u64,
    expires_at_unix_us: u64,
    peers: Vec<RegisteredPeer>,
}

struct RegisteredPeer {
    certificate_sha256: [u8; 32],
    identity_id: String,
    role: RuntimePeerRole,
    revoked: bool,
    grants: Vec<Grant>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Grant {
    installation_id: String,
    workspace_id: String,
    namespace_id: String,
}

impl RuntimePeerPolicy {
    /// Parse original UTF-8 JSON: at most 65,536 bytes and depth 32.
    /// Policy/identity IDs are exact domain identifiers of at most 128 bytes;
    /// workspace/namespace use the domain's 256-byte scope identifier bound.
    ///
    /// # Errors
    /// Returns only `InvalidPolicy` for malformed, ambiguous or excessive input.
    pub fn parse_json(input: &[u8]) -> Result<Self, RuntimePeerError> {
        decode::parse(input)
    }

    /// Exact validated deployment policy version, not an authority capability.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Authenticate only the leaf obtained by `PeerIdentity::from_request`.
    /// Claimed role/installation/scope are selectors, never transport identity.
    /// The public API has no caller-selected clock or pin override.
    ///
    /// # Errors
    /// Refuses missing TLS evidence, invalid selectors, stale policy, clock
    /// errors, revoked/unknown leaves and nonmatching role or exact grant.
    pub fn authorize<T>(
        &self,
        request: &tonic::Request<T>,
        role: RuntimePeerRole,
        installation_id: &str,
        workspace_id: &str,
        namespace_id: &str,
    ) -> Result<AuthenticatedRuntimePeer<'_>, RuntimePeerError> {
        let peer = PeerIdentity::from_request(request);
        let now = checked_clock(SystemTime::now().duration_since(UNIX_EPOCH).ok());
        self.authorize_at(
            peer.as_ref(),
            Selection {
                role,
                installation_id,
                workspace_id,
                namespace_id,
            },
            now,
        )
    }

    // Shared production checks with a private deterministic unit-test seam.
    // Neither this method nor view construction is a public identity shortcut.
    fn authorize_at(
        &self,
        peer: Option<&PeerIdentity>,
        selection: Selection<'_>,
        now: Result<u64, RuntimePeerError>,
    ) -> Result<AuthenticatedRuntimePeer<'_>, RuntimePeerError> {
        let peer = peer.ok_or(RuntimePeerError::Unauthenticated)?;
        if !valid_grant(
            selection.installation_id,
            selection.workspace_id,
            selection.namespace_id,
        ) {
            return Err(RuntimePeerError::InvalidSelector);
        }
        let now = now?;
        if now < self.valid_from_unix_us || now >= self.expires_at_unix_us {
            return Err(RuntimePeerError::PolicyNotCurrent);
        }
        let registered = self
            .peers
            .iter()
            .find(|entry| entry.certificate_sha256 == peer.certificate_sha256)
            .ok_or(RuntimePeerError::Denied)?;
        if registered.revoked || registered.role != selection.role {
            return Err(RuntimePeerError::Denied);
        }
        let grant = registered
            .grants
            .iter()
            .find(|grant| {
                grant.installation_id == selection.installation_id
                    && grant.workspace_id == selection.workspace_id
                    && grant.namespace_id == selection.namespace_id
            })
            .ok_or(RuntimePeerError::Denied)?;
        Ok(AuthenticatedRuntimePeer {
            identity_id: &registered.identity_id,
            role: registered.role,
            installation_id: &grant.installation_id,
            workspace_id: &grant.workspace_id,
            namespace_id: &grant.namespace_id,
            policy_version: &self.version,
            checked_at_unix_us: now,
        })
    }
}

impl fmt::Debug for RuntimePeerPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimePeerPolicy { [redacted] }")
    }
}

/// Borrowed, point-in-time identity evidence, never an execution permit.
/// No public/test-support constructor or deserializer exists. Keeping this
/// view alive does not keep a policy current; every operation needs a new check.
/// Checked time is local Unix microseconds, not calibrated cross-host time.
///
/// The view cannot outlive its policy:
/// ```compile_fail
/// use apex_auth::{AuthenticatedRuntimePeer, RuntimePeerPolicy, RuntimePeerRole};
/// fn detach(p: &RuntimePeerPolicy, r: &tonic::Request<()>)
///     -> AuthenticatedRuntimePeer<'static> {
///     p.authorize(r, RuntimePeerRole::Controller,
///         "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", "work", "ns").unwrap()
/// }
/// ```
pub struct AuthenticatedRuntimePeer<'a> {
    identity_id: &'a str,
    role: RuntimePeerRole,
    installation_id: &'a str,
    workspace_id: &'a str,
    namespace_id: &'a str,
    policy_version: &'a str,
    checked_at_unix_us: u64,
}

impl AuthenticatedRuntimePeer<'_> {
    /// Stable identity selected by the actual leaf pin.
    pub fn identity_id(&self) -> &str {
        self.identity_id
    }
    /// Explicit registered role.
    pub fn role(&self) -> RuntimePeerRole {
        self.role
    }
    /// Installation in the one exact selected grant.
    pub fn installation_id(&self) -> &str {
        self.installation_id
    }
    /// Workspace in the same grant, never a Cartesian-product expansion.
    pub fn workspace_id(&self) -> &str {
        self.workspace_id
    }
    /// Namespace in the same grant.
    pub fn namespace_id(&self) -> &str {
        self.namespace_id
    }
    /// Version of the snapshot used for this check.
    pub fn policy_version(&self) -> &str {
        self.policy_version
    }
    /// Point-in-time local clock sample, not a lease expiration.
    pub fn checked_at_unix_us(&self) -> u64 {
        self.checked_at_unix_us
    }
}

impl fmt::Debug for AuthenticatedRuntimePeer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedRuntimePeer { [point-in-time, redacted] }")
    }
}

struct Selection<'a> {
    role: RuntimePeerRole,
    installation_id: &'a str,
    workspace_id: &'a str,
    namespace_id: &'a str,
}

fn checked_clock(elapsed: Option<Duration>) -> Result<u64, RuntimePeerError> {
    let elapsed = elapsed.ok_or(RuntimePeerError::ClockUnavailable)?;
    u64::try_from(elapsed.as_micros()).map_err(|_| RuntimePeerError::ClockUnavailable)
}

fn valid_grant(installation_id: &str, workspace_id: &str, namespace_id: &str) -> bool {
    apex_domain::is_lowercase_uuidv7(installation_id)
        && apex_domain::is_scope_identifier(workspace_id)
        && apex_domain::is_scope_identifier(namespace_id)
}

#[cfg(test)]
mod tests;
