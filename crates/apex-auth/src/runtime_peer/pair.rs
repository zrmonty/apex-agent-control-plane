//! An actual Agent may attest an observed Controller; no operation authority.

use super::{
    PeerIdentity, RuntimePeerError, RuntimePeerPolicy, RuntimePeerRole, Selection, checked_clock,
};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Borrowed point-in-time pair, not enrollment, placement, a lease or a permit.
/// Only the agent was authenticated on the callback's TLS connection. The
/// controller identity describes that agent's observation under the same policy.
/// The owner must provide current policy and independently check enrollment.
///
/// The pair cannot outlive its policy:
/// ```compile_fail
/// use apex_auth::{RuntimePeerPair, RuntimePeerPolicy};
/// fn detach(p: &RuntimePeerPolicy, r: &tonic::Request<()>) -> RuntimePeerPair<'static> {
///     p.authorize_agent_observation(r, &[0; 32],
///         "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01", "work", "ns").unwrap()
/// }
/// ```
/// Nor can a caller construct a claimed pair:
/// ```compile_fail
/// use apex_auth::RuntimePeerPair;
/// let pair = RuntimePeerPair {
///     agent_identity_id: "claimed-agent", observed_controller_identity_id: "claimed-controller",
///     installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01",
///     workspace_id: "work", namespace_id: "ns", policy_version: "claimed", checked_at_unix_us: 7,
/// };
/// ```
/// Wire data cannot deserialize into pair evidence:
/// ```compile_fail
/// use apex_auth::RuntimePeerPair;
/// let pair = serde_json::from_str::<RuntimePeerPair<'static>>("{}");
/// ```
pub struct RuntimePeerPair<'a> {
    agent_identity_id: &'a str,
    observed_controller_identity_id: &'a str,
    installation_id: &'a str,
    workspace_id: &'a str,
    namespace_id: &'a str,
    policy_version: &'a str,
    checked_at_unix_us: u64,
}

impl RuntimePeerPair<'_> {
    /// Stable identity authenticated from the actual Agent TLS leaf.
    pub fn agent_identity_id(&self) -> &str {
        self.agent_identity_id
    }
    /// Stable Controller identity attested by the Agent, not callback TLS proof.
    pub fn observed_controller_identity_id(&self) -> &str {
        self.observed_controller_identity_id
    }
    /// Installation in both peers' exact selected grant.
    pub fn installation_id(&self) -> &str {
        self.installation_id
    }
    /// Workspace in that same grant.
    pub fn workspace_id(&self) -> &str {
        self.workspace_id
    }
    /// Namespace in that same grant.
    pub fn namespace_id(&self) -> &str {
        self.namespace_id
    }
    /// Immutable policy version used for this check, not a freshness guarantee.
    pub fn policy_version(&self) -> &str {
        self.policy_version
    }
    /// One local checked Unix-microsecond sample, not calibrated cross-host time.
    pub fn checked_at_unix_us(&self) -> u64 {
        self.checked_at_unix_us
    }
}

impl fmt::Debug for RuntimePeerPair<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimePeerPair { [point-in-time, redacted] }")
    }
}

impl RuntimePeerPolicy {
    /// Check an actual TLS Agent and its observed Controller under one policy.
    /// The pin is an Agent assertion, never a replacement for the actual caller.
    /// No caller-selected clock, generic authenticate-by-pin or enrollment exists.
    ///
    /// # Errors
    /// Refuses absent TLS, invalid selectors, clock/policy time failures, or
    /// either leaf's revoked/unknown registration, wrong role or wrong exact grant.
    pub fn authorize_agent_observation<T>(
        &self,
        actual_agent_request: &tonic::Request<T>,
        observed_controller_pin: &[u8; 32],
        installation: &str,
        workspace: &str,
        namespace: &str,
    ) -> Result<RuntimePeerPair<'_>, RuntimePeerError> {
        let agent = PeerIdentity::from_request(actual_agent_request);
        let now = checked_clock(SystemTime::now().duration_since(UNIX_EPOCH).ok());
        self.authorize_agent_observation_at(
            agent.as_ref(),
            observed_controller_pin,
            (installation, workspace, namespace),
            now,
        )
    }

    // Shared production/private deterministic seam. Both roles and exact grants
    // use the same immutable policy and the one checked public clock sample.
    fn authorize_agent_observation_at(
        &self,
        actual_agent: Option<&PeerIdentity>,
        observed_controller_pin: &[u8; 32],
        (installation_id, workspace_id, namespace_id): (&str, &str, &str),
        now: Result<u64, RuntimePeerError>,
    ) -> Result<RuntimePeerPair<'_>, RuntimePeerError> {
        let agent = self.authorize_at(
            actual_agent,
            Selection {
                role: RuntimePeerRole::Agent,
                installation_id,
                workspace_id,
                namespace_id,
            },
            now,
        )?;
        // Only an actual authorized Agent reaches this private observation
        // lookup. This pin is its assertion, not callback Controller TLS proof.
        let observed = PeerIdentity {
            certificate_sha256: *observed_controller_pin,
        };
        let controller = self.authorize_at(
            Some(&observed),
            Selection {
                role: RuntimePeerRole::Controller,
                installation_id,
                workspace_id,
                namespace_id,
            },
            now,
        )?;
        Ok(RuntimePeerPair {
            agent_identity_id: agent.identity_id,
            observed_controller_identity_id: controller.identity_id,
            installation_id: agent.installation_id,
            workspace_id: agent.workspace_id,
            namespace_id: agent.namespace_id,
            policy_version: agent.policy_version,
            checked_at_unix_us: agent.checked_at_unix_us,
        })
    }
}

#[cfg(test)]
mod tests;
