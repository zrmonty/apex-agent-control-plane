use std::time::Duration;

use super::configuration::sql_positive;
use super::{AuthorityClientConfig, AuthorityClientError, AuthorityOperation};
use crate::proto::{
    ProxyDesiredState, ProxyObservedState, RuntimeAuthorityAction, RuntimeAuthoritySnapshot,
};

// Private deterministic seam required by the brief: no public clock/pin override.
pub(super) fn validate(
    snapshot: &RuntimeAuthoritySnapshot,
    config: &AuthorityClientConfig,
    operation: &AuthorityOperation<'_>,
    controller_identity: &str,
    peer_policy_version: &str,
    elapsed: Duration,
) -> Result<(), AuthorityClientError> {
    let target = snapshot
        .target
        .as_ref()
        .ok_or(AuthorityClientError::InvalidSnapshot)?;
    if snapshot.schema_version != 1
        || snapshot.action != i32::from(RuntimeAuthorityAction::CheckCurrentOperation)
        || crate::check_runtime_target(target).is_err()
        || !sql_positive(target.generation)
        || !sql_positive(target.fencing_token)
        || !matches!(ProxyDesiredState::try_from(snapshot.desired_state), Ok(state) if state != ProxyDesiredState::Unspecified)
        || !matches!(ProxyObservedState::try_from(snapshot.observed_state), Ok(state) if state != ProxyObservedState::Unspecified)
    {
        return Err(AuthorityClientError::InvalidSnapshot);
    }
    if target != operation.target
        || snapshot.operation_id != operation.operation_id
        || snapshot.command_id != operation.command_id
        || snapshot.installation_id != config.installation_id
        || snapshot.agent_identity_id != config.agent_identity_id
        || snapshot.observed_controller_identity_id != controller_identity
        || snapshot.peer_policy_version != peer_policy_version
        || snapshot.enrollment_version != config.enrollment_version
        || snapshot.host_policy_version != config.host_policy_version
        || snapshot.config_hash != operation.config_hash
    {
        return Err(AuthorityClientError::MismatchedSnapshot);
    }
    validate_elapsed(snapshot, elapsed)
}

pub(super) fn validate_elapsed(
    snapshot: &RuntimeAuthoritySnapshot,
    elapsed: Duration,
) -> Result<(), AuthorityClientError> {
    if !sql_positive(snapshot.checked_at_unix_us)
        || !sql_positive(snapshot.lease_expires_at_unix_us)
    {
        return Err(AuthorityClientError::InvalidSnapshot);
    }
    let interval = snapshot
        .lease_expires_at_unix_us
        .checked_sub(snapshot.checked_at_unix_us)
        .filter(|interval| *interval != 0)
        .ok_or(AuthorityClientError::InvalidSnapshot)?;
    // Preserve integer microseconds above 2^53 and the entire local nanosecond tail.
    // Never compare either remote DB timestamp to the local wall clock.
    if elapsed >= Duration::from_micros(interval) {
        return Err(AuthorityClientError::InvalidSnapshot);
    }
    Ok(())
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
