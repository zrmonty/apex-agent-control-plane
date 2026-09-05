//! Bounded journal metadata and desired/observed-state invariants.

use super::configuration_error;
use crate::proto::{ProxyDesiredState, ProxyObservedState};
use crate::proxy::ProxyError;

/// Only matching successful observations complete a desired operation.
/// Reconciliation and recoverable failure observations remain nonterminal.
pub(super) fn validate_observation(
    persisted_desired: i32,
    observed: ProxyObservedState,
) -> Result<(), ProxyError> {
    use ProxyDesiredState::{Paused as WantPaused, Retired as WantRetired, Serving};
    use ProxyObservedState::{Failed, NotServing, Paused, Ready, Reconciling, Retired};

    let desired =
        ProxyDesiredState::try_from(persisted_desired).map_err(|_| configuration_error())?;
    if matches!(
        (desired, observed),
        (Serving, Ready)
            | (WantPaused, Paused)
            | (WantRetired, Retired)
            | (
                Serving | WantPaused | WantRetired,
                Reconciling | Failed | NotServing
            )
    ) {
        Ok(())
    } else {
        Err(ProxyError::invalid_lifecycle_transition())
    }
}

pub(in super::super) fn desired_text(state: ProxyDesiredState) -> Result<&'static str, ProxyError> {
    match state {
        ProxyDesiredState::Serving => Ok("serving"),
        ProxyDesiredState::Paused => Ok("paused"),
        ProxyDesiredState::Retired => Ok("retired"),
        ProxyDesiredState::Unspecified => Err(ProxyError::invalid_proxy_spec(
            "A desired proxy state is required.",
        )),
    }
}

pub(in super::super) fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}
