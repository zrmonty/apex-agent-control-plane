use super::{ProxyError, ProxyLifecycleState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleCommand {
    Validate,
    ValidationSucceeded,
    Deploy,
    Ready,
    Degrade,
    Recover,
    Pause,
    Resume,
    Fail,
    Retire,
    Retired,
}

impl LifecycleCommand {
    pub const fn operation(self) -> &'static str {
        match self {
            Self::Validate => "validate_proxy",
            Self::ValidationSucceeded => "validation_succeeded",
            Self::Deploy => "deploy_proxy",
            Self::Ready => "proxy_ready",
            Self::Degrade => "proxy_degraded",
            Self::Recover => "proxy_recovered",
            Self::Pause => "pause_proxy",
            Self::Resume => "resume_proxy",
            Self::Fail => "proxy_failed",
            Self::Retire => "retire_proxy",
            Self::Retired => "proxy_retired",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleTransition {
    pub prior_state: ProxyLifecycleState,
    pub next_state: ProxyLifecycleState,
    pub command: LifecycleCommand,
}

pub fn transition_state(
    current: ProxyLifecycleState,
    command: LifecycleCommand,
    approved: bool,
) -> Result<ProxyLifecycleState, ProxyError> {
    let next = match (current, command) {
        (ProxyLifecycleState::Draft, LifecycleCommand::Validate) => ProxyLifecycleState::Validating,
        (ProxyLifecycleState::Validating, LifecycleCommand::ValidationSucceeded) => {
            ProxyLifecycleState::AwaitingApproval
        }
        (ProxyLifecycleState::AwaitingApproval, LifecycleCommand::Deploy) if approved => {
            ProxyLifecycleState::Provisioning
        }
        (ProxyLifecycleState::Provisioning, LifecycleCommand::Ready) => ProxyLifecycleState::Ready,
        (ProxyLifecycleState::Ready, LifecycleCommand::Degrade) => ProxyLifecycleState::Degraded,
        (ProxyLifecycleState::Degraded, LifecycleCommand::Recover) => ProxyLifecycleState::Ready,
        (ProxyLifecycleState::Ready, LifecycleCommand::Pause) => ProxyLifecycleState::Paused,
        (ProxyLifecycleState::Paused, LifecycleCommand::Resume) => ProxyLifecycleState::Provisioning,
        (ProxyLifecycleState::Validating | ProxyLifecycleState::Provisioning, LifecycleCommand::Fail) => {
            ProxyLifecycleState::Failed
        }
        (
            ProxyLifecycleState::Ready | ProxyLifecycleState::Degraded | ProxyLifecycleState::Paused,
            LifecycleCommand::Retire,
        ) => ProxyLifecycleState::Retiring,
        (ProxyLifecycleState::Retiring, LifecycleCommand::Retired) => ProxyLifecycleState::Retired,
        (ProxyLifecycleState::AwaitingApproval, LifecycleCommand::Deploy) => {
            return Err(ProxyError::approval_required());
        }
        _ => return Err(ProxyError::invalid_lifecycle_transition()),
    };
    Ok(next)
}

impl LifecycleTransition {
    pub fn new(
        prior_state: ProxyLifecycleState,
        command: LifecycleCommand,
        approved: bool,
    ) -> Result<Self, ProxyError> {
        Ok(Self {
            prior_state,
            next_state: transition_state(prior_state, command, approved)?,
            command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{LifecycleCommand, ProxyLifecycleState, transition_state};

    #[test]
    fn allows_only_the_documented_lifecycle_edges() {
        let cases = [
            (ProxyLifecycleState::Draft, LifecycleCommand::Validate, false, ProxyLifecycleState::Validating),
            (ProxyLifecycleState::Validating, LifecycleCommand::ValidationSucceeded, false, ProxyLifecycleState::AwaitingApproval),
            (ProxyLifecycleState::AwaitingApproval, LifecycleCommand::Deploy, true, ProxyLifecycleState::Provisioning),
            (ProxyLifecycleState::Provisioning, LifecycleCommand::Ready, false, ProxyLifecycleState::Ready),
            (ProxyLifecycleState::Ready, LifecycleCommand::Pause, false, ProxyLifecycleState::Paused),
            (ProxyLifecycleState::Paused, LifecycleCommand::Resume, false, ProxyLifecycleState::Provisioning),
            (ProxyLifecycleState::Ready, LifecycleCommand::Degrade, false, ProxyLifecycleState::Degraded),
            (ProxyLifecycleState::Degraded, LifecycleCommand::Recover, false, ProxyLifecycleState::Ready),
            (ProxyLifecycleState::Ready, LifecycleCommand::Retire, false, ProxyLifecycleState::Retiring),
            (ProxyLifecycleState::Retiring, LifecycleCommand::Retired, false, ProxyLifecycleState::Retired),
        ];

        for (current, command, approved, expected) in cases {
            assert_eq!(transition_state(current, command, approved), Ok(expected));
        }
    }

    #[test]
    fn rejects_invalid_edges_and_missing_deploy_approval() {
        assert!(transition_state(
            ProxyLifecycleState::Draft,
            LifecycleCommand::Deploy,
            true,
        )
        .is_err());
        assert!(transition_state(
            ProxyLifecycleState::AwaitingApproval,
            LifecycleCommand::Deploy,
            false,
        )
        .is_err());
        assert!(transition_state(
            ProxyLifecycleState::Ready,
            LifecycleCommand::Ready,
            false,
        )
        .is_err());
    }

    #[test]
    fn retirement_is_terminal() {
        for command in [
            LifecycleCommand::Validate,
            LifecycleCommand::Deploy,
            LifecycleCommand::Pause,
            LifecycleCommand::Resume,
            LifecycleCommand::Degrade,
            LifecycleCommand::Recover,
            LifecycleCommand::Retire,
        ] {
            assert!(transition_state(ProxyLifecycleState::Retired, command, true).is_err());
        }
    }
}
