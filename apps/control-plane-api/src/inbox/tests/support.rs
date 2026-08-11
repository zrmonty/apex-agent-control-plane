//! Fixtures shared by more than one of this module's sibling test groups.

use crate::inbox::*;

pub(super) fn command(command_id: &str, agent_id: &str) -> PendingCommand {
    PendingCommand {
        command_id: command_id.to_owned(),
        workspace_id: "acme".to_owned(),
        namespace_id: "prod".to_owned(),
        agent_id: agent_id.to_owned(),
        run_id: "run-1".to_owned(),
        trace_id: "trace-1".to_owned(),
        action: "stop".to_owned(),
        reason_code: Some("operator.request".to_owned()),
        parameters: Vec::new(),
        issued_at: "2026-08-08T00:00:00.000000Z".to_owned(),
        delivery_attempt: 0,
    }
}

pub(super) fn target(agent_id: &str) -> PollTarget {
    PollTarget {
        agent_id: agent_id.to_owned(),
        limit: DEFAULT_MAX_COMMANDS_PER_POLL,
    }
}

pub(super) fn scope(workspace_id: &str, namespace_id: &str) -> ExactScope {
    ExactScope {
        workspace_id: workspace_id.to_owned(),
        namespace_id: namespace_id.to_owned(),
    }
}

pub(super) fn acme_prod() -> ExactScope {
    scope("acme", "prod")
}

