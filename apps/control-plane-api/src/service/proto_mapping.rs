//! Free functions mapping this crate's internal delivery/inbox types onto the
//! `proto::v1` wire types, shared by [`super::submit`], [`super::poll`], and
//! [`super::query`]'s RPC handlers.

use crate::errors::CommandError;
use crate::inbox::{DeliveryStatus, PendingCommand, RecordResult};
use crate::proto;

pub(super) fn delivery_status_to_proto(status: DeliveryStatus) -> proto::CommandDeliveryState {
    match status {
        DeliveryStatus::Pending => proto::CommandDeliveryState::CommandDeliveryPending,
        DeliveryStatus::Delivered => proto::CommandDeliveryState::CommandDeliveryDelivered,
        DeliveryStatus::Acknowledged => proto::CommandDeliveryState::CommandDeliveryAcknowledged,
        DeliveryStatus::Exhausted => proto::CommandDeliveryState::CommandDeliveryExhausted,
        DeliveryStatus::Cancelled => proto::CommandDeliveryState::CommandDeliveryCancelled,
    }
}

/// The inverse of `delivery_status_to_proto`, used to parse `ListCommands`'
/// `state` filter. `Unspecified` means "no filter" -- the proto3 default for
/// an unset enum field -- rather than a fifth delivery state.
pub(super) fn proto_state_to_delivery_status(
    state: proto::CommandDeliveryState,
) -> Option<DeliveryStatus> {
    match state {
        proto::CommandDeliveryState::Unspecified => None,
        proto::CommandDeliveryState::CommandDeliveryPending => Some(DeliveryStatus::Pending),
        proto::CommandDeliveryState::CommandDeliveryDelivered => Some(DeliveryStatus::Delivered),
        proto::CommandDeliveryState::CommandDeliveryAcknowledged => {
            Some(DeliveryStatus::Acknowledged)
        }
        proto::CommandDeliveryState::CommandDeliveryExhausted => Some(DeliveryStatus::Exhausted),
        proto::CommandDeliveryState::CommandDeliveryCancelled => Some(DeliveryStatus::Cancelled),
    }
}

/// Maps a stored action name onto the wire enum. Factored out of
/// `pending_to_proto` so `ListCommands`'s `CommandSummary` reports the same
/// action the same way `PollCommands`'s `PendingControlCommand` does, rather
/// than risking a second mapping that could drift from the first.
fn action_to_proto(action: &str) -> proto::ControlAction {
    match action {
        "stop" => proto::ControlAction::Stop,
        "pause" => proto::ControlAction::Pause,
        "resume" => proto::ControlAction::Resume,
        "inject" => proto::ControlAction::Inject,
        "set_budget" => proto::ControlAction::SetBudget,
        "resolve_hold" => proto::ControlAction::ResolveHold,
        "force_stop" => proto::ControlAction::ForceStop,
        _ => proto::ControlAction::Unspecified,
    }
}

/// Maps a stored [`crate::inbox::CommandSummary`] onto the wire type. Every
/// field here is one `GetCommandStatus`/`PendingControlCommand` already
/// expose; this introduces no new field.
pub(super) fn command_summary_to_proto(
    summary: crate::inbox::CommandSummary,
) -> proto::CommandSummary {
    proto::CommandSummary {
        command_id: summary.command_id,
        agent_id: summary.agent_id,
        action: action_to_proto(&summary.action) as i32,
        state: delivery_status_to_proto(summary.state) as i32,
        delivery_attempt: summary.delivery_attempt,
        issued_at: summary.issued_at,
    }
}

/// Builds the accepted [`proto::BulkCommandResult`] for one bulk target.
///
/// Mirrors `ControlCommandResponse`'s own fields exactly (`command_id`,
/// `duplicate`, `delivered`), including `submit_command`'s own reasoning for
/// `delivered`: a reused `command_id` whose outbox row is complete can still
/// create a fresh inbox delivery after retention, so `delivered` only claims
/// the old trace fanout covers this attempt when the inbox write itself also
/// reports `AlreadyRecorded`.
pub(super) fn accepted_bulk_result(
    target: &proto::BulkCommandTarget,
    command_id: String,
    outcome: crate::outbox::SubmitOutcome,
    record: RecordResult,
) -> proto::BulkCommandResult {
    proto::BulkCommandResult {
        workspace_id: target.workspace_id.clone(),
        namespace_id: target.namespace_id.clone(),
        agent_id: target.agent_id.clone(),
        accepted: true,
        command_id: Some(command_id),
        duplicate: Some(outcome.duplicate),
        delivered: Some(outcome.delivered && record == RecordResult::AlreadyRecorded),
        error_code: None,
        error_message: None,
    }
}

/// Builds the rejected [`proto::BulkCommandResult`] for one bulk target.
///
/// `error_code`/`error_message` are this crate's existing, redacted
/// [`CommandErrorCode`]/message pair (`errors.rs`) -- never a bulk-specific
/// taxonomy -- so a caller that already handles `SubmitCommand` errors
/// handles a rejected bulk target without a new case to learn.
pub(super) fn rejected_bulk_result(
    target: &proto::BulkCommandTarget,
    error: CommandError,
) -> proto::BulkCommandResult {
    proto::BulkCommandResult {
        workspace_id: target.workspace_id.clone(),
        namespace_id: target.namespace_id.clone(),
        agent_id: target.agent_id.clone(),
        accepted: false,
        command_id: None,
        duplicate: None,
        delivered: None,
        error_code: Some(error.code.as_str().to_owned()),
        error_message: Some(error.message().to_owned()),
    }
}

/// Maps a stored delivery record onto the wire type.
///
/// `parameters` is decoded from the bytes recorded at accept time. A record
/// that somehow fails to decode yields `None` rather than an error: the
/// command's action, target and reason are what a `stop` needs, and refusing
/// to deliver a `stop` because an optional parameters blob is unreadable would
/// be the wrong trade on this channel.
pub(super) fn pending_to_proto(command: PendingCommand) -> proto::PendingControlCommand {
    let action = action_to_proto(&command.action);
    proto::PendingControlCommand {
        command_id: command.command_id,
        workspace_id: command.workspace_id,
        namespace_id: command.namespace_id,
        agent_id: command.agent_id,
        run_id: command.run_id,
        trace_id: command.trace_id,
        action: action as i32,
        reason_code: command.reason_code,
        parameters: if command.parameters.is_empty() {
            None
        } else {
            <prost_types::Struct as prost::Message>::decode(command.parameters.as_slice()).ok()
        },
        issued_at: command.issued_at,
        delivery_attempt: command.delivery_attempt,
    }
}
