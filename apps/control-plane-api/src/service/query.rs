//! The operator-facing query/management path: `GetCommandStatus`,
//! `ListCommands`, and `CancelCommand`. All three authenticate against the
//! operator credential space and scope-check
//! `operator.allows_scope(workspace_id, namespace_id)`, never touching the
//! agent workload credential space `poll`'s handlers use.

use crate::auth::OperatorCredentialResolver;
use crate::errors::CommandError;
use crate::inbox::{CancelResult, InboxKey};
use crate::proto;

use super::ControlGatewayService;
use super::proto_mapping::{command_summary_to_proto, delivery_status_to_proto, proto_state_to_delivery_status};

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    /// The real logic behind `ControlGateway::get_command_status`. Kept as an
    /// inherent method so the trait impl in `service.rs` can stay a thin,
    /// single-block dispatch table -- see that file's module doc.
    pub(super) async fn do_get_command_status(
        &self,
        request: tonic::Request<proto::GetCommandStatusRequest>,
    ) -> Result<tonic::Response<proto::GetCommandStatusResponse>, tonic::Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }
        let key = InboxKey {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            command_id: input.command_id.clone(),
        };
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.status(&key, crate::DEFAULT_MAX_DELIVERY_ATTEMPTS)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (state, delivery_attempt) = result
            .map(|(status, attempt)| (delivery_status_to_proto(status), attempt))
            .unwrap_or((proto::CommandDeliveryState::Unspecified, 0));
        Ok(tonic::Response::new(proto::GetCommandStatusResponse {
            command_id: input.command_id,
            state: state as i32,
            delivery_attempt,
        }))
    }

    /// The real logic behind `ControlGateway::list_commands`. See
    /// [`Self::do_get_command_status`]'s doc for why this is an inherent
    /// method rather than living directly in the trait impl.
    pub(super) async fn do_list_commands(
        &self,
        request: tonic::Request<proto::ListCommandsRequest>,
    ) -> Result<tonic::Response<proto::ListCommandsResponse>, tonic::Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        let input = request.into_inner();
        if input.workspace_id.is_empty() || input.namespace_id.is_empty() {
            return Err(CommandError::invalid_command().into_status());
        }
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }

        // A cursor, not an offset: resuming strictly after the last-seen
        // sequence is what keeps a page stable while commands are
        // concurrently recorded, delivered, and settled underneath a paging
        // operator. An unparsable token is refused rather than silently
        // treated as "start over", which would make a corrupted or forged
        // token look like an empty scope instead of an error.
        let after_sequence = if input.page_token.is_empty() {
            0
        } else {
            input
                .page_token
                .parse::<u64>()
                .map_err(|_| CommandError::invalid_command().into_status())?
        };
        let requested = input.page_size as usize;
        let limit = if requested == 0 {
            crate::inbox::DEFAULT_LIST_COMMANDS_PAGE_SIZE
        } else {
            // The hard ceiling: a caller can only ever narrow the page it
            // asks for, never raise it past MAX_LIST_COMMANDS_PAGE_SIZE.
            requested.min(crate::inbox::MAX_LIST_COMMANDS_PAGE_SIZE)
        };
        let state = proto::CommandDeliveryState::try_from(input.state)
            .ok()
            .and_then(proto_state_to_delivery_status);
        let agent_id = input.agent_id.filter(|value| !value.is_empty());
        let workspace_id = input.workspace_id;
        let namespace_id = input.namespace_id;

        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        // `spawn_blocking` for the same reason every other inbox-touching
        // path here uses it: the inbox is behind a mutex and its durable
        // backend performs synchronous I/O.
        let page = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            let query = crate::inbox::ListCommandsQuery {
                workspace_id: &workspace_id,
                namespace_id: &namespace_id,
                agent_id: agent_id.as_deref(),
                state,
                after_sequence,
                limit,
                max_attempts: crate::DEFAULT_MAX_DELIVERY_ATTEMPTS,
            };
            inbox.list_commands(&query)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;

        let next_page_token = if page.has_more {
            page.commands
                .last()
                .map(|command| command.sequence.to_string())
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(tonic::Response::new(proto::ListCommandsResponse {
            commands: page
                .commands
                .into_iter()
                .map(command_summary_to_proto)
                .collect(),
            next_page_token,
        }))
    }

    /// The real logic behind `ControlGateway::cancel_command`. See
    /// [`Self::do_get_command_status`]'s doc for why this is an inherent
    /// method rather than living directly in the trait impl.
    ///
    /// Retracts a command an operator issued, before it has ever reached its
    /// target agent.
    ///
    /// Authenticated and scope-checked identically to `get_command_status`
    /// above -- same operator credential space, same
    /// `operator.allows_scope(workspace_id, namespace_id)` gate, no agent
    /// identity involved. The only new behaviour is in the inbox: `cancel`
    /// refuses (rather than performs) the mutation once the command has been
    /// delivered even once, because at that point the agent may already be
    /// acting on it and retracting it would recreate exactly the "did the
    /// agent get it or not" ambiguity the delivery-tracking design in
    /// `inbox.rs` exists to eliminate.
    pub(super) async fn do_cancel_command(
        &self,
        request: tonic::Request<proto::CancelCommandRequest>,
    ) -> Result<tonic::Response<proto::CancelCommandResponse>, tonic::Status> {
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }
        let key = InboxKey {
            workspace_id: input.workspace_id,
            namespace_id: input.namespace_id,
            command_id: input.command_id.clone(),
        };
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let now_millis = crate::envelope::now_unix_millis();
        let result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.cancel(&key, now_millis)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (cancelled, already_cancelled) = match result {
            CancelResult::Cancelled => (true, false),
            CancelResult::AlreadyCancelled => (false, true),
            CancelResult::NotFound => (false, false),
        };
        Ok(tonic::Response::new(proto::CancelCommandResponse {
            command_id: input.command_id,
            cancelled,
            already_cancelled,
        }))
    }
}
