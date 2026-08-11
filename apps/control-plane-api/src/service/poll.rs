//! The agent-facing path: `PollCommands` and `AckCommand`. Both authenticate
//! against the agent workload credential space (`agent_auth`), never the
//! operator one -- see [`crate::agent_auth`].

use crate::agent_auth::peer_identity_from_request;
use crate::auth::OperatorCredentialResolver;
use crate::errors::CommandError;
use crate::inbox::{AckResult, InboxKey, PendingCommand, PollTarget};
use crate::proto;

use super::proto_mapping::pending_to_proto;
use super::{CallerScopes, ControlGatewayService};

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    /// The real logic behind `ControlGateway::poll_commands`. Kept as an
    /// inherent method so the trait impl in `service.rs` can stay a thin,
    /// single-block dispatch table -- see that file's module doc.
    ///
    /// Returns the commands pending for the **calling agent**.
    ///
    /// The security shape of this method, in order:
    ///
    /// 1. The caller is authenticated against the agent workload credential
    ///    space (`agent_auth`), never the operator one. An operator token
    ///    cannot reach past this line.
    /// 2. The agent identity is `caller.bound_agent_id()` -- derived from the
    ///    credential. An unbound caller is refused outright rather than
    ///    defaulted to anything.
    /// 3. The permitted scopes are the caller's own, asked through
    ///    [`CallerScopes`].
    /// 4. The only request field read is `max_commands`, and it is clamped
    ///    into the gateway's own bounds. It can shorten a result set the
    ///    caller was already entitled to and nothing else.
    ///
    /// There is deliberately no branch anywhere below on an `agent_id`,
    /// `run_id`, `workspace_id` or `namespace_id` from the request, because
    /// the request has none. Adding one would be a security change.
    pub(super) async fn do_poll_commands(
        &self,
        request: tonic::Request<proto::PollCommandsRequest>,
    ) -> Result<tonic::Response<proto::PollCommandsResponse>, tonic::Status> {
        let peer = peer_identity_from_request(&request);
        let caller = self
            .agent_auth
            .authenticate(request.metadata(), peer.as_ref())
            .map_err(CommandError::into_status)?;
        // `authenticated_for_agent` is the only public constructor an external
        // resolver can use and it always binds an agent id, so this is
        // belt-and-braces -- but an unbound caller reaching a per-agent
        // retrieval path is precisely the bug worth failing closed on rather
        // than assuming away.
        let Some(agent_id) = caller.bound_agent_id().map(str::to_owned) else {
            return Err(CommandError::unauthenticated().into_status());
        };
        let subject = caller.subject().unwrap_or(&agent_id).to_owned();
        self.admit_poll(&subject)
            .await
            .map_err(CommandError::into_status)?;

        let requested = request.get_ref().max_commands as usize;
        let limit = if requested == 0 {
            crate::inbox::DEFAULT_MAX_COMMANDS_PER_POLL
        } else {
            requested.min(crate::inbox::MAX_COMMANDS_PER_POLL)
        };
        let target = PollTarget {
            agent_id: agent_id.clone(),
            limit,
        };

        let inbox = self.inbox.clone();
        let policy = self.delivery_policy;
        let now_millis = crate::envelope::now_unix_millis();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        // `spawn_blocking` for the same reason the accept path uses it: the
        // inbox is behind a mutex, its durable backend performs synchronous
        // I/O, and neither may run on a tonic worker thread.
        let claim_result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox
                .with_lock(|inbox| inbox.claim(&target, &CallerScopes(&caller), policy, now_millis))
        })
        .await;
        let claimed: Vec<PendingCommand> = match claim_result {
            Ok(Ok(Ok(claimed))) => {
                self.metrics
                    .storage_healthy
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                claimed
            }
            Ok(Ok(Err(error))) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(error.into_status());
            }
            Ok(Err(error)) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(error.into_status());
            }
            Err(_) => {
                self.metrics
                    .storage_healthy
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(CommandError::internal().into_status());
            }
        };

        self.metrics
            .polls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(tonic::Response::new(proto::PollCommandsResponse {
            commands: claimed.into_iter().map(pending_to_proto).collect(),
            agent_id,
            min_poll_interval_seconds: self.min_poll_interval_seconds(),
        }))
    }

    /// The real logic behind `ControlGateway::ack_command`. See
    /// [`Self::do_poll_commands`]'s doc for why this is an inherent method
    /// rather than living directly in the trait impl.
    pub(super) async fn do_ack_command(
        &self,
        request: tonic::Request<proto::AckCommandRequest>,
    ) -> Result<tonic::Response<proto::AckCommandResponse>, tonic::Status> {
        let peer = peer_identity_from_request(&request);
        let caller = self
            .agent_auth
            .authenticate(request.metadata(), peer.as_ref())
            .map_err(CommandError::into_status)?;
        let Some(agent_id) = caller.bound_agent_id().map(str::to_owned) else {
            return Err(CommandError::unauthenticated().into_status());
        };
        let input = request.into_inner();
        if input.workspace_id.is_empty()
            || input.namespace_id.is_empty()
            || input.command_id.is_empty()
            || input.delivery_attempt == 0
        {
            return Err(CommandError::invalid_command().into_status());
        }
        if !caller.allows_scope(&format!("{}/{}", input.workspace_id, input.namespace_id)) {
            return Err(CommandError::scope_denied().into_status());
        }
        let target = PollTarget { agent_id, limit: 1 };
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
            inbox.acknowledge(&target, &key, input.delivery_attempt, now_millis)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)?;
        let (acknowledged, already_acknowledged) = match result {
            AckResult::Acknowledged => (true, false),
            AckResult::AlreadyAcknowledged => (false, true),
            AckResult::NotFound => (false, false),
        };
        Ok(tonic::Response::new(proto::AckCommandResponse {
            command_id: input.command_id,
            acknowledged,
            already_acknowledged,
        }))
    }
}
