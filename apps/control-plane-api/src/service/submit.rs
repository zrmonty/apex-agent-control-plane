//! The write path: `SubmitCommand` and `SubmitBulkCommand`. Both funnel
//! through [`ControlGatewayService::accept_and_record`], and `force_stop`
//! additionally funnels through [`ControlGatewayService::submit_force_stop`]'s
//! dual-approval gate -- see [`crate::dual_approval`].

use apex_event_ingest::IngestRequest;

use crate::auth::{OperatorCaller, OperatorCredentialResolver};
use crate::dual_approval::{ApprovalKey, ApprovalOutcome};
use crate::envelope::{
    AcceptedCommand, ControlCommandInput, build_control_request, derive_target_command_id,
    resolve_command_id_and_timestamp, validate_bulk_id,
};
use crate::errors::{CommandError, CommandErrorCode};
use crate::inbox::{DeliveryStatus, InboxKey, PendingCommand, RecordResult};
use crate::outbox::submit_command;
use crate::proto;

use super::proto_mapping::{accepted_bulk_result, rejected_bulk_result};
use super::{ControlGatewayService, MAX_BULK_COMMAND_TARGETS};

impl<R: OperatorCredentialResolver> ControlGatewayService<R> {
    /// The `force_stop` path: validates scope exactly as the single-operator
    /// path does, then runs the submission through [`DualApprovalGate`]
    /// instead of straight to [`build_control_request`].
    ///
    /// A `command_id` that has *already* been durably recorded (an
    /// operator's idempotent retry of a `force_stop` that already went
    /// through) skips the approval dance entirely and falls straight through
    /// to the ordinary accept path, which recognises it as a duplicate the
    /// same way every other action's retry already does. Without this check,
    /// a retried, already-enacted `force_stop` would re-enter
    /// `AwaitingSecond` -- the approval gate's in-memory slot for that
    /// `command_id` was cleared the moment the second approval landed -- and
    /// an operator would be told to find a second approver again for a
    /// command that already ran.
    async fn submit_force_stop(
        &self,
        input: ControlCommandInput,
        operator: OperatorCaller,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        if !operator.allows_scope(&input.workspace_id, &input.namespace_id) {
            return Err(CommandError::scope_denied().into_status());
        }
        let (command_id, _timestamp) =
            resolve_command_id_and_timestamp(input.command_id.clone())
                .map_err(CommandError::into_status)?;

        let status_key = InboxKey {
            workspace_id: input.workspace_id.clone(),
            namespace_id: input.namespace_id.clone(),
            command_id: command_id.clone(),
        };
        let already_recorded = self
            .inbox_status(&status_key)
            .await?
            .is_some();

        let mut input = input;
        input.command_id = Some(command_id.clone());

        if !already_recorded {
            let approval_key = ApprovalKey {
                workspace_id: input.workspace_id.clone(),
                namespace_id: input.namespace_id.clone(),
                command_id: command_id.clone(),
            };
            let fingerprint = crate::dual_approval::fingerprint(&input);
            let outcome = self
                .dual_approval
                .submit(approval_key, fingerprint, operator.subject())
                .map_err(CommandError::into_status)?;
            match outcome {
                ApprovalOutcome::AwaitingSecond | ApprovalOutcome::AlreadyApprovedBySameOperator => {
                    return Ok(tonic::Response::new(proto::ControlCommandResponse {
                        duplicate: false,
                        command_id,
                        delivered: false,
                        awaiting_second_approval: true,
                    }));
                }
                ApprovalOutcome::FieldMismatch => {
                    return Err(CommandError::new(
                        crate::errors::CommandErrorCode::IdempotencyConflict,
                        "command_id was already approved once with different fields. Use a new command_id for a genuinely different force_stop.",
                    )
                    .into_status());
                }
                ApprovalOutcome::Approved => {}
            }
        }

        let AcceptedCommand {
            command_id,
            request: ingest_request,
            delivery,
        } = build_control_request(input, &operator).map_err(CommandError::into_status)?;
        self.accept_and_record(command_id, ingest_request, delivery)
            .await
    }

    /// Looks up whether `key` has already been durably recorded, off the
    /// tonic worker thread for the same reason every other inbox read on
    /// this service is (`get_command_status` is the sibling of this call).
    async fn inbox_status(
        &self,
        key: &InboxKey,
    ) -> Result<Option<(DeliveryStatus, u32)>, tonic::Status> {
        let inbox = self.inbox.clone();
        let key = key.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            inbox.status(&key, crate::DEFAULT_MAX_DELIVERY_ATTEMPTS)
        })
        .await
        .map_err(|_| CommandError::internal().into_status())?
        .map_err(CommandError::into_status)
    }

    /// The shared tail of every action's accept path: commit the outbox row,
    /// then durably record the delivery, then report. Factored out so
    /// `submit_command`'s single-operator path and `submit_force_stop`'s
    /// second-approval path -- the only two callers -- describe one command
    /// identically rather than risking the two accept paths drifting.
    async fn accept_and_record(
        &self,
        command_id: String,
        ingest_request: IngestRequest,
        delivery: PendingCommand,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        let outbox = self.outbox.clone();
        let inbox = self.inbox.clone();
        let storage_permit = self
            .storage_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CommandError::rate_limited().into_status())?;
        let accept_result = tokio::task::spawn_blocking(move || {
            let _storage_permit = storage_permit;
            // Keep the authoritative outbox commit ahead of the delivery
            // record, but perform both synchronous backend operations in one
            // blocking task so the accept path pays one scheduler handoff.
            let outcome = submit_command(&outbox, &ingest_request)?;
            let delivery_result = inbox.with_lock(|inbox| inbox.record(&delivery))??;
            Ok::<_, CommandError>((outcome, delivery_result))
        })
        .await;
        let (outcome, delivery_result) = match accept_result {
            Ok(Ok(value)) => {
                self.metrics
                    .storage_healthy
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                value
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
            .submissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if outcome.duplicate {
            self.metrics
                .duplicate_submissions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // Recorded *after* the outbox commits, and never conditionally on
        // whether the outbox call said "first acceptance" or "duplicate".
        //
        // Order matters: the outbox row is the authoritative durable
        // acceptance and the audit record, so it commits first. If this
        // second write then fails, the command is still durable and still
        // reaches the trace; the operator gets an error and retries the same
        // `command_id`, which the outbox recognises as a duplicate and which
        // reaches this line again -- and `record` is idempotent, so the retry
        // completes the delivery half without double-queueing it. Returning
        // success here on a failed inbox write is the one thing that would be
        // wrong: it is exactly the "recorded but never delivered" shape this
        // whole work item exists to remove.
        Ok(tonic::Response::new(proto::ControlCommandResponse {
            duplicate: outcome.duplicate,
            command_id,
            // A reused command_id whose outbox row is complete can still
            // create a fresh inbox delivery after retention. Describe that
            // delivery as pending rather than claiming the old trace fanout
            // covers it.
            delivered: outcome.delivered && delivery_result == RecordResult::AlreadyRecorded,
            awaiting_second_approval: false,
        }))
    }

    /// The real logic behind `ControlGateway::submit_command`. Kept as an
    /// inherent method so the trait impl in `service.rs` can stay a thin,
    /// single-block dispatch table -- see that file's module doc.
    pub(super) async fn do_submit_command(
        &self,
        request: tonic::Request<proto::ControlCommandRequest>,
    ) -> Result<tonic::Response<proto::ControlCommandResponse>, tonic::Status> {
        // Independent auth boundary: never falls through to any ingest-path
        // credential, and failures here never touch the ingest rate-limit or
        // idempotency state.
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;
        self.admit(operator.subject())
            .await
            .map_err(CommandError::into_status)?;

        let input = ControlCommandInput::from_request(request.into_inner());

        // `force_stop` is the one action that requires two distinct
        // operators before anything is recorded -- see `dual_approval` for
        // the gate and `Ownership and Team Authorization.md`'s "Production
        // forced stop or bulk control" row for the policy it implements.
        // Every other action keeps the single-operator path below,
        // unchanged.
        if input.action == proto::ControlAction::ForceStop {
            return self.submit_force_stop(input, operator).await;
        }

        let AcceptedCommand {
            command_id,
            request: ingest_request,
            delivery,
        } = build_control_request(input, &operator).map_err(CommandError::into_status)?;
        self.accept_and_record(command_id, ingest_request, delivery)
            .await
    }

    /// The real logic behind `ControlGateway::submit_bulk_command`. See
    /// [`Self::do_submit_command`]'s doc for why this is an inherent method
    /// rather than living directly in the trait impl.
    pub(super) async fn do_submit_bulk_command(
        &self,
        request: tonic::Request<proto::SubmitBulkCommandRequest>,
    ) -> Result<tonic::Response<proto::SubmitBulkCommandResponse>, tonic::Status> {
        // Same independent operator auth boundary as `submit_command`. There
        // is no separate "bulk operator" credential space -- an operator who
        // may issue a command into a scope may issue it in bulk, and an
        // operator who may not is refused per-target below exactly as they
        // would be refused by a single `SubmitCommand` call.
        let operator = self
            .auth
            .authenticate(request.metadata())
            .map_err(CommandError::into_status)?;

        let input = request.into_inner();
        if input.targets.is_empty() {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "SubmitBulkCommand requires at least one target.",
            )
            .into_status());
        }
        if input.targets.len() > MAX_BULK_COMMAND_TARGETS {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "SubmitBulkCommand exceeds the maximum number of targets allowed in one call.",
            )
            .into_status());
        }
        // The action is a single request-level field shared by every target,
        // not a per-target property, so an unspecified action is a
        // whole-request failure -- surfaced once, here -- rather than the
        // same per-target rejection repeated `targets.len()` times.
        let action = proto::ControlAction::try_from(input.action)
            .unwrap_or(proto::ControlAction::Unspecified);
        if crate::envelope::action_name(action).is_none() {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "action must be one of stop, pause, resume, inject, set_budget.",
            )
            .into_status());
        }

        let (bulk_id, bulk_millis) =
            validate_bulk_id(input.bulk_id).map_err(CommandError::into_status)?;

        // Phase 1: per-target admission and validation. Both are cheap,
        // synchronous, in-memory operations -- no storage I/O -- so they run
        // directly on this async task. Scope authorization happens here, via
        // `build_control_request`'s own `operator.allows_scope` check, run
        // once per target: an operator scoped to one workspace gets exactly
        // the same `SCOPE_DENIED` for a target outside it that a standalone
        // `SubmitCommand` call would give them, and nothing about being
        // inside a bulk call widens that.
        //
        // The admission ceiling is charged once per target -- the same
        // ceiling `submit_command` charges once per call -- so a bulk call
        // cannot admit more durable commands per second than the same
        // operator issuing them one at a time would be allowed to. Checked
        // sequentially rather than concurrently: `MAX_BULK_COMMAND_TARGETS`
        // already bounds the total to a size where sequential admission
        // checks stay well inside the latency this channel already accepts
        // for a full poll batch, and sequential is simpler to reason about
        // than parallel admission racing itself over the same operator
        // bucket.
        let target_count = input.targets.len();
        let mut slots: Vec<Option<proto::BulkCommandResult>> = Vec::with_capacity(target_count);
        let mut pending = Vec::with_capacity(target_count);
        // Targets are moved out of `input.targets` (rather than borrowed and
        // cloned) since each target is used at most twice -- once to build
        // its `ControlCommandInput` (which still needs its own owned copies
        // of the target's fields, because the target itself is kept alive
        // for the result below) and once, by value, to build the
        // `BulkCommandResult` that reports on it. Nothing here reuses
        // `input.targets` afterward, so moving is behavior-identical to the
        // old borrow-and-clone and removes one full `BulkCommandTarget`
        // clone (five `String` allocations) per accepted target.
        for target in input.targets {
            if let Err(error) = self.admit(operator.subject()).await {
                slots.push(Some(rejected_bulk_result(target, error)));
                continue;
            }
            let command_id = derive_target_command_id(&bulk_id, bulk_millis, &target);
            let command_input = ControlCommandInput {
                command_id: Some(command_id),
                workspace_id: target.workspace_id.clone(),
                namespace_id: target.namespace_id.clone(),
                agent_id: target.agent_id.clone(),
                run_id: target.run_id.clone(),
                parent_run_id: target.parent_run_id.clone(),
                trace_id: target.trace_id.clone(),
                action,
                reason_code: input.reason_code.clone(),
                parameters: input.parameters.clone(),
            };
            match build_control_request(command_input, &operator) {
                Ok(accepted) => {
                    slots.push(None);
                    pending.push((slots.len() - 1, target, accepted));
                }
                Err(error) => slots.push(Some(rejected_bulk_result(target, error))),
            }
        }

        // Phase 2: durable writes for whatever passed phase 1, batched into
        // one blocking task holding a single storage permit for the whole
        // call -- see `MAX_BULK_COMMAND_TARGETS`'s own comment for why that
        // ceiling exists. Skipped entirely when every target already failed
        // phase 1, so an all-rejected bulk call never touches storage at all.
        if !pending.is_empty() {
            let outbox = self.outbox.clone();
            let inbox = self.inbox.clone();
            let storage_permit = self
                .storage_slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| CommandError::rate_limited().into_status())?;
            let write_results = tokio::task::spawn_blocking(move || {
                let _storage_permit = storage_permit;
                pending
                    .into_iter()
                    .map(|(slot, target, accepted)| {
                        let AcceptedCommand {
                            command_id,
                            request: ingest_request,
                            delivery,
                        } = accepted;
                        // Same ordering as `submit_command`: the outbox
                        // commit is the authoritative durable acceptance and
                        // audit record, so it happens before the inbox
                        // delivery record for this same target.
                        let result: Result<_, CommandError> = (|| {
                            let outcome = submit_command(&outbox, &ingest_request)?;
                            let record = inbox.with_lock(|inbox| inbox.record(&delivery))??;
                            Ok((outcome, record))
                        })();
                        (slot, target, command_id, result)
                    })
                    .collect::<Vec<_>>()
            })
            .await
            .map_err(|_| CommandError::internal().into_status())?;

            // A per-target storage failure here is the same signal
            // `submit_command` treats as a storage-health flip for its one
            // target; folded across the whole batch, any failure marks the
            // gateway unhealthy exactly as it would if that target had
            // arrived as its own `SubmitCommand` call.
            let mut any_storage_failure = false;
            for (slot, target, command_id, result) in write_results {
                let filled = match result {
                    Ok((outcome, record)) => {
                        self.metrics
                            .submissions
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if outcome.duplicate {
                            self.metrics
                                .duplicate_submissions
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        accepted_bulk_result(target, command_id, outcome, record)
                    }
                    Err(error) => {
                        any_storage_failure = true;
                        rejected_bulk_result(target, error)
                    }
                };
                slots[slot] = Some(filled);
            }
            self.metrics.storage_healthy.store(
                !any_storage_failure,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        let results = slots
            .into_iter()
            .map(|slot| slot.expect("every target index is filled exactly once, by phase 1 or phase 2"))
            .collect();

        Ok(tonic::Response::new(proto::SubmitBulkCommandResponse {
            bulk_id,
            results,
        }))
    }
}
