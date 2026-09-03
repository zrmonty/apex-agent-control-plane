//! PostgreSQL-backed command delivery state for multi-replica gateways.
//!
//! The event outbox and this inbox intentionally have separate tables and
//! separate completion state. They share a database connection authority so
//! a command accepted by one gateway replica is visible to an agent polling
//! another, while the outbox remains the audit/fanout authority.

use postgres::Client;

use super::{
    CommandInbox, CommandSummary, DeliveryPolicy, DeliveryStatus, ListCommandsPage,
    ListCommandsQuery, PendingCommand, PollTarget, RecordResult, ScopeAuthorizer, command_hash,
    is_recordable, resolve_delivery_status,
};
use crate::errors::{CommandError, CommandErrorCode};

const INBOX_SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0003_u64 as i64;
const CLAIM_BATCH: i64 = 1_024;

pub struct PostgresCommandInbox {
    client: Client,
    capacity: usize,
    /// Per-`(workspace_id, namespace_id)` ceiling, enforced in *addition* to
    /// `capacity`. See [`super::DEFAULT_INBOX_SCOPE_QUOTA`].
    scope_quota: usize,
}

#[path = "inbox_postgres/recovering.rs"]
mod recovering;

pub use recovering::RecoveringPostgresCommandInbox;

impl PostgresCommandInbox {
    pub fn connect(
        connection_string: &str,
        capacity: usize,
        scope_quota: usize,
    ) -> Result<Self, CommandError> {
        if capacity == 0 || capacity > super::DEFAULT_INBOX_CAPACITY {
            return Err(configuration_error());
        }
        // Same fail-loud discipline as `capacity` immediately above: a
        // misconfigured per-scope quota (zero, or wider than the global
        // ceiling it is supposed to sit inside of) is a startup error, not a
        // value to silently clamp.
        if scope_quota == 0 || scope_quota > capacity {
            return Err(configuration_error());
        }
        let mut client = apex_durability::connect_postgres(connection_string)
            .map_err(|_| configuration_error())?;
        apex_durability::apply_postgres_schema(
            &mut client,
            INBOX_SCHEMA_LOCK,
            include_str!("../../../deploy/postgres/control_inbox.sql"),
        )
        .map_err(|_| configuration_error())?;
        Ok(Self {
            client,
            capacity,
            scope_quota,
        })
    }
}

impl CommandInbox for PostgresCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        if !is_recordable(command) {
            return Err(CommandError::new(
                CommandErrorCode::InvalidCommand,
                "The command was malformed: check target identifiers, action, and required parameters for the requested action.",
            ));
        }
        let hash = command_hash(command)?;
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| CommandError::internal())?;
        let existing = tx
            .query_opt(
                "SELECT command_hash FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3
                 FOR UPDATE",
                &[
                    &command.workspace_id,
                    &command.namespace_id,
                    &command.command_id,
                ],
            )
            .map_err(|_| CommandError::internal())?;
        if let Some(row) = existing {
            let stored: Vec<u8> = row.get(0);
            tx.commit().map_err(|_| CommandError::internal())?;
            if stored == hash {
                return Ok(RecordResult::AlreadyRecorded);
            }
            return Err(CommandError::new(
                CommandErrorCode::IdempotencyConflict,
                "command_id was already recorded with different delivery fields. Use a new command_id for a genuinely different command.",
            ));
        }

        // Scoped advisory lock: closes the TOCTOU window between the
        // per-scope COUNT below and the INSERT further down. Under Postgres's
        // default READ COMMITTED isolation those were two separate
        // statements with nothing serialising them, so two concurrent
        // `record()` calls for the SAME scope -- different tokio tasks,
        // different replicas, each on its own connection -- could both read
        // the count as under quota and both commit, overshooting the
        // per-scope ceiling the fairness fix below exists to enforce.
        // `pg_advisory_xact_lock` auto-releases at commit or rollback (unlike
        // `apply_postgres_schema`'s session-scoped lock/unlock pair in
        // `postgres_transport.rs`, which is session-scoped on purpose for a
        // different reason), so a caller that errors out of this function
        // anywhere below still releases it when `tx` drops.
        //
        // Deliberately scoped to `(workspace_id, namespace_id)` via
        // `hashtext`, not a single fixed key: a global lock here would
        // serialise every tenant's inserts against each other and defeat the
        // point of a multi-tenant, scale-first system, to protect a boundary
        // that only ever needs correctness *per scope*. `hashtext` is a
        // 32-bit hash, so two different scopes can in principle collide onto
        // the same lock key; that costs unrelated tenants some extra
        // serialisation on an unlucky hash collision, which is a performance
        // detail, not a correctness one -- the count-then-insert below is
        // still scoped to the caller's own `workspace_id`/`namespace_id`.
        let scope_lock_key = format!("{}|{}", command.workspace_id, command.namespace_id);
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1))",
            &[&scope_lock_key],
        )
        .map_err(|_| CommandError::internal())?;

        let scope_count: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2",
                &[&command.workspace_id, &command.namespace_id],
            )
            .map_err(|_| CommandError::internal())?
            .get(0);
        if scope_count >= self.scope_quota as i64 {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "This workspace/namespace has reached its share of the durable command inbox. Retry after operator remediation.",
            ));
        }

        // The global ceiling is intentionally left lock-free across scopes.
        // It can therefore still be overshot by a small margin under extreme
        // concurrency spanning many *different* scopes recording
        // simultaneously -- each holds only its own scope's advisory lock, so
        // several of them can pass this COUNT concurrently the same way the
        // per-scope count used to. That is an accepted, explicitly-reasoned
        // tradeoff: the per-scope quota above is the actual security boundary
        // being protected (one tenant cannot starve every other tenant's
        // delivery, including an emergency `stop`), not the exact value of
        // the global number, and a global lock to make the global ceiling
        // exact would serialise unrelated tenants against each other for a
        // guarantee this system does not need.
        let count: i64 = tx
            .query_one("SELECT COUNT(*) FROM apex_control_inbox", &[])
            .map_err(|_| CommandError::internal())?
            .get(0);
        if count >= self.capacity as i64 {
            return Err(CommandError::new(
                CommandErrorCode::Capacity,
                "The durable command inbox is at capacity. Retry after operator remediation.",
            ));
        }

        let inserted = tx
            .execute(
                "INSERT INTO apex_control_inbox
                 (workspace_id, namespace_id, command_id, command_hash,
                  agent_id, run_id, trace_id, action, reason_code, parameters,
                  issued_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 ON CONFLICT (workspace_id, namespace_id, command_id) DO NOTHING",
                &[
                    &command.workspace_id,
                    &command.namespace_id,
                    &command.command_id,
                    &hash.as_slice(),
                    &command.agent_id,
                    &command.run_id,
                    &command.trace_id,
                    &command.action,
                    &command.reason_code,
                    &command.parameters.as_slice(),
                    &command.issued_at,
                ],
            )
            .map_err(|_| CommandError::internal())?;
        if inserted == 0 {
            let stored: Vec<u8> = tx
                .query_one(
                    "SELECT command_hash FROM apex_control_inbox
                     WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3",
                    &[
                        &command.workspace_id,
                        &command.namespace_id,
                        &command.command_id,
                    ],
                )
                .map_err(|_| CommandError::internal())?
                .get(0);
            tx.commit().map_err(|_| CommandError::internal())?;
            return if stored == hash {
                Ok(RecordResult::AlreadyRecorded)
            } else {
                Err(CommandError::new(
                    CommandErrorCode::IdempotencyConflict,
                    "command_id was already recorded with different delivery fields. Use a new command_id for a genuinely different command.",
                ))
            };
        }
        tx.commit().map_err(|_| CommandError::internal())?;
        Ok(RecordResult::Recorded)
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        let max_attempts = i64::from(policy.max_attempts);
        let redelivery_after = i64::try_from(policy.redelivery_after.as_millis())
            .map_err(|_| CommandError::internal())?;
        let now_millis = i64::try_from(now_millis).map_err(|_| CommandError::internal())?;
        let mut tx = self
            .client
            .transaction()
            .map_err(|_| CommandError::internal())?;
        let mut cursor = 0_i64;
        let mut selected = Vec::with_capacity(target.limit);

        // Scan in bounded batches so a credential with no matching scope does
        // not make the gateway load every command payload into memory. The
        // sequence cursor keeps the scan progressing past rows the caller is
        // authenticated but not authorised to read.
        while selected.len() < target.limit {
            let rows = tx
                .query(
                    "SELECT sequence, workspace_id, namespace_id, command_id
                     FROM apex_control_inbox
                     WHERE agent_id = $1
                       AND acknowledged_at_millis IS NULL
                       AND cancelled_at_millis IS NULL
                       AND attempts < $2
                       AND (last_delivered_millis IS NULL
                            OR $3 - last_delivered_millis >= $4)
                       AND sequence > $5
                     ORDER BY sequence ASC
                     LIMIT $6
                     FOR UPDATE SKIP LOCKED",
                    &[
                        &target.agent_id,
                        &max_attempts,
                        &now_millis,
                        &redelivery_after,
                        &cursor,
                        &CLAIM_BATCH,
                    ],
                )
                .map_err(|_| CommandError::internal())?;
            if rows.is_empty() {
                break;
            }
            for row in &rows {
                let sequence: i64 = row.get(0);
                cursor = sequence;
                let workspace_id: String = row.get(1);
                let namespace_id: String = row.get(2);
                if scopes.allows(&workspace_id, &namespace_id) {
                    selected.push(sequence);
                    if selected.len() >= target.limit {
                        break;
                    }
                }
            }
            if rows.len() < CLAIM_BATCH as usize {
                break;
            }
        }

        let mut claimed = Vec::with_capacity(selected.len());
        if !selected.is_empty() {
            let rows = tx
                .query(
                    "UPDATE apex_control_inbox
                     SET attempts = attempts + 1, last_delivered_millis = $1
                     WHERE sequence = ANY($2::bigint[])
                     RETURNING sequence, command_id, workspace_id, namespace_id, agent_id,
                               run_id, trace_id, action, reason_code, parameters,
                               issued_at, attempts",
                    &[&now_millis, &selected],
                )
                .map_err(|_| CommandError::internal())?;
            if rows.len() != selected.len() {
                return Err(CommandError::internal());
            }

            // PostgreSQL does not promise UPDATE ... RETURNING order. Restore
            // the sequence order promised by the file and memory backends.
            let mut returned: Vec<_> = rows
                .into_iter()
                .map(|row| {
                    let sequence: i64 = row.get(0);
                    let command = PendingCommand {
                        command_id: row.get(1),
                        workspace_id: row.get(2),
                        namespace_id: row.get(3),
                        agent_id: row.get(4),
                        run_id: row.get(5),
                        trace_id: row.get(6),
                        action: row.get(7),
                        reason_code: row.get(8),
                        parameters: row.get(9),
                        issued_at: row.get(10),
                        delivery_attempt: row.get::<_, i64>(11).try_into().unwrap_or(u32::MAX),
                    };
                    (sequence, command)
                })
                .collect();
            returned.sort_unstable_by_key(|(sequence, _)| *sequence);

            for (_, command) in returned {
                if !is_recordable(&command) {
                    return Err(configuration_error());
                }
                claimed.push(command);
            }
        }
        tx.commit().map_err(|_| CommandError::internal())?;
        Ok(claimed)
    }

    fn undelivered_count(&mut self) -> usize {
        self.try_undelivered_count().unwrap_or(0)
    }

    fn pending_count(&mut self) -> usize {
        self.try_pending_count().unwrap_or(0)
    }

    fn try_undelivered_count(&mut self) -> Result<usize, CommandError> {
        let count: i64 = self
            .client
            .query_one(
                "SELECT COUNT(*) FROM apex_control_inbox
                 WHERE attempts = 0 AND cancelled_at_millis IS NULL",
                &[],
            )
            .map_err(|_| CommandError::internal())?
            .get(0);
        usize::try_from(count).map_err(|_| CommandError::internal())
    }

    fn try_pending_count(&mut self) -> Result<usize, CommandError> {
        let count: i64 = self
            .client
            .query_one("SELECT COUNT(*) FROM apex_control_inbox", &[])
            .map_err(|_| CommandError::internal())?
            .get(0);
        usize::try_from(count).map_err(|_| CommandError::internal())
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &super::InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<super::AckResult, CommandError> {
        let now_millis = i64::try_from(now_millis).map_err(|_| CommandError::internal())?;
        let updated = self
            .client
            .execute(
                "UPDATE apex_control_inbox
                 SET acknowledged_at_millis = $1
                 WHERE workspace_id = $2 AND namespace_id = $3 AND command_id = $4
                   AND agent_id = $5
                   AND acknowledged_at_millis IS NULL
                   AND attempts >= $6",
                &[
                    &now_millis,
                    &key.workspace_id,
                    &key.namespace_id,
                    &key.command_id,
                    &target.agent_id,
                    &i64::from(delivery_attempt),
                ],
            )
            .map_err(|_| CommandError::internal())?;
        if updated > 0 {
            return Ok(super::AckResult::Acknowledged);
        }
        let existing = self
            .client
            .query_opt(
                "SELECT acknowledged_at_millis FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3
                   AND agent_id = $4",
                &[
                    &key.workspace_id,
                    &key.namespace_id,
                    &key.command_id,
                    &target.agent_id,
                ],
            )
            .map_err(|_| CommandError::internal())?;
        Ok(match existing {
            Some(row) if row.get::<_, Option<i64>>(0).is_some() => {
                super::AckResult::AlreadyAcknowledged
            }
            _ => super::AckResult::NotFound,
        })
    }

    fn status(
        &mut self,
        key: &super::InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(super::DeliveryStatus, u32)>, CommandError> {
        let row = self
            .client
            .query_opt(
                "SELECT attempts, last_delivered_millis, acknowledged_at_millis, cancelled_at_millis
                 FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3",
                &[&key.workspace_id, &key.namespace_id, &key.command_id],
            )
            .map_err(|_| CommandError::internal())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let attempts = row.get::<_, i64>(0).try_into().unwrap_or(u32::MAX);
        let acknowledged = row.get::<_, Option<i64>>(2).is_some();
        let cancelled = row.get::<_, Option<i64>>(3).is_some();
        let state = resolve_delivery_status(cancelled, acknowledged, attempts, max_attempts);
        Ok(Some((state, attempts)))
    }

    /// Scoped, cursor-paginated enumeration for `ListCommands`.
    ///
    /// A single bounded query rather than `claim`'s batched scan-loop: the
    /// difference is that `claim`'s filter is an opaque `ScopeAuthorizer`
    /// callback the SQL engine cannot evaluate, so it has to pull rows into
    /// Rust in bounded batches to apply it. `agent_id` and `state` here are
    /// both plain values, fully expressible as SQL predicates, so Postgres
    /// itself can keep scanning the `(workspace_id, namespace_id, sequence)`
    /// index past non-matching rows within the one query -- there is nothing
    /// a Rust-side batching loop would add except extra round trips.
    ///
    /// `LIMIT` asks for one row past the caller's limit so `has_more`
    /// reflects whether a further matching row genuinely exists, without a
    /// second `COUNT` query.
    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        let after_sequence = i64::try_from(query.after_sequence).unwrap_or(i64::MAX);
        let max_attempts = i64::from(query.max_attempts);
        let limit = i64::try_from(query.limit).map_err(|_| CommandError::internal())?;
        let fetch_limit = limit.saturating_add(1);
        let state_code: Option<i16> = query.state.map(|state| match state {
            DeliveryStatus::Pending => 1,
            DeliveryStatus::Delivered => 2,
            DeliveryStatus::Acknowledged => 3,
            DeliveryStatus::Exhausted => 4,
            DeliveryStatus::Cancelled => 5,
        });

        let rows = self
            .client
            .query(
                "SELECT sequence, command_id, agent_id, action, attempts, issued_at,
                        acknowledged_at_millis, cancelled_at_millis
                 FROM apex_control_inbox
                 WHERE workspace_id = $1
                   AND namespace_id = $2
                   AND ($3::text IS NULL OR agent_id = $3)
                   AND sequence > $4
                   AND (
                        $5::smallint IS NULL
                        OR ($5 = 1 AND attempts = 0 AND acknowledged_at_millis IS NULL
                            AND cancelled_at_millis IS NULL)
                        OR ($5 = 2 AND attempts > 0 AND attempts < $6
                            AND acknowledged_at_millis IS NULL AND cancelled_at_millis IS NULL)
                        OR ($5 = 3 AND acknowledged_at_millis IS NOT NULL)
                        OR ($5 = 4 AND attempts >= $6 AND acknowledged_at_millis IS NULL
                            AND cancelled_at_millis IS NULL)
                        OR ($5 = 5 AND cancelled_at_millis IS NOT NULL)
                   )
                 ORDER BY sequence ASC
                 LIMIT $7",
                &[
                    &query.workspace_id,
                    &query.namespace_id,
                    &query.agent_id,
                    &after_sequence,
                    &state_code,
                    &max_attempts,
                    &fetch_limit,
                ],
            )
            .map_err(|_| CommandError::internal())?;

        let has_more = rows.len() > query.limit;
        let mut commands = Vec::with_capacity(query.limit.min(rows.len()));
        for row in rows.iter().take(query.limit) {
            let sequence: i64 = row.get(0);
            let attempts: i64 = row.get(4);
            let acknowledged = row.get::<_, Option<i64>>(6).is_some();
            let cancelled = row.get::<_, Option<i64>>(7).is_some();
            let attempts_u32 = attempts.try_into().unwrap_or(u32::MAX);
            commands.push(CommandSummary {
                command_id: row.get(1),
                agent_id: row.get(2),
                action: row.get(3),
                state: resolve_delivery_status(
                    cancelled,
                    acknowledged,
                    attempts_u32,
                    query.max_attempts,
                ),
                delivery_attempt: attempts_u32,
                issued_at: row.get(5),
                sequence: sequence.try_into().unwrap_or(u64::MAX),
            });
        }
        Ok(ListCommandsPage { commands, has_more })
    }

    /// Retracts a never-delivered command. Same shape as `acknowledge`: an
    /// optimistic `UPDATE ... WHERE` first (atomic and race-safe against a
    /// concurrent `claim` on the same row -- Postgres re-evaluates the WHERE
    /// clause against the committed row once any lock it waits on is
    /// released, so a claim that lands first is always seen), and only on
    /// that update matching zero rows does a follow-up `SELECT` classify why:
    /// unknown key, already cancelled, or already delivered.
    fn cancel(
        &mut self,
        key: &super::InboxKey,
        now_millis: u64,
    ) -> Result<super::CancelResult, CommandError> {
        let now_millis = i64::try_from(now_millis).map_err(|_| CommandError::internal())?;
        let updated = self
            .client
            .execute(
                "UPDATE apex_control_inbox
                 SET cancelled_at_millis = $1
                 WHERE workspace_id = $2 AND namespace_id = $3 AND command_id = $4
                   AND cancelled_at_millis IS NULL
                   AND attempts = 0",
                &[
                    &now_millis,
                    &key.workspace_id,
                    &key.namespace_id,
                    &key.command_id,
                ],
            )
            .map_err(|_| CommandError::internal())?;
        if updated > 0 {
            return Ok(super::CancelResult::Cancelled);
        }
        let existing = self
            .client
            .query_opt(
                "SELECT cancelled_at_millis FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3",
                &[&key.workspace_id, &key.namespace_id, &key.command_id],
            )
            .map_err(|_| CommandError::internal())?;
        match existing {
            None => Ok(super::CancelResult::NotFound),
            Some(row) if row.get::<_, Option<i64>>(0).is_some() => {
                Ok(super::CancelResult::AlreadyCancelled)
            }
            // Row exists, not cancelled, and the UPDATE above matched zero
            // rows -- the only remaining reason is `attempts > 0`.
            Some(_) => Err(CommandError::already_delivered()),
        }
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        let now_millis = i64::try_from(now_millis).map_err(|_| CommandError::internal())?;
        let retention_millis =
            i64::try_from(retention_millis).map_err(|_| CommandError::internal())?;
        self.client
            .execute(
                "DELETE FROM apex_control_inbox
                 WHERE (
                     (cancelled_at_millis IS NOT NULL
                      AND $2 - cancelled_at_millis >= $3)
                     OR (
                         cancelled_at_millis IS NULL
                         AND (acknowledged_at_millis IS NOT NULL OR attempts >= $1)
                         AND last_delivered_millis IS NOT NULL
                         AND $2 - last_delivered_millis >= $3
                     )
                 )",
                &[&i64::from(max_attempts), &now_millis, &retention_millis],
            )
            .map_err(|_| CommandError::internal())?;
        Ok(())
    }
}

fn configuration_error() -> CommandError {
    CommandError::new(
        CommandErrorCode::Internal,
        "The control gateway failed to process the request.",
    )
}

/// Opt-in, like every other live-Postgres test in this repository (mirroring
/// `apps/event-ingest/src/outbox/postgres_tests_cases.rs`'s `url()`): CI does
/// not provision a database for this job, so every test here reads
/// `APEX_CONTROL_POSTGRES_URL` and prints a skip line and returns rather than
/// failing when it is unset. This is this crate's own variable, distinct from
/// `apps/event-ingest`'s `APEX_POSTGRES_URL` -- see
/// `control_postgres_url_is_this_crate_s_own_variable` in `startup/tests.rs`
/// for why the two are deliberately never the same name.
#[cfg(test)]
#[path = "inbox_postgres/tests.rs"]
mod tests;
