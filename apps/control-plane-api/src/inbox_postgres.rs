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
}

/// Reconnects a Postgres inbox slot after a transport-level failure. A poll
/// may be redelivered after an ambiguous transaction outcome, which is already
/// part of the inbox's at-least-once contract; losing the slot until restart
/// is not.
pub struct RecoveringPostgresCommandInbox {
    connection_string: String,
    capacity: usize,
    inner: PostgresCommandInbox,
}

impl RecoveringPostgresCommandInbox {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, CommandError> {
        let inner = PostgresCommandInbox::connect(connection_string, capacity)?;
        Ok(Self {
            connection_string: connection_string.to_owned(),
            capacity,
            inner,
        })
    }

    fn with_retry<T>(
        &mut self,
        mut operation: impl FnMut(&mut PostgresCommandInbox) -> Result<T, CommandError>,
    ) -> Result<T, CommandError> {
        match operation(&mut self.inner) {
            Ok(value) => Ok(value),
            Err(error) if error.code == CommandErrorCode::Internal => {
                let replacement =
                    PostgresCommandInbox::connect(&self.connection_string, self.capacity)?;
                self.inner = replacement;
                operation(&mut self.inner)
            }
            Err(error) => Err(error),
        }
    }
}

impl CommandInbox for RecoveringPostgresCommandInbox {
    fn record(&mut self, command: &PendingCommand) -> Result<RecordResult, CommandError> {
        self.with_retry(|inner| inner.record(command))
    }

    fn claim(
        &mut self,
        target: &PollTarget,
        scopes: &dyn ScopeAuthorizer,
        policy: DeliveryPolicy,
        now_millis: u64,
    ) -> Result<Vec<PendingCommand>, CommandError> {
        self.with_retry(|inner| inner.claim(target, scopes, policy, now_millis))
    }

    fn undelivered_count(&mut self) -> usize {
        self.inner.undelivered_count()
    }

    fn pending_count(&mut self) -> usize {
        self.inner.pending_count()
    }

    fn acknowledge(
        &mut self,
        target: &PollTarget,
        key: &super::InboxKey,
        delivery_attempt: u32,
        now_millis: u64,
    ) -> Result<super::AckResult, CommandError> {
        self.with_retry(|inner| inner.acknowledge(target, key, delivery_attempt, now_millis))
    }

    fn status(
        &mut self,
        key: &super::InboxKey,
        max_attempts: u32,
    ) -> Result<Option<(super::DeliveryStatus, u32)>, CommandError> {
        self.with_retry(|inner| inner.status(key, max_attempts))
    }

    fn list_commands(
        &mut self,
        query: &ListCommandsQuery<'_>,
    ) -> Result<ListCommandsPage, CommandError> {
        self.with_retry(|inner| inner.list_commands(query))
    }

    fn maintain(
        &mut self,
        now_millis: u64,
        retention_millis: u64,
        max_attempts: u32,
    ) -> Result<(), CommandError> {
        self.with_retry(|inner| inner.maintain(now_millis, retention_millis, max_attempts))
    }
}

impl PostgresCommandInbox {
    pub fn connect(connection_string: &str, capacity: usize) -> Result<Self, CommandError> {
        if capacity == 0 || capacity > super::DEFAULT_INBOX_CAPACITY {
            return Err(configuration_error());
        }
        let mut client = apex_event_ingest::connect_postgres(connection_string)
            .map_err(|_| configuration_error())?;
        apex_event_ingest::apply_postgres_schema(
            &mut client,
            INBOX_SCHEMA_LOCK,
            include_str!("../../../deploy/postgres/control_inbox.sql"),
        )
        .map_err(|_| configuration_error())?;
        Ok(Self { client, capacity })
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
        self.client
            .query_one(
                "SELECT COUNT(*) FROM apex_control_inbox WHERE attempts = 0",
                &[],
            )
            .ok()
            .and_then(|row| row.get::<_, i64>(0).try_into().ok())
            .unwrap_or(0)
    }

    fn pending_count(&mut self) -> usize {
        self.client
            .query_one("SELECT COUNT(*) FROM apex_control_inbox", &[])
            .ok()
            .and_then(|row| row.get::<_, i64>(0).try_into().ok())
            .unwrap_or(0)
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
                "SELECT attempts, last_delivered_millis, acknowledged_at_millis
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
        let state = resolve_delivery_status(acknowledged, attempts, max_attempts);
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
        });

        let rows = self
            .client
            .query(
                "SELECT sequence, command_id, agent_id, action, attempts, issued_at,
                        acknowledged_at_millis
                 FROM apex_control_inbox
                 WHERE workspace_id = $1
                   AND namespace_id = $2
                   AND ($3::text IS NULL OR agent_id = $3)
                   AND sequence > $4
                   AND (
                        $5::smallint IS NULL
                        OR ($5 = 1 AND attempts = 0 AND acknowledged_at_millis IS NULL)
                        OR ($5 = 2 AND attempts > 0 AND attempts < $6
                            AND acknowledged_at_millis IS NULL)
                        OR ($5 = 3 AND acknowledged_at_millis IS NOT NULL)
                        OR ($5 = 4 AND attempts >= $6 AND acknowledged_at_millis IS NULL)
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
            let attempts_u32 = attempts.try_into().unwrap_or(u32::MAX);
            commands.push(CommandSummary {
                command_id: row.get(1),
                agent_id: row.get(2),
                action: row.get(3),
                state: resolve_delivery_status(acknowledged, attempts_u32, query.max_attempts),
                delivery_attempt: attempts_u32,
                issued_at: row.get(5),
                sequence: sequence.try_into().unwrap_or(u64::MAX),
            });
        }
        Ok(ListCommandsPage { commands, has_more })
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
                 WHERE (acknowledged_at_millis IS NOT NULL OR attempts >= $1)
                   AND last_delivered_millis IS NOT NULL
                   AND $2 - last_delivered_millis >= $3",
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
