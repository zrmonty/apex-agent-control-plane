//! PostgreSQL-backed command delivery state for multi-replica gateways.
//!
//! The event outbox and this inbox intentionally have separate tables and
//! separate completion state. They share a database connection authority so
//! a command accepted by one gateway replica is visible to an agent polling
//! another, while the outbox remains the audit/fanout authority.

use postgres::Client;

use super::{
    CommandInbox, DeliveryPolicy, PendingCommand, PollTarget, RecordResult,
    ScopeAuthorizer, command_hash, is_recordable,
};
use crate::errors::{CommandError, CommandErrorCode};

const INBOX_SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0003_u64 as i64;
const CLAIM_BATCH: i64 = 1_024;

pub struct PostgresCommandInbox {
    client: Client,
    capacity: usize,
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
        let mut tx = self.client.transaction().map_err(|_| CommandError::internal())?;
        let existing = tx
            .query_opt(
                "SELECT command_hash FROM apex_control_inbox
                 WHERE workspace_id = $1 AND namespace_id = $2 AND command_id = $3
                 FOR UPDATE",
                &[&command.workspace_id, &command.namespace_id, &command.command_id],
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
                    &[&command.workspace_id, &command.namespace_id, &command.command_id],
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
        let mut tx = self.client.transaction().map_err(|_| CommandError::internal())?;
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
}

fn configuration_error() -> CommandError {
    CommandError::new(
        CommandErrorCode::Internal,
        "The control gateway failed to process the request.",
    )
}
