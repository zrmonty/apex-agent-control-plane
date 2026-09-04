use postgres::Client;

use super::super::{
    CommandSummary, DeliveryStatus, ListCommandsPage, ListCommandsQuery, resolve_delivery_status,
};
use crate::errors::CommandError;

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
pub(super) fn list_commands(
    client: &mut Client,
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

    let rows = client
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
