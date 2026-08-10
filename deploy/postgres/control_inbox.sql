-- Authoritative command delivery state for the OOB control gateway.
--
-- This is deliberately a different table from apex_event_outbox. The event
-- outbox answers whether the control event reached the queryable trace; this
-- table answers whether the targeted agent has retrieved the command. Both
-- are retained independently because either side may still be pending.
CREATE TABLE IF NOT EXISTS apex_control_inbox (
    sequence BIGSERIAL PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    command_hash BYTEA NOT NULL CHECK (octet_length(command_hash) = 32),
    agent_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason_code TEXT,
    parameters BYTEA NOT NULL,
    issued_at TEXT NOT NULL,
    attempts BIGINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_delivered_millis BIGINT,
    acknowledged_at_millis BIGINT,
    UNIQUE (workspace_id, namespace_id, command_id)
);

ALTER TABLE apex_control_inbox
    ADD COLUMN IF NOT EXISTS acknowledged_at_millis BIGINT;

CREATE INDEX IF NOT EXISTS apex_control_inbox_delivery_idx
    ON apex_control_inbox (agent_id, sequence);

CREATE INDEX IF NOT EXISTS apex_control_inbox_retention_idx
    ON apex_control_inbox (last_delivered_millis)
    WHERE last_delivered_millis IS NOT NULL;

-- No *separate* index was added for the per-`(workspace_id, namespace_id)`
-- quota's `SELECT COUNT(*) ... WHERE workspace_id = $1 AND namespace_id = $2`
-- (`PostgresCommandInbox::record`, `inbox_postgres.rs`): the index below,
-- added for ListCommands, already carries those two columns as its leftmost
-- prefix, so the quota check is a plain prefix range scan (index-only, once
-- the visibility map is warm) on an index this table needs regardless. A
-- second, narrower index over just (workspace_id, namespace_id) would
-- duplicate most of that data on disk and add write amplification to every
-- insert for a negligible read benefit -- the wrong tradeoff for a hot,
-- multi-tenant write path.
--
-- Supports ListCommands' scope-and-cursor scan: workspace/namespace equality
-- plus an ascending `sequence` range, the same per-scope ordering
-- `apex_control_inbox_delivery_idx` already gives the per-agent `claim()`
-- scan above. Without this, a ListCommands call would fall back to a full
-- scan of the table ordered by the primary key and filter every row in
-- application code, which is exactly the OFFSET-shaped cost this index
-- exists to avoid.
CREATE INDEX IF NOT EXISTS apex_control_inbox_scope_idx
    ON apex_control_inbox (workspace_id, namespace_id, sequence);
