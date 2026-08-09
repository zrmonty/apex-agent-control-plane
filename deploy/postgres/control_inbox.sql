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
    UNIQUE (workspace_id, namespace_id, command_id)
);

CREATE INDEX IF NOT EXISTS apex_control_inbox_delivery_idx
    ON apex_control_inbox (agent_id, sequence);
