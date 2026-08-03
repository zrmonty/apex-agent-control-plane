-- Apex v1 analytical event schema.
--
-- This table is a projection, not the immutable record. The writer must validate
-- the protobuf envelope before inserting and must preserve the event_id/event_hash
-- pair. ReplacingMergeTree removes repeated writes of the same canonical event
-- during background merges while retaining a changed-payload conflict as a
-- distinct row for investigation. The writer, not ClickHouse SQL callers, is the
-- tenant authorization boundary.

CREATE DATABASE IF NOT EXISTS apex;

CREATE TABLE IF NOT EXISTS apex.events
(
    workspace_id      LowCardinality(String),
    namespace_id      LowCardinality(String),
    event_id          UUID,
    event_timestamp   DateTime64(6, 'UTC'),
    event_type        Enum8(
        'TURN_START' = 1,
        'LLM' = 2,
        'TOOL' = 3,
        'MESSAGE' = 4,
        'MEMORY' = 5,
        'DECISION' = 6,
        'WORKFLOW' = 7,
        'AGENT_SPAWN' = 8,
        'CONTROL' = 9,
        'SCORE' = 10,
        'TURN_END' = 11,
        'ERROR' = 12
    ),
    agent_id          String,
    run_id            String,
    parent_run_id     Nullable(String),
    trace_id          String,
    agent_group_ids   Array(String),
    actor_type        Enum8(
        'USER' = 1,
        'AGENT' = 2,
        'SYSTEM' = 3,
        'SCHEDULE' = 4
    ),
    actor_id          String,
    agent_code        String,
    prompt_revision   String,
    model             String,
    data_json         String CODEC(ZSTD(3)),
    prev_hash         Nullable(FixedString(64)),
    event_hash        FixedString(64),
    schema_version    UInt32,
    envelope_protobuf String CODEC(ZSTD(3)),
    ingested_at       DateTime64(6, 'UTC') MATERIALIZED now64(6),
    -- Defense-in-depth limits; the service must reject these before allocation.
    CONSTRAINT workspace_id_bounded CHECK length(workspace_id) BETWEEN 1 AND 128,
    CONSTRAINT namespace_id_bounded CHECK length(namespace_id) BETWEEN 1 AND 128,
    CONSTRAINT agent_id_bounded CHECK length(agent_id) BETWEEN 1 AND 256,
    CONSTRAINT run_id_bounded CHECK length(run_id) BETWEEN 1 AND 256,
    CONSTRAINT trace_id_bounded CHECK length(trace_id) BETWEEN 1 AND 256,
    CONSTRAINT actor_id_bounded CHECK length(actor_id) BETWEEN 1 AND 256,
    CONSTRAINT agent_code_bounded CHECK length(agent_code) <= 256,
    CONSTRAINT prompt_revision_bounded CHECK length(prompt_revision) <= 256,
    CONSTRAINT model_bounded CHECK length(model) <= 256,
    CONSTRAINT parent_run_id_bounded CHECK isNull(parent_run_id) OR length(parent_run_id) BETWEEN 1 AND 256,
    CONSTRAINT agent_groups_bounded CHECK length(agent_group_ids) <= 128,
    CONSTRAINT data_json_bounded CHECK length(data_json) <= 262144,
    CONSTRAINT envelope_bounded CHECK length(envelope_protobuf) BETWEEN 1 AND 262144,
    CONSTRAINT event_hash_shape CHECK length(event_hash) = 64,
    CONSTRAINT previous_hash_shape CHECK isNull(prev_hash) OR length(prev_hash) = 64,
    CONSTRAINT supported_schema_version CHECK schema_version = 1
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(ingested_at)
ORDER BY (workspace_id, namespace_id, event_id, event_hash, trace_id, event_timestamp)
SETTINGS index_granularity = 8192;

-- Query by event_id with FINAL when an idempotent point lookup must collapse
-- repeated writes. A result containing more than one event_hash is an
-- idempotency conflict and must be surfaced, never silently overwritten.

-- Deployment requirements:
-- * Expose ClickHouse only to the authenticated projection/query services; do
--   not grant agents direct SQL access.
-- * Apply scope predicates in the service before query execution and enforce
--   ClickHouse max_rows_to_read/max_bytes_to_read limits per request.
-- * Encrypt transport and disks, disable arbitrary SQL for untrusted callers,
--   and apply retention through controlled TTL/migration policy rather than
--   accepting retention expressions from event data.
