-- Authoritative production idempotency state for the ingest gateway.
-- The unique scope/event key makes concurrent gateway replicas converge on
-- one payload hash. A reservation is committed only after durable fanout
-- succeeds; failed publishes delete the reservation in the same transaction.
CREATE TABLE IF NOT EXISTS apex_ingest_idempotency (
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    payload_hash BYTEA NOT NULL CHECK (octet_length(payload_hash) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
    reservation_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    committed_at TIMESTAMPTZ,
    PRIMARY KEY (workspace_id, namespace_id, event_id),
    UNIQUE (reservation_id),
    CHECK ((state = 'pending' AND committed_at IS NULL) OR
           (state = 'committed' AND committed_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS apex_ingest_idempotency_pending_idx
    ON apex_ingest_idempotency (state, created_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS apex_ingest_idempotency_committed_retention_idx
    ON apex_ingest_idempotency (committed_at)
    WHERE state = 'committed';

-- The application must use a transaction with these semantics:
-- 1. INSERT ... ON CONFLICT (workspace_id, namespace_id, event_id) ...
-- 2. Return duplicate only when the stored payload_hash matches exactly.
-- 3. Return conflict when the hash differs.
-- 4. Mark pending -> committed after all durable sinks acknowledge.
-- 5. DELETE the matching pending reservation on publish failure.
-- 6. Reap only expired pending rows in the crash-recovery reaper.
-- 7. Delete committed rows only through the separately scheduled retention
--    maintenance operation, after the configured replay/idempotency window.
