-- Authoritative event outbox. The canonical envelope is persisted before any
-- projection is called and remains pending until all projections acknowledge.
CREATE TABLE IF NOT EXISTS apex_event_outbox (
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    event_id UUID NOT NULL,
    envelope BYTEA NOT NULL,
    payload_hash BYTEA NOT NULL CHECK (octet_length(payload_hash) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    quarantined_at TIMESTAMPTZ,
    quarantine_reason TEXT,
    PRIMARY KEY (workspace_id, namespace_id, event_id),
    CHECK ((state = 'pending' AND completed_at IS NULL) OR
           (state = 'complete' AND completed_at IS NOT NULL)),
    CHECK ((quarantined_at IS NULL AND quarantine_reason IS NULL) OR
           (quarantined_at IS NOT NULL AND quarantine_reason IS NOT NULL))
);

ALTER TABLE apex_event_outbox
    ADD COLUMN IF NOT EXISTS quarantined_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS quarantine_reason TEXT;

CREATE INDEX IF NOT EXISTS apex_event_outbox_pending_idx
    ON apex_event_outbox (next_attempt_at, created_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS apex_event_outbox_pending_claim_idx
    ON apex_event_outbox (next_attempt_at, created_at)
    WHERE state = 'pending' AND quarantined_at IS NULL;

CREATE INDEX IF NOT EXISTS apex_event_outbox_completed_retention_idx
    ON apex_event_outbox (completed_at)
    WHERE state = 'complete';

-- Workers claim pending rows with SELECT ... FOR UPDATE SKIP LOCKED, dispatch
-- the full idempotent fanout, and set complete only after every sink returns
-- success. A crash leaves the row pending for replay; completed rows are
-- retained according to the control-plane retention policy.
