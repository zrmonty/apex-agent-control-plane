-- Apply after mcp_proxies.sql with the store's migration advisory lock.
-- One batch/transaction makes this additive migration rollback-safe.
SELECT pg_advisory_xact_lock(765234190005);

-- Accepted states: no journal objects/marker (fresh), or exactly version 1 with
-- the existing journal tables and generation column. Never repair an unversioned
-- or partial journal, or modify a newer journal during application rollback.
-- This gate must precede every journal DDL statement and function replacement.
DO $$
DECLARE
    marker regclass := to_regclass('mcp_proxy_operation_schema');
    journal_tables regclass[] := ARRAY[
        to_regclass('mcp_proxy_operations'),
        to_regclass('mcp_proxy_controller_leases'),
        to_regclass('mcp_proxy_evidence_intents')];
    existing_tables INTEGER;
    version_rows BIGINT;
    supported_rows BIGINT;
    has_generation BOOLEAN := EXISTS (
        SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('mcp_proxies')
        AND attname = 'deployment_generation' AND attnum > 0 AND NOT attisdropped);
BEGIN
    SELECT count(*) INTO existing_tables FROM pg_class WHERE oid = ANY(journal_tables);
    IF marker IS NULL THEN
        IF existing_tables <> 0 OR has_generation
           OR to_regclass('mcp_proxies_exact_identity_idx') IS NOT NULL
           OR to_regclass('mcp_proxy_pending_evidence_idx') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_operation()') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_evidence()') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_fence()') IS NOT NULL THEN
            RAISE EXCEPTION 'proxy operation schema version is missing from an existing journal'
                USING ERRCODE = '0A000';
        END IF;
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid
        WHERE c.oid = marker AND c.relkind = 'r' AND a.attname = 'version'
        AND a.atttypid = 'integer'::regtype AND a.attnotnull
        AND a.attnum > 0 AND NOT a.attisdropped) THEN
        RAISE EXCEPTION 'proxy operation schema version marker is inconsistent'
            USING ERRCODE = '0A000';
    END IF;
    LOCK TABLE mcp_proxy_operation_schema IN SHARE MODE;
    SELECT count(*), count(*) FILTER (WHERE version = 1)
        INTO version_rows, supported_rows FROM mcp_proxy_operation_schema;
    IF version_rows <> 1 OR supported_rows <> 1 THEN
        RAISE EXCEPTION 'unsupported or inconsistent proxy operation schema version'
            USING ERRCODE = '0A000';
    END IF;
    IF existing_tables <> 3 OR EXISTS (
        SELECT 1 FROM pg_class WHERE oid = ANY(journal_tables) AND relkind <> 'r')
       OR NOT EXISTS (
        SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('mcp_proxies')
        AND attname = 'deployment_generation' AND atttypid = 'bigint'::regtype
        AND attnotnull AND attnum > 0 AND NOT attisdropped)
       OR to_regprocedure('mcp_proxy_preserve_operation()') IS NULL
       OR to_regprocedure('mcp_proxy_preserve_evidence()') IS NULL
       OR to_regprocedure('mcp_proxy_preserve_fence()') IS NULL THEN
        RAISE EXCEPTION 'proxy operation schema version 1 journal is incomplete'
            USING ERRCODE = '0A000';
    END IF;
END;
$$;

ALTER TABLE mcp_proxies ADD COLUMN IF NOT EXISTS deployment_generation
    BIGINT NOT NULL DEFAULT 0 CHECK (deployment_generation >= 0);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_proxies_exact_identity_idx
    ON mcp_proxies (workspace_id, namespace_id, proxy_id);

CREATE TABLE IF NOT EXISTS mcp_proxy_operations (
    operation_id UUID PRIMARY KEY CHECK (
        operation_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    request_id UUID NOT NULL UNIQUE CHECK (
        request_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    proxy_id UUID NOT NULL,
    revision_id UUID NOT NULL,
    expected_revision_id UUID,
    generation BIGINT NOT NULL CHECK (generation > 0),
    desired_state TEXT NOT NULL CHECK (desired_state IN ('serving', 'paused', 'retired')),
    request_hash TEXT NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    accepted_result BYTEA NOT NULL CHECK (octet_length(accepted_result) BETWEEN 1 AND 16384),
    current_result BYTEA NOT NULL CHECK (octet_length(current_result) BETWEEN 1 AND 16384),
    observed_state INTEGER NOT NULL DEFAULT 1 CHECK (observed_state BETWEEN 1 AND 7),
    observed_at_micros BIGINT NOT NULL DEFAULT 0 CHECK (observed_at_micros >= 0),
    created_at_micros BIGINT NOT NULL CHECK (created_at_micros >= 0),
    CHECK (operation_id <> request_id),
    FOREIGN KEY (workspace_id, namespace_id, proxy_id)
        REFERENCES mcp_proxies (workspace_id, namespace_id, proxy_id),
    FOREIGN KEY (proxy_id, revision_id) REFERENCES mcp_proxy_revisions (proxy_id, revision_id),
    UNIQUE (workspace_id, namespace_id, proxy_id, generation),
    UNIQUE (workspace_id, namespace_id, proxy_id, operation_id)
);

-- Durable per-proxy counter survives operation and generation changes. Never
-- delete/recreate this row on release; expiry makes the next claim increment it.
CREATE TABLE IF NOT EXISTS mcp_proxy_controller_leases (
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    proxy_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    worker_id TEXT NOT NULL CHECK (worker_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    fencing_token BIGINT NOT NULL CHECK (fencing_token > 0),
    expires_at_micros BIGINT NOT NULL CHECK (expires_at_micros >= 0),
    PRIMARY KEY (workspace_id, namespace_id, proxy_id),
    FOREIGN KEY (workspace_id, namespace_id, proxy_id, operation_id)
        REFERENCES mcp_proxy_operations (workspace_id, namespace_id, proxy_id, operation_id)
);

-- canonical_payload stores the original validated protobuf envelope bytes.
-- payload_hash is the frozen Apex v1 canonical hash, not SHA256(protobuf bytes).
-- operation_result freezes the response for an idempotent transition retry.
CREATE TABLE IF NOT EXISTS mcp_proxy_evidence_intents (
    event_id UUID PRIMARY KEY CHECK (
        event_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    proxy_id UUID NOT NULL,
    operation_id UUID NOT NULL,
    event_timestamp TEXT NOT NULL CHECK (length(event_timestamp) BETWEEN 20 AND 40),
    canonical_payload BYTEA NOT NULL CHECK (octet_length(canonical_payload) BETWEEN 1 AND 262144),
    payload_hash TEXT NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    operation_result BYTEA NOT NULL CHECK (octet_length(operation_result) BETWEEN 1 AND 16384),
    enqueued_at_micros BIGINT CHECK (enqueued_at_micros >= 0),
    FOREIGN KEY (workspace_id, namespace_id, proxy_id, operation_id)
        REFERENCES mcp_proxy_operations (workspace_id, namespace_id, proxy_id, operation_id)
);
CREATE INDEX IF NOT EXISTS mcp_proxy_pending_evidence_idx
    ON mcp_proxy_evidence_intents (workspace_id, namespace_id, proxy_id, event_timestamp, event_id)
    WHERE enqueued_at_micros IS NULL;

CREATE OR REPLACE FUNCTION mcp_proxy_preserve_operation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'proxy operation history is immutable' USING ERRCODE = '23514';
    END IF;
    IF OLD.observed_state IN (3, 4, 5)
       AND (NEW.observed_state, NEW.current_result, NEW.observed_at_micros)
           IS DISTINCT FROM
           (OLD.observed_state, OLD.current_result, OLD.observed_at_micros) THEN
        RAISE EXCEPTION 'completed proxy operation is immutable' USING ERRCODE = '23514';
    END IF;
    IF (NEW.operation_id, NEW.request_id, NEW.workspace_id, NEW.namespace_id,
        NEW.proxy_id, NEW.revision_id, NEW.expected_revision_id, NEW.generation,
        NEW.desired_state, NEW.request_hash, NEW.accepted_result, NEW.created_at_micros)
       IS DISTINCT FROM
       (OLD.operation_id, OLD.request_id, OLD.workspace_id, OLD.namespace_id,
        OLD.proxy_id, OLD.revision_id, OLD.expected_revision_id, OLD.generation,
        OLD.desired_state, OLD.request_hash, OLD.accepted_result, OLD.created_at_micros)
       OR NEW.observed_at_micros < OLD.observed_at_micros THEN
        RAISE EXCEPTION 'proxy operation identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mcp_proxy_preserve_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'proxy evidence is immutable' USING ERRCODE = '23514';
    END IF;
    IF (NEW.event_id, NEW.workspace_id, NEW.namespace_id, NEW.proxy_id,
        NEW.operation_id, NEW.event_timestamp, NEW.canonical_payload,
        NEW.payload_hash, NEW.operation_result)
       IS DISTINCT FROM
       (OLD.event_id, OLD.workspace_id, OLD.namespace_id, OLD.proxy_id,
        OLD.operation_id, OLD.event_timestamp, OLD.canonical_payload,
        OLD.payload_hash, OLD.operation_result)
       OR (OLD.enqueued_at_micros IS NOT NULL
           AND NEW.enqueued_at_micros IS DISTINCT FROM OLD.enqueued_at_micros) THEN
        RAISE EXCEPTION 'proxy evidence is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mcp_proxy_preserve_fence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'proxy fence cannot be reset' USING ERRCODE = '23514';
    END IF;
    IF (NEW.workspace_id, NEW.namespace_id, NEW.proxy_id) IS DISTINCT FROM
       (OLD.workspace_id, OLD.namespace_id, OLD.proxy_id)
       OR NEW.fencing_token < OLD.fencing_token
       OR NEW.generation < OLD.generation
       OR ((NEW.worker_id, NEW.operation_id, NEW.generation) IS DISTINCT FROM
           (OLD.worker_id, OLD.operation_id, OLD.generation)
           AND NEW.fencing_token <= OLD.fencing_token) THEN
        RAISE EXCEPTION 'proxy fence must increase on handoff' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

-- Install the completion invariant on new and previously initialized journals.
-- Invalid historical rows fail migration explicitly; never rewrite audit history.
-- Create triggers once without dropping protection during repeat startup.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'mcp_proxy_operations'::regclass
                   AND conname = 'mcp_proxy_operation_desired_observed_check') THEN
        ALTER TABLE mcp_proxy_operations ADD CONSTRAINT mcp_proxy_operation_desired_observed_check
            CHECK (observed_state IN (1, 2, 6, 7)
                OR (desired_state = 'serving' AND observed_state = 3)
                OR (desired_state = 'paused' AND observed_state = 4)
                OR (desired_state = 'retired' AND observed_state = 5));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'mcp_proxy_operations'::regclass
                   AND tgname = 'mcp_proxy_operations_immutable') THEN
        CREATE TRIGGER mcp_proxy_operations_immutable BEFORE UPDATE OR DELETE
            ON mcp_proxy_operations FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_operation();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'mcp_proxy_evidence_intents'::regclass
                   AND tgname = 'mcp_proxy_evidence_immutable') THEN
        CREATE TRIGGER mcp_proxy_evidence_immutable BEFORE UPDATE OR DELETE
            ON mcp_proxy_evidence_intents FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_evidence();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'mcp_proxy_controller_leases'::regclass
                   AND tgname = 'mcp_proxy_fence_monotonic') THEN
        CREATE TRIGGER mcp_proxy_fence_monotonic BEFORE UPDATE OR DELETE
            ON mcp_proxy_controller_leases FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_fence();
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS mcp_proxy_operation_schema (
    version INTEGER PRIMARY KEY CHECK (version = 1)
);
INSERT INTO mcp_proxy_operation_schema (version) VALUES (1) ON CONFLICT DO NOTHING;
