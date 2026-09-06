-- Additive execution journal, applied with the existing schema advisory lock.
DO $$
DECLARE
    marker regclass := to_regclass('mcp_proxy_managed_schema');
    acceptance regclass := to_regclass('mcp_proxy_managed_acceptance');
    attempts regclass := to_regclass('mcp_proxy_runtime_attempts');
    total bigint;
    supported bigint;
BEGIN
    IF marker IS NULL THEN
        IF acceptance IS NOT NULL OR attempts IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_acceptance()') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_command_floor()') IS NOT NULL THEN
            RAISE EXCEPTION 'unversioned managed runtime journal' USING ERRCODE='0A000';
        END IF;
        RETURN;
    END IF;
    IF acceptance IS NULL OR attempts IS NULL THEN
        RAISE EXCEPTION 'partial managed runtime journal' USING ERRCODE='0A000';
    END IF;
    LOCK TABLE mcp_proxy_managed_schema IN SHARE MODE;
    SELECT count(*),count(*) FILTER(WHERE version=1) INTO total,supported FROM mcp_proxy_managed_schema;
    IF total<>1 OR supported<>1 THEN
        RAISE EXCEPTION 'unsupported managed runtime journal' USING ERRCODE='0A000';
    END IF;
END; $$;
CREATE TABLE IF NOT EXISTS mcp_proxy_managed_acceptance (
    request_id UUID PRIMARY KEY REFERENCES mcp_proxy_operations(request_id),
    operation_id UUID NOT NULL UNIQUE REFERENCES mcp_proxy_operations(operation_id),
    semantic_hash TEXT NOT NULL CHECK (semantic_hash ~ '^[0-9a-f]{64}$'),
    proxy_snapshot BYTEA NOT NULL CHECK (octet_length(proxy_snapshot) BETWEEN 1 AND 524288),
    revision_snapshot BYTEA NOT NULL CHECK (octet_length(revision_snapshot) BETWEEN 1 AND 524288)
);
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_acceptance() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'managed acceptance is immutable' USING ERRCODE = '23514';
END; $$;

CREATE TABLE IF NOT EXISTS mcp_proxy_managed_schema (
    version INTEGER PRIMARY KEY CHECK(version=1)
);
INSERT INTO mcp_proxy_managed_schema(version) VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS mcp_proxy_runtime_attempts (
    workspace_id TEXT NOT NULL, namespace_id TEXT NOT NULL, proxy_id UUID NOT NULL,
    last_command_id UUID NOT NULL CHECK (last_command_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    operation_id UUID NOT NULL,
    fencing_token BIGINT NOT NULL CHECK (fencing_token>0),
    request_bytes BYTEA NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 4096),
    outcome_event_id UUID NOT NULL, uncertain_event_id UUID NOT NULL,
    event_time_micros BIGINT NOT NULL CHECK (event_time_micros>0),
    response_bytes BYTEA CHECK (octet_length(response_bytes) BETWEEN 1 AND 16384),
    PRIMARY KEY(workspace_id,namespace_id,proxy_id),
    FOREIGN KEY(workspace_id,namespace_id,proxy_id,operation_id)
        REFERENCES mcp_proxy_operations(workspace_id,namespace_id,proxy_id,operation_id)
);
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_command_floor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'command allocator cannot reset' USING ERRCODE='23514'; END IF;
    IF NEW.last_command_id < OLD.last_command_id OR NEW.fencing_token < OLD.fencing_token
        OR (NEW.workspace_id,NEW.namespace_id,NEW.proxy_id) IS DISTINCT FROM (OLD.workspace_id,OLD.namespace_id,OLD.proxy_id)
        OR ((NEW.operation_id,NEW.fencing_token) IS DISTINCT FROM (OLD.operation_id,OLD.fencing_token)
            AND NEW.last_command_id <= OLD.last_command_id) THEN
        RAISE EXCEPTION 'command allocation must increase on handoff' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mcp_proxy_runtime_attempts'::regclass AND tgname='mcp_proxy_command_floor') THEN
        CREATE TRIGGER mcp_proxy_command_floor BEFORE UPDATE OR DELETE ON mcp_proxy_runtime_attempts
            FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_command_floor();
    END IF;
END; $$;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='mcp_proxy_managed_acceptance'::regclass
                   AND tgname='mcp_proxy_managed_acceptance_immutable') THEN
        CREATE TRIGGER mcp_proxy_managed_acceptance_immutable BEFORE UPDATE OR DELETE
        ON mcp_proxy_managed_acceptance FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_acceptance();
    END IF;
END; $$;
