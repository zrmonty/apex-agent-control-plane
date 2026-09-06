-- Private registry/selection metadata, never workload enrollment or routing.
DO $$
DECLARE marker regclass := to_regclass('mcp_proxy_serving_schema');
BEGIN
    IF marker IS NULL THEN
        IF to_regclass('mcp_proxy_serving_selection') IS NOT NULL
           OR to_regclass('mcp_proxy_deployments') IS NOT NULL
           OR to_regclass('mcp_proxy_grant_decisions') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_serving_epoch()') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_deployment()') IS NOT NULL THEN
            RAISE EXCEPTION 'unversioned serving registry' USING ERRCODE='0A000';
        END IF;
    ELSE
        IF to_regclass('mcp_proxy_serving_selection') IS NULL
           OR to_regclass('mcp_proxy_deployments') IS NULL
           OR to_regclass('mcp_proxy_grant_decisions') IS NULL THEN
            RAISE EXCEPTION 'partial serving registry' USING ERRCODE='0A000';
        END IF;
        LOCK TABLE mcp_proxy_serving_schema IN SHARE MODE;
        IF (SELECT count(*) FROM mcp_proxy_serving_schema) <> 1
           OR NOT EXISTS(SELECT 1 FROM mcp_proxy_serving_schema WHERE version=1) THEN
            RAISE EXCEPTION 'unsupported serving registry' USING ERRCODE='0A000';
        END IF;
    END IF;
END; $$;

CREATE TABLE IF NOT EXISTS mcp_proxy_serving_selection (
    proxy_id UUID PRIMARY KEY REFERENCES mcp_proxies(proxy_id),
    workspace_id TEXT NOT NULL, namespace_id TEXT NOT NULL, installation_id UUID NOT NULL,
    epoch BIGINT NOT NULL CHECK(epoch>0),
    selected_instance UUID,
    withdrawal_operation UUID,
    FOREIGN KEY(workspace_id,namespace_id,proxy_id) REFERENCES mcp_proxies(workspace_id,namespace_id,proxy_id)
);

CREATE TABLE IF NOT EXISTS mcp_proxy_deployments (
    instance_id UUID PRIMARY KEY,
    proxy_id UUID NOT NULL REFERENCES mcp_proxy_serving_selection(proxy_id),
    binding_bytes BYTEA NOT NULL CHECK(octet_length(binding_bytes) BETWEEN 1 AND 4096),
    configuration_bytes BYTEA NOT NULL CHECK(octet_length(configuration_bytes) BETWEEN 1 AND 262144),
    original_operation UUID NOT NULL REFERENCES mcp_proxy_operations(operation_id),
    profile_ref TEXT NOT NULL CHECK(length(profile_ref) BETWEEN 1 AND 128),
    profile_version TEXT NOT NULL CHECK(length(profile_version) BETWEEN 1 AND 128),
    proof_sha256 BYTEA NOT NULL CHECK(octet_length(proof_sha256)=32),
    mode INTEGER NOT NULL CHECK(mode IN (1,2,3)),
    highest_sequence BIGINT NOT NULL DEFAULT 0 CHECK(highest_sequence>=0),
    applied_sequence BIGINT NOT NULL DEFAULT 0 CHECK(applied_sequence BETWEEN 0 AND highest_sequence),
    applied_mode INTEGER NOT NULL DEFAULT 0 CHECK(applied_mode BETWEEN 0 AND 3),
    admitting BOOLEAN NOT NULL DEFAULT FALSE,
    active_calls BIGINT NOT NULL DEFAULT 0 CHECK(active_calls BETWEEN 0 AND 4294967295),
    last_serve_sequence BIGINT NOT NULL DEFAULT 0 CHECK(last_serve_sequence BETWEEN 0 AND highest_sequence),
    readiness_id UUID, readiness_bytes BYTEA CHECK(octet_length(readiness_bytes) BETWEEN 1 AND 16384),
    readiness_until BIGINT NOT NULL DEFAULT 0 CHECK(readiness_until>=0),
    readiness_fence BIGINT NOT NULL DEFAULT 0 CHECK(readiness_fence>=0),
    terminated BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE(proxy_id,instance_id),
    CHECK(NOT admitting OR applied_mode=2),
    CHECK(NOT terminated OR mode=3)
);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_proxy_one_serve ON mcp_proxy_deployments(proxy_id) WHERE mode=2;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='mcp_proxy_serving_selection'::regclass AND conname='mcp_proxy_selected_instance') THEN
        ALTER TABLE mcp_proxy_serving_selection ADD CONSTRAINT mcp_proxy_selected_instance
        FOREIGN KEY(proxy_id,selected_instance) REFERENCES mcp_proxy_deployments(proxy_id,instance_id);
    END IF;
END; $$;

CREATE TABLE IF NOT EXISTS mcp_proxy_grant_decisions (
    instance_id UUID NOT NULL REFERENCES mcp_proxy_deployments(instance_id),
    sequence BIGINT NOT NULL CHECK(sequence>0),
    nonce BYTEA NOT NULL CHECK(octet_length(nonce)=32),
    request_bytes BYTEA NOT NULL CHECK(octet_length(request_bytes) BETWEEN 1 AND 8192),
    decision_id UUID NOT NULL UNIQUE,
    epoch BIGINT NOT NULL CHECK(epoch>0),
    mode INTEGER NOT NULL CHECK(mode IN (1,2,3)),
    issued_at BIGINT NOT NULL CHECK(issued_at>0),
    valid_until BIGINT NOT NULL CHECK(valid_until>issued_at AND valid_until-issued_at<=10000000),
    PRIMARY KEY(instance_id,sequence)
);

CREATE OR REPLACE FUNCTION mcp_proxy_preserve_serving_epoch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'serving epoch cannot reset' USING ERRCODE='23514'; END IF;
    IF (NEW.proxy_id,NEW.workspace_id,NEW.namespace_id,NEW.installation_id) IS DISTINCT FROM
       (OLD.proxy_id,OLD.workspace_id,OLD.namespace_id,OLD.installation_id)
       OR NEW.epoch<OLD.epoch OR (NEW.selected_instance IS DISTINCT FROM OLD.selected_instance AND NEW.epoch<=OLD.epoch) THEN
        RAISE EXCEPTION 'serving epoch must increase' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_deployment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'deployment identity cannot reset' USING ERRCODE='23514'; END IF;
    IF (NEW.instance_id,NEW.proxy_id,NEW.binding_bytes,NEW.configuration_bytes,NEW.original_operation,NEW.profile_ref,NEW.profile_version,NEW.proof_sha256)
       IS DISTINCT FROM (OLD.instance_id,OLD.proxy_id,OLD.binding_bytes,OLD.configuration_bytes,OLD.original_operation,OLD.profile_ref,OLD.profile_version,OLD.proof_sha256)
       OR (OLD.mode=3 AND NEW.mode<>3) OR (OLD.terminated AND NOT NEW.terminated)
       OR NEW.highest_sequence<OLD.highest_sequence OR NEW.applied_sequence<OLD.applied_sequence
       OR NEW.last_serve_sequence<OLD.last_serve_sequence THEN
        RAISE EXCEPTION 'immutable deployment or monotonic progress violation' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_grant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'issued decision is immutable' USING ERRCODE='23514';
END; $$;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mcp_proxy_serving_selection'::regclass AND tgname='mcp_proxy_serving_epoch') THEN
        CREATE TRIGGER mcp_proxy_serving_epoch BEFORE UPDATE OR DELETE ON mcp_proxy_serving_selection FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_serving_epoch();
        CREATE TRIGGER mcp_proxy_deployment_immutable BEFORE UPDATE OR DELETE ON mcp_proxy_deployments FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_deployment();
        CREATE TRIGGER mcp_proxy_grant_immutable BEFORE UPDATE ON mcp_proxy_grant_decisions FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_grant();
    END IF;
END; $$;
CREATE TABLE IF NOT EXISTS mcp_proxy_serving_schema(version INTEGER PRIMARY KEY CHECK(version=1));
INSERT INTO mcp_proxy_serving_schema VALUES(1) ON CONFLICT DO NOTHING;
