-- Private accounting, not policy evaluation, workload authentication or routing.
DO $$ BEGIN
    IF to_regclass('mcp_proxy_admissions_schema') IS NULL THEN
        IF to_regclass('mcp_proxy_admission_counters') IS NOT NULL
           OR to_regclass('mcp_proxy_call_admissions') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_admission()') IS NOT NULL THEN
            RAISE EXCEPTION 'unversioned admissions schema' USING ERRCODE='0A000';
        END IF;
    ELSE
        IF to_regclass('mcp_proxy_admission_counters') IS NULL
           OR to_regclass('mcp_proxy_call_admissions') IS NULL THEN
            RAISE EXCEPTION 'partial admissions schema' USING ERRCODE='0A000';
        END IF;
        LOCK TABLE mcp_proxy_admissions_schema IN SHARE MODE;
        IF (SELECT count(*) FROM mcp_proxy_admissions_schema)<>1
           OR NOT EXISTS(SELECT 1 FROM mcp_proxy_admissions_schema WHERE version=1) THEN
            RAISE EXCEPTION 'unsupported admissions schema' USING ERRCODE='0A000';
        END IF;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS mcp_proxy_admission_counters (
    proxy_id UUID PRIMARY KEY REFERENCES mcp_proxy_serving_selection(proxy_id),
    minute_bucket BIGINT NOT NULL CHECK(minute_bucket>=0),
    minute_used BIGINT NOT NULL CHECK(minute_used BETWEEN 0 AND 1000000),
    day_bucket BIGINT NOT NULL CHECK(day_bucket>=0),
    day_used BIGINT NOT NULL CHECK(day_used BETWEEN 0 AND 1000000),
    active_calls BIGINT NOT NULL CHECK(active_calls BETWEEN 0 AND 1024),
    total_admissions BIGINT NOT NULL CHECK(total_admissions BETWEEN 0 AND 1000000)
);
CREATE TABLE IF NOT EXISTS mcp_proxy_call_admissions (
    call_id UUID PRIMARY KEY,
    admission_id UUID NOT NULL UNIQUE,
    proxy_id UUID NOT NULL,
    instance_id UUID NOT NULL,
    semantic_sha256 BYTEA NOT NULL CHECK(octet_length(semantic_sha256)=32),
    policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
    policy_revision TEXT NOT NULL CHECK(policy_revision ~ '^[1-9][0-9]{0,19}$'
        AND policy_revision::numeric<=18446744073709551615),
    epoch BIGINT NOT NULL CHECK(epoch>0),
    issued_at BIGINT NOT NULL CHECK(issued_at>0),
    valid_until BIGINT NOT NULL CHECK(valid_until>issued_at AND valid_until-issued_at<=10000000),
    released BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY(proxy_id,instance_id) REFERENCES mcp_proxy_deployments(proxy_id,instance_id)
);
CREATE INDEX IF NOT EXISTS mcp_proxy_outstanding_admissions
    ON mcp_proxy_call_admissions(proxy_id,instance_id) WHERE NOT released;

CREATE OR REPLACE FUNCTION mcp_proxy_preserve_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'admission tombstone cannot be deleted' USING ERRCODE='23514'; END IF;
    IF (NEW.call_id,NEW.admission_id,NEW.proxy_id,NEW.instance_id,NEW.semantic_sha256,NEW.policy_id,NEW.policy_revision,NEW.epoch,NEW.issued_at,NEW.valid_until)
       IS DISTINCT FROM (OLD.call_id,OLD.admission_id,OLD.proxy_id,OLD.instance_id,OLD.semantic_sha256,OLD.policy_id,OLD.policy_revision,OLD.epoch,OLD.issued_at,OLD.valid_until)
       OR (OLD.released AND NOT NEW.released) THEN
        RAISE EXCEPTION 'immutable admission identity' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_admission_counters() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'admission counters cannot reset' USING ERRCODE='23514'; END IF;
    IF NEW.proxy_id<>OLD.proxy_id OR NEW.total_admissions<OLD.total_admissions
       OR NEW.minute_bucket<OLD.minute_bucket OR NEW.day_bucket<OLD.day_bucket
       OR (NEW.minute_bucket=OLD.minute_bucket AND NEW.minute_used<OLD.minute_used)
       OR (NEW.day_bucket=OLD.day_bucket AND NEW.day_used<OLD.day_used) THEN
        RAISE EXCEPTION 'monotonic admission counters' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mcp_proxy_call_admissions'::regclass AND tgname='mcp_proxy_admission_immutable') THEN
        CREATE TRIGGER mcp_proxy_admission_immutable BEFORE UPDATE OR DELETE ON mcp_proxy_call_admissions FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_admission();
        CREATE TRIGGER mcp_proxy_admission_counters_monotonic BEFORE UPDATE OR DELETE ON mcp_proxy_admission_counters FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_admission_counters();
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS mcp_proxy_admissions_schema(version INTEGER PRIMARY KEY CHECK(version=1));
INSERT INTO mcp_proxy_admissions_schema VALUES(1) ON CONFLICT DO NOTHING;
