-- Authenticated registration provenance is append-only and separate from grants.
DO $$ BEGIN
    IF to_regclass('mcp_proxy_attestations_schema') IS NULL THEN
        IF to_regclass('mcp_proxy_deployment_attestations') IS NOT NULL
           OR to_regprocedure('mcp_proxy_preserve_attestation()') IS NOT NULL THEN
            RAISE EXCEPTION 'unversioned attestation registry' USING ERRCODE='0A000';
        END IF;
    ELSE
        IF to_regclass('mcp_proxy_deployment_attestations') IS NULL THEN
            RAISE EXCEPTION 'partial attestation registry' USING ERRCODE='0A000';
        END IF;
        LOCK TABLE mcp_proxy_attestations_schema IN SHARE MODE;
        IF (SELECT count(*) FROM mcp_proxy_attestations_schema) <> 1
           OR NOT EXISTS(SELECT 1 FROM mcp_proxy_attestations_schema WHERE version=1) THEN
            RAISE EXCEPTION 'unsupported attestation registry' USING ERRCODE='0A000';
        END IF;
    END IF;
END; $$;
CREATE TABLE IF NOT EXISTS mcp_proxy_deployment_attestations (
    instance_id UUID PRIMARY KEY REFERENCES mcp_proxy_deployments(instance_id),
    attestation_bytes BYTEA NOT NULL CHECK(octet_length(attestation_bytes) BETWEEN 1 AND 16384),
    authority_bytes BYTEA NOT NULL CHECK(octet_length(authority_bytes) BETWEEN 1 AND 4096),
    registered_at_unix_us BIGINT NOT NULL DEFAULT ((extract(epoch FROM clock_timestamp())*1000000)::BIGINT)
        CHECK(registered_at_unix_us>0)
);
CREATE OR REPLACE FUNCTION mcp_proxy_preserve_attestation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'registration attestation is immutable' USING ERRCODE='23514';
END; $$;
DO $$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='mcp_proxy_deployment_attestations'::regclass AND tgname='mcp_proxy_attestation_immutable') THEN
        CREATE TRIGGER mcp_proxy_attestation_immutable BEFORE UPDATE OR DELETE ON mcp_proxy_deployment_attestations
            FOR EACH ROW EXECUTE FUNCTION mcp_proxy_preserve_attestation();
    END IF;
END; $$;
CREATE TABLE IF NOT EXISTS mcp_proxy_attestations_schema(version INTEGER PRIMARY KEY CHECK(version=1));
INSERT INTO mcp_proxy_attestations_schema VALUES(1) ON CONFLICT DO NOTHING;
