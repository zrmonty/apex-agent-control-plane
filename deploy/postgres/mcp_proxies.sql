CREATE TABLE IF NOT EXISTS mcp_proxies (
    proxy_id UUID PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    slug TEXT NOT NULL,
    description TEXT,
    owner TEXT,
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
        'draft', 'validating', 'awaiting_approval', 'provisioning', 'ready',
        'degraded', 'paused', 'failed', 'retiring', 'retired'
    )),
    redaction_status TEXT NOT NULL CHECK (redaction_status IN ('redacted', 'partially_redacted')),
    active_revision_id UUID,
    draft_revision_id UUID,
    created_at_micros BIGINT NOT NULL CHECK (created_at_micros >= 0),
    desired_state TEXT NOT NULL,
    observed_status TEXT,
    retired_at_micros BIGINT,
    UNIQUE (workspace_id, namespace_id, slug)
);

CREATE INDEX IF NOT EXISTS mcp_proxies_scope_created_idx
    ON mcp_proxies (workspace_id, namespace_id, created_at_micros, proxy_id);

CREATE TABLE IF NOT EXISTS mcp_proxy_revisions (
    proxy_id UUID NOT NULL REFERENCES mcp_proxies(proxy_id),
    revision_id UUID NOT NULL,
    spec_json TEXT NOT NULL,
    config_hash TEXT NOT NULL CHECK (length(config_hash) = 64),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN (
        'draft', 'validating', 'awaiting_approval', 'provisioning', 'ready',
        'degraded', 'paused', 'failed', 'retiring', 'retired'
    )),
    redaction_status TEXT NOT NULL CHECK (redaction_status IN ('redacted', 'partially_redacted')),
    created_by TEXT NOT NULL,
    created_at_micros BIGINT NOT NULL CHECK (created_at_micros >= 0),
    created_at TEXT NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (proxy_id, revision_id),
    UNIQUE (proxy_id, revision_id)
);

CREATE TABLE IF NOT EXISTS mcp_proxy_idempotency (
    request_id UUID NOT NULL,
    operation TEXT NOT NULL,
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    proxy_id UUID NOT NULL REFERENCES mcp_proxies(proxy_id),
    revision_id UUID,
    PRIMARY KEY (request_id, operation),
    UNIQUE (request_id, operation)
);

CREATE TABLE IF NOT EXISTS mcp_proxy_lifecycle_transitions (
    transition_id UUID PRIMARY KEY,
    request_id UUID,
    proxy_id UUID NOT NULL REFERENCES mcp_proxies(proxy_id),
    operation TEXT NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_]{0,63}$'),
    workspace_id TEXT NOT NULL,
    namespace_id TEXT NOT NULL,
    revision_id UUID,
    prior_state TEXT,
    next_state TEXT NOT NULL,
    actor_id TEXT,
    reason_code TEXT NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_.-]{0,127}$'),
    status TEXT NOT NULL CHECK (status ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    occurred_at_micros BIGINT NOT NULL CHECK (occurred_at_micros >= 0)
);

ALTER TABLE mcp_proxy_lifecycle_transitions
    ADD COLUMN IF NOT EXISTS request_id UUID;
