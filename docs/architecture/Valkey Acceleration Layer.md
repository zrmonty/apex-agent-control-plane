# Valkey Acceleration Layer

**Status:** Accepted — optional deployment capability  
**Date:** 2026-08-03

## Decision

Add **Valkey** as an optional, self-hosted acceleration layer for short-lived, non-authoritative data. Valkey is Redis-compatible and BSD-licensed. It is not required for a functional local installation, and Apex must continue safely when it is unavailable.

PostgreSQL remains authoritative for control state, roles, approvals, enrollment consumption, and durable idempotency. NATS JetStream remains the durable event backbone. ClickHouse remains the analytical store. Immutable archive storage remains the records authority. Valkey is never used to satisfy an audit, compliance, authorization, retention, legal-hold, or financial-ledger requirement.

## Approved uses

| Use | Data | Failure behavior |
|---|---|---|
| Ingest/API rate limiting | Hashed scope/identity keys and counters with short TTL. | Fail closed or use a conservative local limiter for protected endpoints; never fail open without an explicit local-development policy. |
| Abuse and attack counters | Fingerprints for denied auth, prompt-injection blocks, tool/egress denials, malformed events. | Continue creating durable security findings; temporarily lose only cross-instance aggregation. |
| Ephemeral query cache | Already-redacted, scope/version-bound UI/API results with bounded TTL. | Cache miss falls back to authorized source query. |
| Real-time UI fan-out | Presence, short-lived invalidation notices, and live-view cursors. | UI reconnects to the control API/SSE; no control action is lost or assumed successful. |
| Revocation acceleration | Short-lived deny cache keyed by identity/certificate/enrollment fingerprint. | Authoritative revocation check remains PostgreSQL/policy; protected admission fails closed if it cannot obtain a safe decision. |
| Distributed work hints | TTL locks and fencing tokens for non-authoritative background optimization only. | PostgreSQL transactions or Kubernetes leases remain the authority for state-changing reconciliation. |

## Explicitly prohibited uses

- Canonical telemetry, event replay, or consumer offsets.
- Human sessions or the Keycloak identity store.
- Authorization grants, role membership, approvals, policy definitions, policy exceptions, or legal holds.
- One-time enrollment-code consumption without a PostgreSQL transactional record.
- Audit, security-finding, diagnostic, cost-ledger, archive, or retention records.
- Prompt/completion/tool content, credentials, private keys, cookies, raw ePHI, or raw payment-card data.
- General Lua/function execution from application clients.

## Security profile

- Valkey is internal-only: no host-published port in the default Compose profile and no public service/load balancer in Kubernetes.
- Disable the unauthenticated default user. Use separate least-privilege ACL identities and key prefixes per Apex service.
- Use mTLS with a private CA; disable the plaintext port (`port 0`) in production. Valkey supports client-certificate authentication mapped to ACL users. [Valkey TLS](https://valkey.io/topics/encryption/), [Valkey ACL](https://valkey.io/topics/acl/)
- Mount credentials and TLS material from the secret system; never command-line arguments, source files, or browser configuration.
- Deny dangerous/admin/scripting commands for application identities, including `FLUSH*`, `CONFIG`, `MODULE`, `ACL`, `SCRIPT`, `EVAL`, and `FUNCTION`.
- Set explicit memory ceilings, per-key TTLs, max value sizes, client/connection limits, and latency/error telemetry. Eviction may affect only recoverable cache/hint keys.
- Pin the image by digest, scan it in CI, patch on supported releases, and require backup/restore only for operational configuration—not as a source-of-truth recovery mechanism.

Valkey documents that an unhardened instance can bind broadly and be unauthenticated by default; Apex therefore never ships it exposed or with the default user enabled. [Valkey installation security](https://valkey.io/topics/installation/)

## Implementation plan

### Phase 0 — interface and protected use cases

1. Create a small Rust `EphemeralStore` interface with capability-specific operations: rate limit, fingerprint counter, redacted cache, revocation deny hint, and non-authoritative lease. Do not expose a generic key-value client to product code.
2. Implement an in-process bounded fallback for local development and a Valkey adapter behind an explicit `valkey` deployment feature.
3. Add an optional Compose profile with internal networking, mTLS, ACL file, non-TLS port disabled, no default user, no host port, and digest-pinned image.
4. Implement rate limits and security-finding fingerprint counters first. Every operation must use scoped, HMAC-derived key segments and explicit TTLs.
5. Test fail-closed protected endpoints, ACL denial, TLS/client-certificate failure, eviction/cache loss, restart, rate-limit bypass attempts, key-collision resistance, and no-sensitive-data assertions.

### Phase 1 — operator and UI acceleration

1. Add redacted query caching and live-view invalidation with cache-version keys tied to scope and authorization/policy revision.
2. Add Valkey health/capacity to Operations Home and make degraded behavior visible.

### Phase 2 — optional production HA

1. Offer Sentinel/cluster topology only for installations whose measured rate-limit/cache load requires it.
2. Keep HA optional; do not require it for a single-host self-hosted profile.

## Acceptance criteria

- Disabling Valkey never causes Apex to grant access, lose a control/audit/cost record, or misrepresent command success.
- No Valkey value contains restricted content or a durable authority record.
- Every application identity is restricted by mTLS, ACL command set, and service-specific key pattern.
- A security/rate-limit decision is reproducible from authoritative data when the cache is empty, evicted, or restarted.
