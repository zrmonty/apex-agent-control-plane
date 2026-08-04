# Valkey Acceleration Layer

**Status:** Accepted — optional deployment capability  
**Date:** 2026-08-03

## Decision

Add **Valkey** as an optional, self-hosted acceleration layer for short-lived, non-authoritative data.

Valkey is Redis-compatible and BSD-licensed. It is not required for a functional local installation. Apex must continue safely when Valkey is unavailable.

Authoritative stores:

| Concern | Authority |
|---|---|
| Control state, roles, approvals, enrollment consumption, durable idempotency | PostgreSQL |
| Durable event backbone | NATS JetStream |
| Analytical store | ClickHouse |
| Records authority | Immutable archive storage |

Valkey must never satisfy an audit, compliance, authorization, retention, legal-hold, or financial-ledger requirement.

## Approved uses

| Use | Data | Failure behavior |
|---|---|---|
| Ingest and API rate limiting | Hashed scope and identity keys and counters with short TTL | Fail closed or use a conservative local limiter for protected endpoints. Never fail open without an explicit local-development policy. |
| Abuse and attack counters | Fingerprints for denied auth, prompt-injection blocks, tool or egress denials, malformed events | Continue durable security findings. Temporarily lose only cross-instance aggregation. |
| Ephemeral query cache | Already-redacted, scope and version-bound UI or API results with bounded TTL | Cache miss falls back to the authorized source query. |
| Real-time UI fan-out | Presence, short-lived invalidation notices, and live-view cursors | UI reconnects to the control API or SSE. No control action is lost or assumed successful. |
| Revocation acceleration | Short-lived deny cache keyed by identity, certificate, or enrollment fingerprint | Authoritative revocation check remains PostgreSQL or policy. Protected admission fails closed if it cannot obtain a safe decision. |
| Distributed work hints | TTL locks and fencing tokens for non-authoritative background optimization only | PostgreSQL transactions or Kubernetes leases remain the authority for state-changing reconciliation. |

## Explicitly prohibited uses

- Canonical telemetry, event replay, or consumer offsets
- Human sessions or the Keycloak identity store
- Authorization grants, role membership, approvals, policy definitions, policy exceptions, or legal holds
- One-time enrollment-code consumption without a PostgreSQL transactional record
- Audit, security-finding, diagnostic, cost-ledger, archive, or retention records
- Prompt, completion, or tool content, credentials, private keys, cookies, raw ePHI, or raw payment-card data
- General Lua or function execution from application clients

## Security profile

1. Keep Valkey internal only. Do not publish a host port in the default Compose profile. Do not publish a public service or load balancer in Kubernetes.
2. Disable the unauthenticated default user. Use separate least-privilege ACL identities and key prefixes per Apex service.
3. Use mTLS with a private CA. Disable the plaintext port (`port 0`) in production. Map client certificates to ACL users. See [Valkey TLS](https://valkey.io/topics/encryption/) and [Valkey ACL](https://valkey.io/topics/acl/).
4. Mount credentials and TLS material from the secret system. Do not use command-line arguments, source files, or browser configuration.
5. Deny dangerous admin and scripting commands for application identities, including `FLUSH*`, `CONFIG`, `MODULE`, `ACL`, `SCRIPT`, `EVAL`, and `FUNCTION`.
6. Set explicit memory ceilings, per-key TTLs, max value sizes, client and connection limits, and latency or error telemetry. Eviction may affect only recoverable cache or hint keys.
7. Pin the image by digest. Scan it in CI. Patch on supported releases. Use backup and restore only for operational configuration. Do not use Valkey as source-of-truth recovery.

An unhardened Valkey instance can bind broadly and run unauthenticated by default. Apex therefore never ships it exposed or with the default user enabled. See [Valkey installation security](https://valkey.io/topics/installation/).

## Implementation plan

### Phase 0 — interface and protected use cases

**Status: implemented in tree.**

1. **Done:** Rust `EphemeralStore` capability boundary (`rate limit`, `fingerprint counter`, `deny hint`) in `apps/event-ingest/src/ephemeral/`. Product code does not get a generic key-value client.
2. **Done:** `InMemoryEphemeralStore` process-local fallback. `ValkeyEphemeralStore` behind Cargo feature `valkey` (`redis` crate, mTLS and ACL username and password from files).
3. **Done:** Optional Compose overlay `deploy/compose/compose.valkey.yaml` (internal network, TLS port only, ACL file, no default user, no host port, digest-pinned `VALKEY_IMAGE`).
4. **Done:** Gateway admission uses the store for distributed request rate limits when configured. Process-local buckets remain a hard ceiling. Keys use fixed prefix `apex:ingest:` with safe scope identifiers only.
5. **Done (unit):** Fallback-on-unavailable, invalid-key fail-closed, Redis key-shape tests, deny-hint semantics. Live ACL and TLS handshake remains an environment acceptance check with real certs.

Redacted UI cache and non-authoritative leases remain Phase 1.

### Phase 1 — operator and UI acceleration

1. Add redacted query caching and live-view invalidation with cache-version keys tied to scope and authorization or policy revision.
2. Add Valkey health and capacity to Operations Home. Make degraded behavior visible.

### Phase 2 — optional production HA

1. Offer Sentinel or cluster topology only for installations whose measured rate-limit or cache load requires it.
2. Keep HA optional. Do not require it for a single-host self-hosted profile.

## Acceptance criteria

- Disabling Valkey never causes Apex to grant access, lose a control, audit, or cost record, or misrepresent command success.
- No Valkey value contains restricted content or a durable authority record.
- Every application identity is restricted by mTLS, ACL command set, and service-specific key pattern.
- A security or rate-limit decision is reproducible from authoritative data when the cache is empty, evicted, or restarted.

Writing style: [ASD-STE100 Simplified Technical English](../writing-style-ste100.md).
