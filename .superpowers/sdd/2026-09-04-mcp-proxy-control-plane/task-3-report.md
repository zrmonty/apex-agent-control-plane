# Task 3 Report — durable storage and immutable revisions

Date: 2026-09-04
Worktree: `E:\Agent Control Plane\.worktrees\mcp-proxy-platform`
Branch: `codex/mcp-proxy-platform`
Base reviewed dependency: Task 2 domain boundary at `a6e06be210c0472cc2cfae7470a4c538e452773d`

## Scope completed

Implemented the Task 3 storage contract for MCP proxies with immutable UUIDv7-backed revisions, canonical lowercase hashing, exact workspace/namespace isolation, tombstone-preserving retirement, and PostgreSQL durability behind the existing feature boundary.

## Files changed

- `apps/control-plane-api/src/proxy.rs`
- `apps/control-plane-api/src/proxy/tests.rs`
- `apps/control-plane-api/src/proxy/store.rs`
- `apps/control-plane-api/src/proxy/store/shared.rs`
- `apps/control-plane-api/src/proxy/store/memory.rs`
- `apps/control-plane-api/src/proxy/store/postgres.rs`
- `apps/control-plane-api/src/proxy/store/postgres/rows.rs`
- `apps/control-plane-api/src/proxy/store/tests.rs`
- `apps/control-plane-api/src/lib.rs`
- `apps/control-plane-api/src/startup/service.rs`
- `apps/control-plane-api/src/startup/service/storage.rs`
- `deploy/postgres/mcp_proxies.sql`

## TDD record

### Red

Wrote the contract test suite first for:

- create/read
- same-key idempotent replay
- same-key changed-payload conflict
- optimistic revision conflict
- immutable published revision
- scope isolation
- cursor pagination
- retired tombstone behavior

Then ran:

`cargo test -p apex-control-plane-api proxy::store --no-default-features`

Observed expected failure before implementation: unresolved imports for the missing store types and adapters (`CreateProxy`, `InMemoryProxyStore`, `ListProxies`, `ProxyRevisionStore`, `ProxyStore`, `PublishRevision`, `UpdateProxyDraft`).

### Green

Added:

- store traits and DTOs in `proxy/store.rs`
- shared validation/hash/cursor/revision helpers in `proxy/store/shared.rs`
- in-memory adapter in `proxy/store/memory.rs`
- postgres adapter in `proxy/store/postgres.rs`
- postgres row mappers in `proxy/store/postgres/rows.rs`
- schema in `deploy/postgres/mcp_proxies.sql`

Also updated startup wiring to warm the proxy postgres backend during startup so schema/config failures surface before serve-loop entry, without implementing lifecycle or service behavior.

### Refactor

Split the store into focused submodules to stay under the source line limit:

- `proxy/store.rs`: 115 lines
- `proxy/store/shared.rs`: 560 lines
- `proxy/store/memory.rs`: 233 lines
- `proxy/store/postgres.rs`: 538 lines
- `proxy/store/tests.rs`: 292 lines
- `proxy.rs`: 597 lines

`proxy/tests.rs` was left functionally unchanged except for an inline note pointing at the extracted store contract module, preserving that file at 600 lines.

## Behavior implemented

- Strict request/scope validation reusing Task 2 rules
- SecretRef-only persisted spec content via validated `ProxySpec`
- Canonical JSON hashing using lowercase SHA-256 hex
- Immutable published revisions via new revision rows on publish
- Optimistic revision checks on draft update, publish, and retire
- Exact scope isolation on all reads and mutation replay
- Cursor pagination keyed by `(created_at_micros, proxy_id)`
- Retirement tombstones that preserve slug/identity uniqueness
- Parameterized SQL only
- Transactional publication/idempotency recording in postgres

## Verification run

Final focused verification from the isolated worktree:

1. `cargo test -p apex-control-plane-api proxy::store --no-default-features`
   - Passed
   - `test proxy::store::tests::in_memory_store_contract ... ok`

2. `cargo test -p apex-control-plane-api proxy::store --features postgres`
   - Passed
   - `test proxy::store::tests::postgres_store_contract ... ok`
   - `test proxy::store::tests::in_memory_store_contract ... ok`

3. `python scripts/test_check_source_line_limits.py`
   - Passed (exit code 0, no violations reported)

## Self-review

What looks good:

- The same contract suite exercises both adapters, so replay/conflict/tombstone semantics stay aligned.
- Postgres publication is transactional and never mutates a published revision row in place.
- The schema includes the required uniqueness constraints for scoped identity, immutable revisions, and idempotency keys.
- Scope mismatches return not-found behavior rather than leaking cross-scope existence.

Follow-up note for Task 4:

- Startup warm-up currently opens the postgres proxy store once to validate schema/backend readiness and then drops it. That keeps Task 3’s startup wiring real without prematurely introducing runtime/service ownership, but Task 4 should replace the warm-up-only path with the long-lived store dependency that the tonic service will actually use.
