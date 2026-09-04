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
- `apps/control-plane-api/src/proxy/store/postgres/idempotency.rs`
- `apps/control-plane-api/src/proxy/store/postgres/rows.rs`
- `apps/control-plane-api/src/proxy/store/postgres/transitions.rs`
- `apps/control-plane-api/src/proxy/store/transitions.rs`
- `apps/control-plane-api/src/proxy/store/tests.rs`
- `apps/control-plane-api/src/proxy/wire.rs`
- `contracts/proto/apex/v1/mcp_proxy.proto`
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
- PostgreSQL idempotency replay validation in `proxy/store/postgres/idempotency.rs`
- transactional lifecycle transition insertion in `proxy/store/postgres/transitions.rs`
- schema in `deploy/postgres/mcp_proxies.sql`
- explicit CLI `argv_schema` in the protobuf/wire mirror and stored-spec JSON

Also updated startup wiring to warm the proxy postgres backend during startup so schema/config failures surface before serve-loop entry, without implementing lifecycle or service behavior.

### Refactor

Split the store into focused submodules to stay under the source line limit:

- `proxy/store.rs`: 116 lines
- `proxy/store/shared.rs`: 595 lines
- `proxy/store/memory.rs`: 348 lines
- `proxy/store/postgres.rs`: 590 lines
- `proxy/store/postgres/idempotency.rs`: 75 lines
- `proxy/store/postgres/transitions.rs`: 49 lines
- `proxy/store/transitions.rs`: 60 lines
- `proxy/store/tests.rs`: 458 lines
- `proxy/wire.rs`: 526 lines
- `proxy.rs`: 597 lines

`proxy/tests.rs` was left functionally unchanged except for an inline note pointing at the extracted store contract module, preserving that file at 600 lines.

## Behavior implemented

- Strict request/scope validation reusing Task 2 rules
- SecretRef-only persisted spec content via validated `ProxySpec`
- Canonical JSON hashing using lowercase SHA-256 hex
- Immutable published revisions via new revision rows on publish
- Optimistic revision checks on draft update, publish, and retire
- Exact scope isolation on all reads and mutation replay
- Idempotency replay checks compare both canonical payload hash and exact scope in both adapters
- Cursor pagination keyed by `(created_at_micros, proxy_id)`
- Retirement tombstones that preserve slug/identity uniqueness
- Every create, draft update, publish, and retire writes a metadata-only lifecycle transition in the PostgreSQL transaction
- Revision and retirement timestamps use the schema's `created_at_micros`/`retired_at_micros` convention
- Explicit CLI `argv_schema` survives spec serialization/deserialization without inference from `argv_template`
- Parameterized SQL only
- Transactional publication/idempotency recording in postgres

## Verification run

Final focused verification from the isolated worktree:

1. `cargo test -p apex-control-plane-api proxy::store --no-default-features`
   - Passed
   - `test proxy::store::tests::in_memory_store_contract ... ok`

2. `cargo test -p apex-control-plane-api proxy::store --features postgres -- --nocapture`
   - The in-memory contract, schema/SQL compatibility check, and wire round-trip passed.
   - The PostgreSQL contract did not run: `APEX_CONTROL_POSTGRES_URL` was unset and the test printed an explicit skip.

3. `python scripts/test_check_source_line_limits.py`
   - Passed (exit code 0, no violations reported)

## Self-review

What looks good:

- The same contract suite exercises both adapters, so replay/conflict/tombstone semantics stay aligned.
- Postgres publication is transactional and never mutates a published revision row in place.
- The schema includes the required uniqueness constraints for scoped identity, immutable revisions, and idempotency keys.
- Scope mismatches return not-found behavior rather than leaking cross-scope existence.
- No real PostgreSQL contract evidence is claimed without a configured database.

Follow-up note for Task 4:

- Startup warm-up currently opens the postgres proxy store once to validate schema/backend readiness and then drops it. That keeps Task 3’s startup wiring real without prematurely introducing runtime/service ownership, but Task 4 should replace the warm-up-only path with the long-lived store dependency that the tonic service will actually use.

## Review round 1 fix report

Date: 2026-09-04

### Findings addressed

1. PostgreSQL idempotency replay now loads the stored payload hash and exact workspace/namespace scope, compares both against the incoming mutation before replay, returns `PROXY_IDEMPOTENCY_CONFLICT` for changed payloads, and returns scope-safe `PROXY_NOT_FOUND` for a scope mismatch. Create, update draft, publish, and retire all use the same check; the in-memory adapter delegates to the same comparison semantics.
2. UUIDv7 timestamps are converted to microseconds once and used for proxy creation, revision inserts, retirement, cursors, and lifecycle transitions. Revision SQL now names `created_at_micros`, matching the fresh schema.
3. `McpProxyArgSchema` and its fields were added to the protobuf contract and wire mirror. Stored spec JSON writes and reads the explicit schema, with a regression using the existing fixture whose `portfolio_id` schema differs from its `--format json` argv template.
4. Each PostgreSQL create, draft update, publish, and retire mutation inserts one metadata-only lifecycle transition in the same transaction. Rows contain operation, exact scope, proxy, optional actor, revision where applicable, prior/next state, safe reason code, safe status, and microsecond occurrence time; no raw payload or secret value is stored. The in-memory adapter records equivalent metadata for parity checks.
5. The verification section now distinguishes the no-database run from the in-memory/schema checks. The exact external prerequisite for a real PostgreSQL contract run is a reachable database connection string in `APEX_CONTROL_POSTGRES_URL`; none was present in this environment.

### Review-round regression coverage

- Shared idempotency helper: matching hash/scope replays; changed hash conflicts; changed scope is not found.
- Contract suite: same-key replay and changed-payload conflict for create, update draft, publish, and retire, plus immutable revisions, scope isolation, cursor pagination, and retired tombstones.
- Stored-spec round trip: explicit CLI argv schema is preserved.
- Schema/SQL check: rejects `created_at_millis`, requires `created_at_micros`, requires transition metadata columns, and confirms all four mutation call sites use the transition helper.

### Remaining concern

The live PostgreSQL behavior remains unexecuted until `APEX_CONTROL_POSTGRES_URL` points to a reachable test database. The code path is feature-compiled and the schema/SQL compatibility check is non-skipping, but this report does not treat that as a substitute for live database evidence.
