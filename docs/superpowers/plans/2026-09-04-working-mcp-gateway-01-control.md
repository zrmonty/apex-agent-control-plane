# Working MCP Gateway: Control Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make browser operations authenticated, durable and compatible with the actual runtime contract.
**Architecture:** Generate transport types from Protobuf, persist desired operations transactionally, add the Rust session edge, replace preview data, and compile immutable runtime configurations.
**Tech Stack:** Rust/tonic/PostgreSQL; Protobuf/pbjson; generated TypeScript; React/TanStack; OIDC/PKCE.
**Spec:** [Delivery design](../specs/2026-09-04-working-mcp-gateway-design.md); read the [execution index](2026-09-04-working-mcp-gateway.md) first.

## Global constraints

- Apex remains the only policy and durable evidence authority.
- The browser holds no access tokens, refresh tokens, upstream secrets, or runtime credentials.
- Published revisions are immutable; mutations use lowercase UUIDv7 request IDs and optimistic concurrency.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.

Other global constraints in the linked spec also apply. New paths below are proposed implementation files, not existing functionality.

## Task 1: Freeze shared contracts, compatibility fixtures and test entry points

**Files**

- Modify `contracts/proto/apex/v1/mcp_proxy.proto`, `contracts/proto/apex/v1/governance.proto`, `apps/control-plane-api/build.rs`.
- Create `contracts/proto/apex/v1/proxy_runtime.proto`, `proxy_approval.proto`, `proxy_trace.proto` in the same directory.
- Create `contracts/package.json`, `contracts/pnpm-lock.yaml`, `contracts/scripts/generate.mjs`, `contracts/scripts/verify.mjs`.
- Generate `packages/apex-contracts-ts/`; add a package manifest, generated types and a strict JSON conversion boundary.
- Create `contracts/fixtures/mcp-proxy/{control-revision.json,runtime-revision.json,trace.json}` and `contracts/tests/mcp-proxy.test.mjs`.
- Create initial `scripts/verify-working-mcp-gateway.mjs` case registry and `docs/operations/mcp-gateway-release-evidence.md`.

**Interfaces**

Existing `McpProxyService` operations remain compatible. Add `GetProxyCapabilities`, `ListProxyRevisions`, `GetProxyOperation`, `ListProxyBindings`, `ListProxyApprovals`, `DecideProxyApproval`, `GetProxyTrace`. These use existing exact scope/proxy identifiers. `ListProxyActivity` gains a stable cursor and typed call/lifecycle/approval/trace summary variants.

Add a versioned runtime configuration carrying the existing spec fields plus explicit `resource_url`, schemas/output profiles, network grants, telemetry and deployment generation. Define `ProxyOperation` with operation/request/proxy/revision IDs, desired/observed state, generation, error code and observed timestamp. Define runtime RPCs `EnsureRuntime`, `InspectRuntime`, `SetAdmission`, `DrainRuntime`, `RemoveRuntime`, `ProbeUpstream`; all require scope, revision, generation and fencing token. No general exec RPC.

Timing contract example; JSON encodes each integer as a decimal string:

```proto
message ProxyStageTiming {
  string name = 1;
  uint64 started_at_unix_us = 2;
  uint64 duration_us = 3;
  optional uint64 duration_ns = 4;
  string otel_trace_id = 5;
  string span_id = 6;
  string parent_span_id = 7;
  string process_instance_id = 8;
  string clock_source = 9;
  uint64 clock_resolution_ns = 10;
  optional uint64 clock_uncertainty_us = 11;
}
```

- [x] Write failing compatibility tests for different ingress/upstream URLs, canonical approval enums (`none`, `operator`, `dual-operator`), URL-shaped audience, unknown fields, UUIDv4 rejection, unsafe numeric truncation, and missing capability rejection. Create complete control/runtime fixtures from `proxy::tests::valid_proxy_spec()` and `deploy/compose/mcp-proxy-test/revision-config.json`, with distinct real-shape endpoints and no credentials.

```js
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
const trace = JSON.parse(readFileSync(new URL("../fixtures/mcp-proxy/trace.json", import.meta.url)));
assert.equal(trace.durationUs, "7");
assert.equal(typeof trace.startedAtUnixUs, "string");
assert.equal(BigInt(trace.startedAtUnixUs) + 1n, 1788480000123457n);
```

Set that trace fixture's `startedAtUnixUs` to `"1788480000123456"`; include `durationNs: "7000"`. Also round-trip `"9007199254740993"` to catch conversions above JavaScript's safe integer range.

- [x] Run `pnpm --dir contracts test`; expect missing generation/contract behavior, not an unrelated fixture syntax error. Commit no passing claims from nonexistent tests.
- [x] Implement generation with pinned local tooling: Rust descriptor + pbjson serialization and TypeScript protobuf generator/JSON adapters. Generate the browser RPC allowlist from approved services. Add field-count/size validation and descriptor compatibility checking. Generated config validation must preserve unknown-field rejection. Keep the frozen EventEnvelope v1 hash schema unchanged; trace metadata lives in its existing `data` object.
- [x] Run `pnpm --dir contracts generate`, `pnpm --dir contracts test`, `pnpm --dir contracts verify`, `cargo test -p apex-control-plane-api --locked`. `verify` generates into a temporary directory and byte-compares output; it also rejects incompatible field-number reuse. Register acceptance cases that fail explicitly until implemented, with `--list` available immediately.
- [x] Review and commit only contract/generation/fixture/harness files: `feat: define working gateway contracts and compatibility gates`.

## Task 2: Durable operations and atomic lifecycle evidence intent

**Files**

- Modify `apps/control-plane-api/src/proxy/store.rs`, `store/postgres.rs`, `store/postgres/lifecycle.rs`, `store/postgres/transitions.rs`, `proxy/events.rs`, `startup/service/storage.rs`, `startup/service/workers.rs`.
- Create `apps/control-plane-api/src/proxy/store/postgres/operations.rs`, `evidence_intents.rs`, `leases.rs` and `apps/control-plane-api/src/proxy/operation_worker.rs`.
- Create `deploy/postgres/mcp_proxy_operations.sql`; add migration/version checks alongside `mcp_proxies.sql`.
- Create `apps/control-plane-api/tests/proxy_operation_recovery.rs`.

**Interfaces**

`submit_proxy_operation(scope, request_id, expected_revision_id, desired_state) -> ProxyOperation` commits desired state, idempotency result and evidence intent in one Postgres transaction. The intent records immutable event ID, event timestamp, canonical payload and payload hash. `lease_proxy_operation(worker_id, ttl) -> Option<LeasedProxyOperation>` returns a monotonically increasing fencing token; observation writes require that token.

An intent relay calls the existing outbox; it never publishes downstream directly. Each transition has its own event ID; request IDs correlate transitions but are not reused as every transition's event identity. Duplicate retries reproduce original IDs/timestamps/payloads exactly.

- [x] Add crash-boundary tests: transaction rollback, crash after commit/before relay, crash after enqueue/before relay marking, repeated request with different body, stale revision, competing controllers, and production startup without Postgres.

```sql
-- Assertions run by the recovery test after killing and restarting its child.
SELECT count(*) FROM mcp_proxy_operations WHERE request_id = $1;
SELECT count(*) FROM mcp_proxy_evidence_intents WHERE operation_id = $1;
-- First query must be 1; the second equals the number of committed transitions.
-- Every intent must eventually have exactly one canonical accepted event ID.
```

- [x] Run `cargo test -p apex-control-plane-api --features postgres --test proxy_operation_recovery -- --nocapture`; initially fail on absent journal/recovery, and fail clearly if its dedicated test database is unavailable.
- [x] Implement migrations, compare-and-swap generation, lease/fence checks and relay. Preserve existing scopes/idempotency. Require the explicit `production` profile to use Postgres; permit memory only under a named `development` profile. Use bounded blocking DB work outside Tokio worker threads. Keep migration locks and rollback-safe additive schema changes.
- [x] Re-run the recovery suite against real Postgres and `cargo test -p apex-control-plane-api --all-features`. Verify state survives restart without client retries, events survive downstream outage, and no duplicate transition results from lease handoff.
- [x] Commit: `feat: persist proxy operations and lifecycle evidence intents`.

## Task 3: Rust browser sessions and the generated management bridge

**Files**

- Create `apps/control-plane-api/src/browser.rs`, `browser/{oidc.rs,sessions.rs,csrf.rs,rpc.rs,errors.rs,capabilities.rs}`.
- Modify `apps/control-plane-api/src/lib.rs`, `src/startup/service.rs`, `src/startup/env.rs`, `Cargo.toml`, workspace `Cargo.lock`.
- Create `deploy/postgres/operator_sessions.sql` and `apps/control-plane-api/tests/browser_session_flow.rs`.
- Extend `deploy/compose/gateway-ref/keycloak/apex-realm.json` with a local/CI browser client and matching operator claims; keep it explicitly lab-only.

**Interfaces**

Routes: `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`, `GET /api/session`, `POST /api/apex/v1/<Service>/<Method>`. The session response contains subject, authorized scope choices, CSRF token and capabilities, never provider tokens. The RPC bridge decodes generated Protobuf JSON and forwards the operator access credential with a dedicated edge mTLS identity to the existing handlers.

`BrowserSession` contains an opaque random ID, subject, expiry, CSRF binding and an encrypted token bundle in Postgres. Cookie name `__Host-apex_session`, Secure, HttpOnly, SameSite=Lax, Path=/, no Domain. Use a maintained OIDC client and AEAD implementation compatible with the repository license/security policy; do not write cryptography or accept ID tokens as API access tokens.

- [x] Add a real HTTP integration test for login state/nonce/PKCE, callback replay, wrong issuer/audience, expired session, logout, forbidden scope, absent/wrong CSRF, Origin mismatch, token refresh rotation and upstream timeout. Explicitly test that a syntactically valid session cannot turn a denied RPC into an allowed one.

```text
GET /api/session without cookie -> 401, Cache-Control: no-store
POST CreateProxy with cookie but no CSRF -> 403, zero database changes
POST CreateProxy with scope outside operator token -> 403, zero runtime calls
POST CreateProxy with valid session/scope/CSRF -> generated CreateProxyResponse
```

- [x] Run `cargo test -p apex-control-plane-api --features postgres --test browser_session_flow`; expect failure while the routes/session store are absent.
- [x] Add the Rust HTTP edge (Axum/tower modules, with dependencies pinned by lockfile), OIDC code flow, encrypted server-side sessions and strict allowlisted RPC mapping. Reuse scope verification in Rust, not browser claims. Apply request bounds, secure headers/CSP, no-store, safe error mapping (401/403/409/429/503), and audit metadata. No wildcard credentialed CORS, arbitrary redirect URL or provider endpoint supplied by the browser.
- [x] Run the suite and a real Keycloak login in the growing acceptance harness. Confirm browser responses/storage contain no token; revoke/expire the server session and confirm the next mutation is refused. Measure BFF stages using the task-1 timing shape, with clock implementation supplied by task 16.
- [ ] Commit: `feat: add authenticated Rust browser edge for proxy management`.

## Task 4: Replace preview API with honest server state

**Files**

- Modify `apps/operator-ui/src/features/mcp-proxies/{api.ts,types.ts,ProxyListPage.tsx,ProxyDetailPage.tsx}`, `src/app/router.tsx`, `src/layout/AppShell.tsx`, `vite.config.ts`, `package.json`, `pnpm-lock.yaml`.
- Create `apps/operator-ui/src/api/{client.ts,session.ts,request-id.ts}`, `src/features/mcp-proxies/api.test.ts`, `src/test/setup.ts`, `vitest.config.ts`.
- Move demonstration data to `apps/operator-ui/src/test/fixtures/proxies.ts`; production must not import it.

**Interfaces**

`proxyApi` exposes the task-1 generated management methods; inputs/outputs are generated types. UI-only form types may track unsaved editing state but cannot replace contract models. `getSession()` supplies authorized scopes; query keys include subject, workspace, namespace, proxy, revision and filters as applicable. `newRequestId(): string` creates tested UUIDv7 values and the same value is retained for a mutation retry.

- [x] Add Vitest/Testing Library tests for real fetch invocation, credentials/CSRF behavior, no-preview fallback, server error/offline state, scope-switch cache clearing and rejection of stale optimistic updates. Add scripts `test` and `test:watch` to the package with pinned dev dependencies.

```ts
import { expect, test } from "vitest";
import { newRequestId } from "../../api/request-id";
test("uses lowercase UUIDv7 mutation identifiers", () => {
  expect(newRequestId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});
```

- [x] Run `pnpm --dir apps/operator-ui test`; verify tests expose the preview implementation and UUIDv4 behavior before replacement.
- [x] Replace all production `previewProxyApi` imports; add same-origin generated client, route/session guard, scope selector, mutation errors, pagination and server-derived freshness. Display `Unavailable`, `Stale` and `Not configured` when appropriate. Remove “server-authoritative”/“healthy” claims unless backed by a current observation. Wire Vite's development proxy only to the local Rust edge; production uses the deployment HTTPS edge.
- [x] Run UI tests/typecheck/build. In the real harness, create a draft, reload the browser, stop the Rust API and verify data is not fabricated; restore it and verify the same server record appears. Log out and verify scoped query caches clear.
- [ ] Commit: `feat: connect proxy UI to authenticated persistent control plane`.

## Task 5: Compile immutable revisions into runtime configurations

**Files**

- Create `apps/control-plane-api/src/proxy/runtime_config.rs` and `runtime_config/tests.rs`; modify `proxy.rs`, `proxy/validation.rs`, `proxy/wire.rs`.
- Modify `apps/mcp-gateway/src/managed/config.ts`; create `apps/mcp-gateway/src/managed/config-contract.test.ts`.
- Update task-1 control/runtime fixtures and generated contracts; add `apps/control-plane-api/tests/export_runtime_fixture.rs`.

**Interfaces**

`compile_runtime_config(revision: &McpProxyRevision, bindings: &RuntimeDeploymentBindings) -> Result<RuntimeConfiguration, ProxyError>` produces the task-1 generated runtime contract. `RuntimeDeploymentBindings` contains generation, allocated HTTPS resource URL, approved image reference, secret reference metadata, declared network grants, workload identity reference and telemetry policy. It contains no raw secrets. `runtime_manifest_hash(config) -> Result<String, ProxyError>` hashes the deterministic generated representation, excluding the hash field itself; unsupported generated values return a safe error, never a panic or substitute hash.

- [ ] Add cross-language golden tests covering every field, nested array, enum, resource URL audience, distinct ingress/upstream URLs, CPU/memory units, network grants, schema/output profile, rate/approval settings and telemetry precision. Deliberately remove one security setting and assert compilation fails rather than defaulting open.

```powershell
cargo test -p apex-control-plane-api --test export_runtime_fixture
pnpm --dir apps/mcp-gateway exec tsx --test src/managed/config-contract.test.ts
```

The Rust test writes only its temporary test directory; the checked-in golden fixture is updated intentionally. The TypeScript test must consume the Rust-produced artifact in CI, not a separately handwritten lookalike.

- [ ] Run the commands and capture the current enum/audience/shape mismatch as the red result.
- [ ] Implement the compiler and strict generated runtime parsing. Compare control hash and runtime-manifest hash separately. Resolve image IDs through the approved catalog; do not treat arbitrary `sha256:` text as a pullable image reference. Add read-only/config-version startup validation and reject unknown/unimplemented capabilities at publish time.
- [ ] Re-run both sides, contract verify and full gateway tests. Ensure a modified fixture cannot silently widen egress, tools, credential scope or approval policy. Reuse the unchanged portfolio behavior as a regression case.
- [ ] Commit: `feat: compile and verify complete managed runtime configurations`.

## Stage gate G0

- [ ] A real signed-in browser creates and reads its scoped draft after reload and API restart.
- [ ] Production refusal paths never substitute memory/preview data.
- [ ] Generated control/runtime conversion preserves every enforcement field and microsecond integer.
- [ ] Atomic state/evidence intent recovery is demonstrated against Postgres.
- [ ] Record the stage's SHA and commands in the release evidence ledger; proceed to runtime integration.
