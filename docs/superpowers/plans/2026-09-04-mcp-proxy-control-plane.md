# MCP Proxy Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a versioned, durable, scope-authorized MCP proxy resource API with immutable revisions and lifecycle state.

**Architecture:** Add a dedicated `McpProxyService` contract instead of extending the existing agent `ControlGateway`. Store draft desired state and immutable published revisions in the control plane, then expose an idempotent service boundary for validation, deployment, pause, rotation, rollback, retirement, and activity queries.

**Tech Stack:** Rust 2024, tonic, prost, Protobuf, PostgreSQL, existing `apex-auth`, `apex-durability`, `apex-policy`, UUIDv7, serde, and the repository's in-memory/file test patterns.

**Spec:** `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`

## Global Constraints

- Runtime isolation: one hardened OCI container per logical proxy.
- Apex remains the only policy and durable evidence authority.
- Secret values never enter control state, browser state, events, logs, errors, or diagnostic bundles.
- Published revisions are immutable, content-addressed, and rollback-capable.
- Every mutation uses operator authentication, scope authorization, UUIDv7 idempotency, optimistic revision checks, server validation, and a durable lifecycle event.
- The existing `ControlGateway` remains separate from proxy resource lifecycle operations.
- Every changed source and test file must remain at or below 600 lines.

## File map

- Create: `contracts/proto/apex/v1/mcp_proxy.proto` — versioned proxy resource and RPC contract.
- Modify: `apps/control-plane-api/build.rs` — compile the new contract and rerun on changes.
- Create: `apps/control-plane-api/src/proxy.rs` — public proxy domain types and module boundary.
- Create: `apps/control-plane-api/src/proxy/validation.rs` — bounded draft and revision validation.
- Create: `apps/control-plane-api/src/proxy/store.rs` — store trait and in-memory/PostgreSQL adapters.
- Create: `apps/control-plane-api/src/proxy/lifecycle.rs` — state transitions and transition events.
- Create: `apps/control-plane-api/src/proxy/service.rs` — tonic service implementation.
- Modify: `apps/control-plane-api/src/lib.rs` — register and re-export the proxy module/service.
- Create: `deploy/postgres/mcp_proxies.sql` — PostgreSQL tables and unique constraints.
- Create: `apps/control-plane-api/src/proxy/tests.rs` — validation, idempotency, scope, and lifecycle tests.
- Create: `apps/control-plane-api/tests/live_mcp_proxy_control.rs` — live mTLS and PostgreSQL control proof.

## Interfaces

```rust
pub trait ProxyStore: Send + Sync {
    fn create_draft(&self, draft: ProxyDraft) -> Result<McpProxy, ProxyError>;
    fn update_draft(&self, input: UpdateProxyDraft) -> Result<McpProxy, ProxyError>;
    fn publish_revision(&self, input: PublishRevision) -> Result<McpProxyRevision, ProxyError>;
    fn get(&self, scope: ExactScope, proxy_id: ProxyId) -> Result<McpProxy, ProxyError>;
    fn list(&self, query: ListProxies) -> Result<ListProxiesPage, ProxyError>;
}

pub struct ProxyDraft {
    pub proxy_id: ProxyId,
    pub scope: ExactScope,
    pub display_name: String,
    pub slug: String,
    pub spec: ProxySpec,
}

pub struct ProxyId(pub uuid::Uuid);
pub struct ProxyRevisionId(pub uuid::Uuid);

pub enum ProxyLifecycleState {
    Draft,
    Validating,
    AwaitingApproval,
    Provisioning,
    Ready,
    Degraded,
    Paused,
    Failed,
    Retiring,
    Retired,
}

pub struct McpProxyRevision {
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub spec: ProxySpec,
    pub config_hash: String,
}

pub struct ProxyError {
    pub code: String,
    pub message: String,
}

pub trait ProxyRuntimeProvider: Send + Sync {
    fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError>;
    fn readiness(&self, handle: &RuntimeHandle) -> Result<Readiness, ProxyError>;
    fn drain(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
    fn terminate(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
}

pub struct RuntimeHandle {
    pub proxy_id: ProxyId,
    pub revision_id: ProxyRevisionId,
    pub provider_key: String,
}

pub struct Readiness {
    pub endpoint: String,
    pub ready: bool,
}
```

## Task 1: Add the versioned Protobuf contract

**Files:** Create `contracts/proto/apex/v1/mcp_proxy.proto`; modify `apps/control-plane-api/build.rs`; test with the control-plane compile.

- [ ] **Step 1: Write the contract test fixture**

Create a test request fixture in `apps/control-plane-api/src/proxy/tests.rs` with a valid `CreateProxyRequest`, a duplicate idempotency key, and a cross-scope request. Keep all IDs lowercase UUIDv7 values.

- [ ] **Step 2: Run the current compile before the contract exists**

Run `cargo test -p apex-control-plane-api --lib --no-default-features`. Expected: the existing suite passes; no proxy types exist yet.

- [ ] **Step 3: Add `mcp_proxy.proto`**

Define `McpProxyService` with `CreateProxy`, `GetProxy`, `ListProxies`, `UpdateProxyDraft`, `ValidateProxy`, `DiscoverUpstream`, `TestProxyConnection`, `PublishProxyRevision`, `DeployProxy`, `PauseProxy`, `ResumeProxy`, `RotateProxyCredentials`, `RollbackProxy`, `RetireProxy`, and `ListProxyActivity`. Include `workspace_id`, `namespace_id`, `proxy_id`, UUIDv7 `request_id`, opaque page tokens, immutable revision IDs, lifecycle state, redacted status, and secret references only.

- [ ] **Step 4: Register and compile the contract**

Add the proto path and `cargo:rerun-if-changed` line in `build.rs`, then run `cargo test -p apex-control-plane-api --lib --no-default-features`. Expected: generated client/server types compile and the existing suite remains green.

- [ ] **Step 5: Commit**

```powershell
git add contracts/proto/apex/v1/mcp_proxy.proto apps/control-plane-api/build.rs apps/control-plane-api/src/proxy/tests.rs
git commit -m "feat: add MCP proxy management contract"
```

## Task 2: Implement proxy domain types and validation

**Files:** Create `apps/control-plane-api/src/proxy.rs`, `apps/control-plane-api/src/proxy/validation.rs`, and `apps/control-plane-api/src/proxy/tests.rs`; modify `apps/control-plane-api/src/lib.rs`.

**Interfaces:** `ProxyId`, `ProxyRevisionId`, `ProxyLifecycleState`, `ProxySpec`, `UpstreamBinding`, `CliProfile`, `GovernanceBinding`, `ProxyDraft`, `McpProxyRevision`, `ProxyError`, and `validate_proxy_spec(&ProxySpec) -> Result<(), ProxyError>`.

- [ ] **Step 1: Write failing validation tests**

Cover empty slug, invalid scope, unknown transport, missing credential reference, empty tool allowlist, shell-enabled CLI profile, unbounded timeout, unbounded output, private destination without an explicit allow rule, and valid read-only `portfolio.read`.

- [ ] **Step 2: Run the focused tests**

Run `cargo test -p apex-control-plane-api proxy::tests --no-default-features`. Expected: the new tests fail because the proxy module and validator are not implemented.

- [ ] **Step 3: Implement bounded domain types**

Use newtypes for IDs and validated strings. Represent credentials as `SecretRef`, not bytes. Represent CLI arguments as a schema and fixed executable reference. Encode transport, classification, approval mode, limits, and egress destinations as enums or bounded values.

- [ ] **Step 4: Implement validation**

Reject unknown fields before conversion, require exact workspace/namespace scope, enforce maximum lengths and counts, require explicit tool exposure, require `shell = false`, and reject a revision until all referenced policies, credentials, images, and destinations are structurally present.

- [ ] **Step 5: Run the tests and line-limit check**

Run `cargo test -p apex-control-plane-api proxy::tests --no-default-features` and `python scripts/test_check_source_line_limits.py`. Expected: focused tests pass and no changed source file exceeds 600 lines.

- [ ] **Step 6: Commit**

```powershell
git add apps/control-plane-api/src/lib.rs apps/control-plane-api/src/proxy.rs apps/control-plane-api/src/proxy
git commit -m "feat: validate MCP proxy specifications"
```

## Task 3: Add durable storage and immutable revisions

**Files:** Create `apps/control-plane-api/src/proxy/store.rs` and `deploy/postgres/mcp_proxies.sql`; modify control-plane startup wiring and `apps/control-plane-api/src/proxy/tests.rs`.

**Interfaces:** `ProxyStore`, `CreateProxy`, `UpdateProxyDraft`, `PublishRevision`, `ListProxies`, `ListProxiesPage`, and `ProxyRevisionStore` behavior.

- [ ] **Step 1: Write store contract tests**

Test create/read, same-key idempotent replay, same-key changed-payload conflict, optimistic revision conflict, immutable published revision, scope isolation, cursor pagination, and retired-proxy tombstone behavior.

- [ ] **Step 2: Run the tests to verify the missing adapter fails**

Run `cargo test -p apex-control-plane-api proxy::store --no-default-features`. Expected: the tests fail at the missing store implementation.

- [ ] **Step 3: Add PostgreSQL schema**

Create tables for proxy identity, draft JSON/spec, immutable revisions, desired state, observed status, idempotency records, and lifecycle transitions. Add unique constraints for `(workspace_id, namespace_id, slug)`, `(proxy_id, revision_id)`, and `(request_id, operation)`.

- [ ] **Step 4: Implement the store**

Use parameterized queries, canonical JSON hashing, UUIDv7 IDs, cursor tokens based on the last seen `(created_at, proxy_id)`, and transactional revision publication. Provide an in-memory implementation for unit tests and a PostgreSQL implementation behind the existing feature boundary.

- [ ] **Step 5: Run file and PostgreSQL tests**

Run `cargo test -p apex-control-plane-api proxy::store --features postgres`; expected: all store tests pass. Run `python scripts/test_check_source_line_limits.py`.

- [ ] **Step 6: Commit**

```powershell
git add deploy/postgres/mcp_proxies.sql apps/control-plane-api/src/proxy/store.rs apps/control-plane-api/src/proxy/tests.rs
git commit -m "feat: persist MCP proxy revisions"
```

## Task 4: Implement lifecycle and tonic service

**Files:** Create `apps/control-plane-api/src/proxy/lifecycle.rs` and `apps/control-plane-api/src/proxy/service.rs`; modify `apps/control-plane-api/src/main.rs`, `src/lib.rs`, and the service startup wiring.

**Interfaces:** `transition_state`, `McpProxyService`, `ProxyRuntimeProvider`, `ProxyEventSink`, and generated `McpProxyServiceServer`.

- [ ] **Step 1: Write lifecycle and authorization tests**

Cover valid transitions, invalid transitions, operator scope denial, missing approval, deploy idempotency, pause/resume, rollback to a ready revision, and retire terminality.

- [ ] **Step 2: Run focused tests**

Run `cargo test -p apex-control-plane-api proxy::lifecycle --no-default-features`. Expected: failures identify unimplemented transitions and service methods.

- [ ] **Step 3: Implement lifecycle transitions**

Allow only `DRAFT -> VALIDATING -> AWAITING_APPROVAL -> PROVISIONING -> READY`, `READY <-> DEGRADED`, `READY -> PAUSED`, `PAUSED -> PROVISIONING`, `READY|DEGRADED|PAUSED -> RETIRING -> RETIRED`, and explicit `VALIDATING|PROVISIONING -> FAILED`. Persist every transition with actor, reason, revision, and trace IDs.

- [ ] **Step 4: Implement the tonic service**

Authenticate the operator with the existing operator credential path, enforce `ExactScope`, validate request sizes, apply idempotency, delegate to `ProxyStore`, and emit lifecycle events through the existing durable event boundary. Keep runtime-provider calls outside the transaction and reconcile from persisted desired state.

- [ ] **Step 5: Run service tests and workspace verification**

Run `cargo test -p apex-control-plane-api --lib --features "test-support,postgres"` and `cargo test --workspace --locked`. Expected: all existing and new tests pass.

- [ ] **Step 6: Commit**

```powershell
git add apps/control-plane-api/src/main.rs apps/control-plane-api/src/lib.rs apps/control-plane-api/src/proxy
git commit -m "feat: manage MCP proxy lifecycle"
```

## Task 5: Live control-plane proof

**Files:** Create `apps/control-plane-api/tests/live_mcp_proxy_control.rs`; modify `deploy/postgres/mcp_proxies.sql` and the live test setup only when the test demonstrates a missing durable constraint.

- [ ] **Step 1: Write the live test**

Drive create, publish, deploy intent, status read, pause, resume, rollback, and retire over mTLS. Assert a different workspace cannot read or mutate the proxy and that duplicate requests do not create duplicate revisions.

- [ ] **Step 2: Run the live test against the current stack**

Run `cargo test -p apex-control-plane-api --test live_mcp_proxy_control -- --nocapture`. Expected: the new test fails until the live service is wired into the deployment profile.

- [ ] **Step 3: Wire the live service and schema**

Add only the control-plane service registration, PostgreSQL schema application, and required environment references. Do not add a browser-to-Docker path.

- [ ] **Step 4: Run the live test and commit**

Run the focused live test again; expected: pass with no secret values in output. Commit with `git commit -m "test: prove MCP proxy control lifecycle"`.
