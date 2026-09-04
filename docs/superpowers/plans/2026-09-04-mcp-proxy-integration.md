# MCP Proxy Integration and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the complete managed MCP proxy path in containers and CI, including isolation, governance, credentials, lifecycle, evidence, UI, performance, and teardown.

**Architecture:** Add a Docker/OCI runtime provider behind the control-plane lifecycle API, extend the existing live Compose profile with a disposable test proxy, and make the CI/live workflows run focused proxy gates before the full repository gate. Keep the current `portfolio.read` proof as the first acceptance scenario.

**Tech Stack:** Docker Compose, existing mTLS PKI, Rust live tests, TypeScript gateway proof scripts, React/Playwright, PostgreSQL, NATS/ClickHouse evidence path, GitHub Actions, and the existing source-line-limit checker.

**Spec:** `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`

## Global Constraints

- One hardened OCI container per logical proxy.
- No browser-to-Docker or browser-to-secret-provider path.
- Apex remains the only policy and durable evidence authority.
- Downstream analytics outage must not lose a durably admitted event.
- Secrets are references in control state and never appear in test output or artifacts.
- CLI tools use fixed profiles with typed argv; arbitrary shell execution is prohibited.
- The first acceptance slice is read-only `portfolio.read`.
- Existing unrelated roadmap holds remain active.
- Every changed source and test file must remain at or below 600 lines.

## File map

- Create: `apps/control-plane-api/src/proxy/provider.rs` — provider trait and Docker/OCI adapter.
- Create: `apps/control-plane-api/src/proxy/reconciler.rs` — idempotent desired/observed reconciliation.
- Create: `apps/control-plane-api/tests/live_mcp_proxy_runtime.rs` — live container isolation and lifecycle proof.
- Create: `deploy/compose/compose.mcp-proxy.yaml` — disposable proxy provider profile.
- Create: `deploy/compose/mcp-proxy-test/` — fixed upstream, CLI fixture, and health helpers.
- Create: `apps/mcp-gateway/scripts/live_managed_proxy_proof.mjs` — governed MCP call and activity proof.
- Create: `deploy/compose/loadtest/mcp_proxy_loadtest.py` — bounded concurrency and latency measurement.
- Modify: `deploy/compose/compose.gateway-ref.yaml` — provider network/secrets only through the control-plane path.
- Modify: `.github/workflows/ci.yml` — cached gateway/UI checks and proxy contract tests.
- Modify: `.github/workflows/live-mtls-e2e.yml` — live proxy gate with teardown.
- Modify: `docs/performance/gateway-throughput-baseline.md` — measured proxy overhead and resource baseline.
- Create: `docs/security/mcp-proxy-threat-model.md` — reviewed threat/control matrix.

## Interfaces

The provider implements the exact `ProxyRuntimeProvider` interface from the control-plane plan:

```rust
fn provision(&self, revision: &McpProxyRevision) -> Result<RuntimeHandle, ProxyError>;
fn readiness(&self, handle: &RuntimeHandle) -> Result<Readiness, ProxyError>;
fn drain(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
fn terminate(&self, handle: &RuntimeHandle) -> Result<(), ProxyError>;
```

## Task 1: Add the runtime provider and reconciler

**Files:** Create `apps/control-plane-api/src/proxy/provider.rs` and `reconciler.rs`; modify proxy module wiring and test support.

- [ ] **Step 1: Write fake-provider reconciliation tests**

Test create-once, restart convergence, readiness failure, retry after degraded state, pause drain, retirement, duplicate command, and old-revision cleanup. Assert one provider key per `(proxy_id, revision_id)`.

- [ ] **Step 2: Run focused tests**

Run `cargo test -p apex-control-plane-api proxy::reconciler --no-default-features`. Expected: failures identify missing provider and reconciler behavior.

- [ ] **Step 3: Implement provider interfaces**

Keep Docker command construction in the provider adapter. Keep the reconciler free of Docker-specific flags. Apply deterministic labels, revision hashes, resource limits, network policy, secret references, and health checks.

- [ ] **Step 4: Implement idempotent reconciliation**

Persist desired state first, create or find the provider key, wait for readiness, publish observed endpoint, drain the old revision, and record every transition. Controller restart must converge without duplicate active runtimes.

- [ ] **Step 5: Run tests, workspace verification, and commit**

Run `cargo test -p apex-control-plane-api --lib --features "test-support,postgres"`, `cargo test --workspace --locked`, and `python scripts/test_check_source_line_limits.py`; expected: pass. Commit with `git commit -m "feat: reconcile isolated MCP proxy runtimes"`.

## Task 2: Add the live Compose proxy profile

**Files:** Create `deploy/compose/compose.mcp-proxy.yaml` and `deploy/compose/mcp-proxy-test/`; modify the gateway-ref Compose profile only for explicit provider wiring.

- [ ] **Step 1: Write Compose validation assertions**

Assert proxy containers run non-root, read-only, with no-new-privileges, dropped capabilities, bounded tmpfs, no host network, no host mounts, no runtime socket, and only declared networks/secrets.

- [ ] **Step 2: Run Compose config before wiring**

Run `docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.gateway-ref.yaml -f deploy/compose/compose.mcp-proxy.yaml config`. Expected: the new profile is not yet valid.

- [ ] **Step 3: Add fixed test upstreams and provider profile**

Create a deterministic read-only MCP upstream and a CLI fixture with safe output. Mount only staged 0600 secret material and use network aliases that match the declared egress policy.

- [ ] **Step 4: Validate the profile**

Run the Compose config command again; expected: success. Start the profile with the existing live-mTLS setup and inspect `docker inspect` for security options, user, mounts, capabilities, and networks.

- [ ] **Step 5: Commit**

```powershell
git add deploy/compose/compose.mcp-proxy.yaml deploy/compose/mcp-proxy-test deploy/compose/compose.gateway-ref.yaml
git commit -m "test: add isolated MCP proxy Compose profile"
```

## Task 3: Run the live end-to-end proof

**Files:** Create `apps/control-plane-api/tests/live_mcp_proxy_runtime.rs` and `apps/mcp-gateway/scripts/live_managed_proxy_proof.mjs`; modify live workflow only after local proof passes.

- [ ] **Step 1: Write the live proof**

Create two proxies with different scopes and revisions. Prove create, validate, publish, provision, readiness, governed `portfolio.read`, filtered output, activity, pause, resume, credential rotation, rollback, retire, and teardown.

- [ ] **Step 2: Add negative-path assertions**

Prove cross-proxy file/session/credential/cache isolation, wrong audience, expired token, unapproved tool, unsafe URL, unsafe CLI argv, output overflow, policy denial, approval hold, upstream failure, and event-admission failure.

- [ ] **Step 3: Run the focused live gate**

Run `cargo test -p apex-control-plane-api --test live_mcp_proxy_runtime -- --nocapture` and `node apps/mcp-gateway/scripts/live_managed_proxy_proof.mjs`. Expected: pass with metadata-only output and no secret leakage.

- [ ] **Step 4: Add live CI orchestration**

Add the focused test and proof to `.github/workflows/live-mtls-e2e.yml` after PKI/services are ready and before teardown. Preserve existing cleanup on failure.

- [ ] **Step 5: Commit**

Commit with `git commit -m "test: prove managed MCP proxy end to end"`.

## Task 4: Add threat model and performance evidence

**Files:** Create `docs/security/mcp-proxy-threat-model.md` and `deploy/compose/loadtest/mcp_proxy_loadtest.py`; modify `docs/performance/gateway-throughput-baseline.md`.

- [ ] **Step 1: Write threat-model checks**

Map threats to controls for token passthrough, confused deputy, tool poisoning, SSRF, DNS rebinding, CLI injection, secret leakage, container escape, cross-proxy access, replay, stale revisions, and evidence loss.

- [ ] **Step 2: Write bounded load measurements**

Measure cold start, readiness, first call, warm p50/p95/p99 overhead, upstream reuse, discovery, CLI startup, filter cost, evidence admission, idle memory/CPU, active memory/CPU, and safe concurrency for one and multiple proxies.

- [ ] **Step 3: Run measurements and record evidence**

Run `python deploy/compose/loadtest/mcp_proxy_loadtest.py --proxies 1,2,8 --concurrency 1,8,32`; record environment, revision, container limits, sample count, failures, and results. Do not invent SLOs from a single run.

- [ ] **Step 4: Commit**

Commit with `git commit -m "docs: record MCP proxy threats and performance"`.

## Task 5: Add CI gates and final release verification

**Files:** Modify `.github/workflows/ci.yml` and `.github/workflows/live-mtls-e2e.yml`; modify docs only for final command accuracy.

- [ ] **Step 1: Add fast contract/UI gates**

Cache pnpm dependencies using each lockfile, run gateway typecheck/tests/build, UI typecheck/tests/build, and Rust proxy contract tests in parallel where dependencies permit.

- [ ] **Step 2: Add live proxy gate**

Run the managed proxy proof with the existing mTLS, Keycloak, PostgreSQL, Valkey, NATS, and teardown sequence. Upload only redacted logs and status summaries.

- [ ] **Step 3: Run the full local gate**

Run the commands in the master plan's final acceptance section and confirm each exit code is zero. Run `git diff --check` and inspect `git status --short`.

- [ ] **Step 4: Commit the workflow changes**

Commit with `git commit -m "ci: gate managed MCP proxy platform"`.

- [ ] **Step 5: Final review checklist**

Confirm the roadmap still holds unrelated work, the design and source ledger links resolve, no source/test file exceeds 600 lines, no secret appears in tracked files, and the live proof demonstrates the server-derived UI activity path.
