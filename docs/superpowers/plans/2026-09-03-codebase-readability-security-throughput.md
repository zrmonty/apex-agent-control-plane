# Codebase Readability, Security, and Throughput Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the active Apex codebases for human readability, security hardening, and measured throughput without weakening the live vertical slice or activating held roadmap work.

**Architecture:** Split oversized modules by responsibility first, preserving public interfaces and behavior. Then harden trust boundaries using existing fail-closed patterns. Finally optimize only measured hot paths, keeping blocking IO off async workers and preserving authorization-before-adapter and durable-admission-before-success ordering.

**Tech Stack:** Rust 2024, Tokio, tonic, existing Apex crates and test-support fixtures, Node 24 TypeScript, MCP SDK, pnpm, Docker Compose, cargo test/clippy/audit, targeted load-test harnesses.

**Spec:** `docs/superpowers/specs/2026-09-03-live-vertical-slice-and-hardening-design.md`

## Global Constraints

- No tracked source or test file may exceed 600 lines after each checkpoint.
- Splits must be by responsibility and must not change public behavior.
- Security changes fail closed and never log credentials, raw records, or server-controlled diagnostic text.
- Throughput changes require a before/after measurement and must preserve policy, redaction, idempotency, and durable event semantics.
- Work remains limited to active gateway/governance/event foundations; held roadmap features stay paused.

---

### Task 1: Inventory and enforce the readability baseline

**Files:**
- Create: `scripts/check_source_line_limits.py`
- Create: `scripts/test_check_source_line_limits.py`
- Create: `docs/architecture/codebase-hardening-baseline.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add the failing checker test**

Test that a fixture source file with 601 lines is reported and that `.git`, `target`, `node_modules`, `dist`, `build`, and virtual-environment directories are ignored.

- [ ] **Step 2: Run the test to verify it fails**

Run: `python -m pytest scripts/test_check_source_line_limits.py -q`

Expected: FAIL because the checker does not exist.

- [ ] **Step 3: Implement the checker and baseline**

Scan tracked `.rs`, `.ts`, `.tsx`, `.js`, `.mjs`, `.py`, `.go`, `.java`, and `.cs` files; print path and line count for every file over 600 and return nonzero. Record the current offenders and the responsibility-based split order in the baseline document.

- [ ] **Step 4: Verify and add CI enforcement**

Run: `python scripts/check_source_line_limits.py`; `python -m pytest scripts/test_check_source_line_limits.py -q`. Add the checker to CI after checkout and before the expensive build matrix.

- [ ] **Step 5: Commit**

```powershell
git add scripts/check_source_line_limits.py scripts/test_check_source_line_limits.py docs/architecture/codebase-hardening-baseline.md .github/workflows/ci.yml
git commit -m "chore: enforce source readability limits"
```

### Task 2: Split oversized Rust modules

**Files:**
- Split: `apps/event-ingest/src/auth/service.rs`
- Split: `apps/event-ingest/src/startup/service.rs`
- Split: `crates/apex-policy/src/types.rs`
- Split: `crates/apex-durability/src/outbox/tests_cases.rs`
- Split: `apps/control-plane-api/src/inbox_postgres.rs`
- Split: `apps/control-plane-api/src/startup/tests.rs`
- Split: `crates/apex-security/src/tests.rs`
- Split: `apps/control-plane-api/src/service/tests/poll.rs`
- Split: `apps/control-plane-api/src/envelope.rs`

- [ ] **Step 1: Record stable module surfaces**

Before each split, capture the existing public exports with `cargo test` and `cargo doc --workspace --no-deps`; keep original module paths and re-export names unchanged.

- [ ] **Step 2: Split by responsibility**

Move transport/auth implementation and tests under focused `auth/` modules; separate startup configuration, TLS, workers, and tests; separate policy identifiers, requests, decisions, and event types; group outbox tests by backend; separate Postgres inbox read/write/recovery; and separate control envelope construction from timestamp/hash helpers.

- [ ] **Step 3: Run focused tests after each group**

Run: `cargo test -p apex-event-ingest --lib`; `cargo test -p apex-policy`; `cargo test -p apex-durability`; `cargo test -p apex-control-plane-api --lib --features test-support`; `cargo test -p apex-security`.

Expected: PASS after every responsibility group with no behavior changes.

- [ ] **Step 4: Run line and style checks**

Run: `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `python scripts/check_source_line_limits.py`.

Expected: PASS and no tracked Rust source/test file over 600 lines.

- [ ] **Step 5: Commit**

```powershell
git add apps crates
git commit -m "refactor: split oversized Rust modules"
```

### Task 3: Split oversized TypeScript tests and shared fixtures

**Files:**
- Split: `apps/mcp-gateway/src/execution.test.ts`
- Create: `apps/mcp-gateway/src/test-support/fixtures.ts`
- Modify: `apps/mcp-gateway/src/execution.ts` only for pure helper extraction

- [ ] **Step 1: Run the unchanged gateway suite**

Run: `pnpm --dir apps/mcp-gateway test`; `pnpm --dir apps/mcp-gateway typecheck`.

Expected: PASS before the split.

- [ ] **Step 2: Extract fixtures and scenario files**

Group assertions into authorization/admission, filtering/serialization, errors, and live-client files; move only shared immutable fixtures to `test-support/fixtures.ts`; preserve each assertion and public production import.

- [ ] **Step 3: Verify the split**

Run: `pnpm --dir apps/mcp-gateway test`; `pnpm --dir apps/mcp-gateway typecheck`; `pnpm --dir apps/mcp-gateway build`; `python scripts/check_source_line_limits.py`.

Expected: PASS with no TypeScript/JavaScript file over 600 lines.

- [ ] **Step 4: Commit**

```powershell
git add apps/mcp-gateway
git commit -m "refactor: split gateway tests for readability"
```

### Task 4: Harden security boundaries

**Files:**
- Modify: live gateway secret/client modules
- Modify: `apps/control-plane-api/src/governance.rs`
- Modify: `apps/event-ingest/src/auth/`
- Modify: `crates/apex-domain/src/validation/`
- Modify: `deploy/compose/compose.gateway-ref.yaml`
- Create: `docs/security/codebase-hardening-review.md`
- Test: focused Rust, TypeScript, and Python adversarial tests

- [ ] **Step 1: Add adversarial regression tests**

Cover symlinked/unsafe secrets, duplicate auth headers, operator-agent-gateway credential crossover, oversized or deeply nested Structs, malformed resources, raw error suppression, TLS hostname mismatch, event hash mismatch, and live-mode local fallback.

- [ ] **Step 2: Implement minimal fail-closed fixes**

Use bounded path resolution, strict all-or-none TLS/token configuration, dedicated credential spaces, canonical validation before persistence, explicit deadlines, safe error taxonomies, redacted telemetry, and bounded concurrency. Do not add a second authority or loosen any existing boundary.

- [ ] **Step 3: Run security verification**

Run: `cargo test --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo audit`; `pnpm --dir apps/mcp-gateway test`; `python -m pytest deploy scripts -q`; `git diff --check`.

Expected: PASS, or a documented unavailable tool without hiding its result.

- [ ] **Step 4: Commit**

```powershell
git add apps crates deploy scripts docs/security .github
git commit -m "security: harden active gateway boundaries"
```

### Task 5: Measure and improve throughput

**Files:**
- Create: `docs/performance/gateway-throughput-baseline.md`
- Modify: `apps/mcp-gateway/src/live/grpc.ts`
- Modify: `apps/mcp-gateway/src/execution.ts`
- Modify: `apps/event-ingest/src/auth/`
- Modify: `apps/event-ingest/src/gateway/`
- Modify: `crates/apex-durability/src/outbox/`
- Test: `deploy/compose/loadtest/` and focused unit tests

- [ ] **Step 1: Capture a reproducible baseline**

Run the existing bounded load harness against local and live paths, recording command, commit, request count, p50/p95 latency, throughput, admission errors, event bytes, CPU, and memory.

- [ ] **Step 2: Add regression assertions**

Test one validated serialization pass where possible, bounded parallel gRPC calls, pool utilization, and bounded batch fanout without changing order or admission semantics.

- [ ] **Step 3: Implement measured optimizations**

Reuse immutable gRPC channel state, avoid per-request secret reads, avoid redundant serialization, keep blocking IO behind existing semaphores, and batch only within the existing outbox/fanout contracts. Preserve authorization-before-adapter and durable-event-before-success ordering.

- [ ] **Step 4: Re-run benchmark and full tests**

Run the identical load commands, compare p50/p95/throughput to the baseline, then run the workspace tests, gateway test/typecheck/build, and source line checker.

Expected: measured throughput improvement or a documented neutral result with no security or latency-tail regression.

- [ ] **Step 5: Commit**

```powershell
git add apps crates deploy/compose/loadtest docs/performance
git commit -m "perf: improve governed gateway throughput"
```

### Task 6: Final verification and merge

**Files:**
- Modify: `docs/roadmap.md`
- Modify: `docs/phase-0.5-progress.md`

- [ ] **Step 1: Run the complete local matrix**

Run: `cargo fmt --all -- --check`; `cargo test --workspace --all-targets`; `cargo clippy --workspace --all-targets -- -D warnings`; `pnpm --dir apps/mcp-gateway test`; `pnpm --dir apps/mcp-gateway typecheck`; `pnpm --dir apps/mcp-gateway build`; `python scripts/check_source_line_limits.py`; `git diff --check`.

- [ ] **Step 2: Push and inspect CI**

Push the branch, wait for required workflows to finish, and use `gh run view <run-id> --log-failed` for failures. Fix only active-roadmap regressions.

- [ ] **Step 3: Merge and push**

```powershell
git checkout master
git pull --ff-only origin master
git merge --no-ff codex/codebase-hardening -m "merge: harden active codebases"
git push origin master
```

- [ ] **Step 4: Record evidence and holds**

Update the roadmap with line-limit, security, and benchmark evidence plus commit and CI links. Explicitly leave unrelated dashboards/UI, new domains, identity providers, evaluations, cost forecasting, HA cache, broad workflow, autonomous trade, and second MCP governance/audit on hold.
