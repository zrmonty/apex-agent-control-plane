# Managed MCP and Event Throughput Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Improve the seven highest-value measured performance paths without changing the managed proxy's fail-closed, governance, evidence, or network-safety contracts.

**Architecture:** First replace the invalid HTTP probe with a real MCP JSON-RPC load harness and stage timings. Then optimize the TypeScript gateway with bounded upstream discovery, security-preserving DNS reuse, immutable lookup indexes, fewer serialization/allocation passes, and normalized headers. Finally increase durable fanout concurrency only through bounded, idempotency-tested sink scheduling; the existing worker and retry limits remain the safety controls.

**Tech Stack:** TypeScript, Node.js MCP SDK, Node `dns/promises`, Rust, Tokio, PostgreSQL outbox, Python load-test harness, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-09-04-production-mcp-proxy-integrations.md`

## Global Constraints

- Preserve fail-closed startup and request behavior.
- Preserve awaited evidence admission before successful MCP responses.
- Preserve SSRF/rebinding checks, redirect rejection, request/response size limits, and credential isolation.
- Preserve durable outbox retries, idempotency, quarantine, and partial-sink failure semantics.
- Keep all production source files below the repository's 600-line readability limit.
- Every production change starts with a failing regression or performance-contract test.

---

### Task 1: Replace the managed MCP probe with a real protocol load harness

**Files:**
- Modify: `deploy/compose/loadtest/mcp_proxy_loadtest.py`
- Modify: `deploy/compose/loadtest/README.md`
- Test: `deploy/compose/loadtest/test_mcp_proxy_loadtest.py`
- Modify: `apps/mcp-gateway/src/managed/http-server.ts` only if a dedicated health route is required by the harness

**Interfaces:**
- Produces a command that sends MCP `initialize`, `tools/list`, and `tools/call` requests over one session and reports cold-start, warm latency, throughput, errors, and stage timings.
- Consumes an already configured proxy URL, bearer token, tool alias, and JSON input; it never creates credentials or prints bodies.

- [ ] **Step 1: Write the failing harness tests** for JSON-RPC request construction, session reuse, percentile reporting, and failure accounting.
- [ ] **Step 2: Run `python -m pytest deploy/compose/loadtest/test_mcp_proxy_loadtest.py -q` and verify the new protocol assertions fail because the current probe only performs GET requests.
- [ ] **Step 3: Implement the protocol client with bounded concurrency, one initialization per worker/session, explicit cold and warm samples, and JSON output containing `initialize_ms`, `list_tools_ms`, `call_ms`, `p50`, `p95`, `p99`, successes, failures, and throughput.
- [ ] **Step 4: Run the focused tests, then run the harness against the live Compose gateway when available. Record that result in `docs/performance/gateway-throughput-baseline.md`.

### Task 2: Bound upstream discovery concurrency

**Files:**
- Modify: `apps/mcp-gateway/src/live/managed-runtime.ts`
- Test: `apps/mcp-gateway/src/live/managed-runtime.test.ts`

**Interfaces:**
- Adds a bounded discovery helper with a fixed maximum concurrency and all-settled cleanup semantics.
- `buildManagedRuntime` continues to return only after every upstream is discovered or closes every session and fails safely.

- [ ] **Step 1: Add a test with delayed transports proving multiple upstream discoveries overlap while the configured concurrency cap is respected.
- [ ] **Step 2: Run `pnpm --dir apps/mcp-gateway test` and verify the overlap/cap test fails against the serial loop.
- [ ] **Step 3: Implement the bounded scheduler, preserving deterministic error selection and closing all sessions when any discovery fails.
- [ ] **Step 4: Run the focused live-runtime tests and the complete gateway test/typecheck suite.

### Task 3: Reuse safe DNS resolution without weakening SSRF defenses

**Files:**
- Modify: `apps/mcp-gateway/src/managed/mcp-http-transport.ts`
- Test: `apps/mcp-gateway/src/managed/mcp-http-transport.test.ts`

**Interfaces:**
- Adds a bounded per-host resolver cache with an explicit short TTL and in-flight promise coalescing.
- Every request still validates the URL, hostname, resolved addresses, redirect policy, and response bounds; cache expiry and resolver failures fail closed.

- [ ] **Step 1: Add tests proving repeated requests reuse a fresh resolution, concurrent requests coalesce, expired entries resolve again, and private-address changes are rejected.
- [ ] **Step 2: Run the focused transport tests and verify the cache assertions fail because every request currently resolves DNS.
- [ ] **Step 3: Implement the bounded resolver cache and inject the clock/TTL for deterministic tests.
- [ ] **Step 4: Run the complete transport and gateway suite, then capture resolver-call counts and warm p50/p95/p99 with the protocol harness.

### Task 4: Compile immutable tool/upstream lookup indexes

**Files:**
- Modify: `apps/mcp-gateway/src/managed/config.ts`
- Modify: `apps/mcp-gateway/src/managed/upstream.ts`
- Modify: `apps/mcp-gateway/src/managed/managed-executor.ts`
- Modify: `apps/mcp-gateway/src/managed/http-server.ts`
- Test: `apps/mcp-gateway/src/managed/upstream.test.ts`
- Test: `apps/mcp-gateway/src/managed/managed-executor.test.ts`

**Interfaces:**
- Adds a compiled runtime index containing alias-to-tool, upstream-to-tools, and cached MCP tool definitions while retaining configured order and read-only behavior.
- Execution and `tools/list` use those indexes rather than repeated linear scans and reconstruction.

- [ ] **Step 1: Add tests proving aliases resolve identically, unknown aliases fail identically, upstream exposure checks remain scoped, and `tools/list` returns the same schema/order.
- [ ] **Step 2: Run focused tests and verify the new index assertions fail against the current array scans/reconstruction.
- [ ] **Step 3: Implement the index at runtime construction and update call/list paths to consume it.
- [ ] **Step 4: Run all gateway tests and compare CPU/allocations under the protocol harness.

### Task 5: Reduce duplicate filtering and JSON serialization passes

**Files:**
- Modify: `apps/mcp-gateway/src/filtering.ts`
- Modify: `apps/mcp-gateway/src/managed/managed-executor.ts`
- Modify: `apps/mcp-gateway/src/live/events.ts` only if profiling shows event encoding remains dominant
- Test: `apps/mcp-gateway/src/filtering.test.ts`
- Test: `apps/mcp-gateway/src/managed/managed-executor.test.ts`

**Interfaces:**
- Keeps exact `sourceBytes`, `filteredBytes`, `outputBytes`, removed-field, and privacy behavior.
- Uses a single bounded serialization/size result where possible and avoids duplicate map/freeze/serialization work without changing wire payloads.

- [ ] **Step 1: Add tests covering byte counts, field removal, immutable output, and oversized/invalid output rejection.
- [ ] **Step 2: Run focused tests and verify the new instrumentation/byte-count assertion fails before the optimization.
- [ ] **Step 3: Implement the smallest allocation reduction supported by those contracts; do not remove evidence hashing or event serialization.
- [ ] **Step 4: Run the filtering/executor suite and a large realistic payload benchmark; retain the change only if output and byte metrics are identical.

### Task 6: Normalize HTTP headers once per request

**Files:**
- Modify: `apps/mcp-gateway/src/managed/http-server.ts`
- Modify: `apps/mcp-gateway/src/managed/auth.ts`
- Modify: `apps/mcp-gateway/src/managed/http.ts`
- Test: `apps/mcp-gateway/src/managed/http-server.test.ts`
- Test: `apps/mcp-gateway/src/managed/http.test.ts`

**Interfaces:**
- Converts incoming headers to one lower-case normalized representation while preserving duplicate-header rejection and array-valued headers.
- Request URL, content type, authorization, origin, host, and session lookups become direct reads.

- [ ] **Step 1: Add tests for mixed-case names, duplicate values, absent values, authorization, and content-type behavior.
- [ ] **Step 2: Run focused HTTP tests and verify the normalization assertions fail against repeated `Object.entries` scans.
- [ ] **Step 3: Implement one normalization pass and thread the representation through validation/authentication.
- [ ] **Step 4: Run all gateway tests and typecheck; compare request allocation and latency under the protocol harness.

### Task 7: Increase durable fanout throughput with bounded sink scheduling

**Files:**
- Modify: `crates/apex-durability/src/sinks/fanout.rs`
- Modify: `crates/apex-durability/src/outbox/publisher.rs`
- Modify: `apps/event-ingest/src/startup/service.rs` only for validated worker/concurrency configuration
- Test: `crates/apex-durability/src/sinks/fanout.rs` tests or adjacent sink tests
- Test: `crates/apex-durability/src/outbox/publisher.rs` tests
- Modify: `docs/operations/event-ingest-durability.md`

**Interfaces:**
- Retains one durable outbox record as the retry/idempotency unit and never reports success until required sink outcomes satisfy the existing contract.
- Evaluates worker-count and sink-concurrency changes behind bounded configuration and tests partial failures, retries, and duplicate delivery.

- [ ] **Step 1: Add tests measuring the current serial sink behavior and proving the required outcome under one sink failure, retry, and duplicate event.
- [ ] **Step 2: Run the focused Rust tests and verify the concurrency/overlap assertion fails against the serial publisher.
- [ ] **Step 3: Implement the smallest safe throughput change: validate worker/connection limits first, then parallelize only independent sink calls with explicit failure aggregation if the existing contract permits it.
- [ ] **Step 4: Run `cargo test -p apex-durability`, the event-ingest tests, and the durable Compose load test; document measured throughput and backlog drain time.

## Verification Gate

Run the full gateway tests/typecheck/build, full affected Rust tests with locked dependencies, `cargo clippy --all-targets --all-features -- -D warnings` for affected crates, the Python harness tests, `git diff --check`, and the source-line-limit check. Report measured before/after numbers and leave any change without representative improvement out of the final commit.
