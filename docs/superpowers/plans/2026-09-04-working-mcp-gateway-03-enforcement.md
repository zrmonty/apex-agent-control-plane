# Working MCP Gateway: Enforcement and Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute approved tools and CLI profiles through real authentication, generic Apex governance, durable evidence and microsecond-level tracing.
**Architecture:** Generalize the existing data plane and Rust governance together. Keep approvals/admission in Apex, credentials in their scoped provider, evidence in the existing durable pipeline and trace measurement at the actual execution boundaries.
**Tech Stack:** MCP SDK/Node.js 24, Rust/apex-policy, PostgreSQL, OIDC/mTLS, JSON Schema, OpenTelemetry, ClickHouse.
**Spec:** [Delivery design](../specs/2026-09-04-working-mcp-gateway-design.md); prerequisites in the [execution index](2026-09-04-working-mcp-gateway.md).

## Global constraints

- Apex remains the only policy and durable evidence authority.
- Inbound credentials are never passed through to upstreams.
- CLI execution uses approved executables and typed argv with shell interpretation disabled.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.
- Unsupported capabilities are rejected or disabled visibly, never shown as working controls.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.

The full design's remaining global constraints apply. Generalization uses disposable tools to prove the platform; it does not authorize new production business integrations or trading.

## Task 11: Generic discovery, tool schemas, routing and output policies

**Files**

- Modify `apps/mcp-gateway/src/managed/{upstream.ts,http-server.ts,managed-executor.ts}`, `src/live/managed-runtime.ts`, `src/contracts.ts`.
- Create `apps/mcp-gateway/src/managed/{tool-catalog.ts,tool-schema.ts,output-policy.ts,resource-binding.ts}` and corresponding `.test.ts` files.
- Modify `apps/control-plane-api/src/proxy/validation.rs` and task-5 compiler; implement task-1 discovery RPCs through runtime probes.
- Create `deploy/compose/mcp-working/upstream/{server.mjs,tools.mjs}` as a real MCP SDK fixture, separate from production adapters; add `contracts/fixtures/mcp-proxy/generic-runtime.json` with complete generated runtime bindings for both fixture tools below.

**Interfaces**

`ApprovedTool` is a generated runtime binding with alias, upstream/tool ID, catalog/schema hashes, input/output schema, classification, timeout and output profile. `validateToolInput(tool, input) -> unknown` returns validated input; `filterToolOutput(tool, result, decision) -> FilteredToolResult` enforces the declared schema and policy. `resolveResource(binding, validatedInput) -> string` uses only configured literals and bounded JSON pointers; no executable expression language.

`ProbeUpstream` runs a bounded initialization/listing in an isolated non-routable environment with the revision's network/credential grants. It returns normalized catalog metadata and errors, never executes discovered tools or expands exposure.

- [ ] Add tests using two unrelated schemas, alias collisions, pagination, catalog drift, remote `$ref`, malformed schema, response `isError`, mixed content blocks, truncation, output validation and denied paths. Assert no portfolio-specific input requirement for unrelated tools.

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { validateToolInput } from "./tool-schema.js";
test("validates an unrelated tool without portfolio fields", () => {
  const revision = JSON.parse(readFileSync(new URL(
    "../../../../contracts/fixtures/mcp-proxy/generic-runtime.json", import.meta.url,
  ), "utf8"));
  const echo = revision.exposedTools.find((tool: { alias: string }) => tool.alias === "fixture.echo");
  assert.ok(echo);
  assert.deepEqual(validateToolInput(echo, { value: "hello" }), { value: "hello" });
  assert.throws(() => validateToolInput(echo, { portfolioId: "alpha" }));
});
```

Fixture tools are `fixture.echo` with strict `{value:string}` and `fixture.sum` with strict `{left:number,right:number}` schemas. Also call them through a real MCP SDK client and assert exact filtered outputs and invalid-input rejection. The schema-unit test alone does not close this task.

- [ ] Run the new focused `.test.ts` files with the existing `tsx --test` runner, then `pnpm --dir apps/mcp-gateway test`; confirm the old portfolio validation fails the unrelated calls.
- [ ] Implement catalog/schema/output modules and replace portfolio routing branches in managed runtime. Use a maintained, pinned JSON Schema validator compatible with the SDK; prohibit remote schema loading and bound schema depth/size/complexity. Keep the portfolio-specific filter as one registered output profile, not the global path. Text/binary content requires explicit handling; never return unexamined raw content as a generic fallback.
- [ ] Run real SDK initialization, `tools/list`, `tools/call`, cancellation and schema-drift tests through the packaged runtime. Unknown tool names, unselected discoveries and unsupported capabilities remain unavailable. Discovery failure returns a useful redacted error in the control API.
- [ ] Commit: `feat: execute approved generic MCP tool schemas and output policies`.

## Task 12: Usable client enrollment, token verification and outbound credentials

**Files**

- Modify `apps/mcp-gateway/src/managed/{auth.ts,http.ts,http-server.ts}`, `src/live/{inbound-auth.ts,secrets.ts,managed-runtime.ts}`.
- Create `apps/mcp-gateway/src/live/{jwks-cache.ts,outbound-oauth.ts,outbound-mtls.ts}`, focused auth tests, and `src/managed/session-identity.ts`.
- Extend runtime-agent credential staging and task-1 binding metadata API.
- Create `deploy/compose/mcp-working/keycloak/README.md` and scoped MCP client/resource enrollment fixtures; modify the lab realm only under the test profile.

**Interfaces**

`VerifiedCaller` includes subject/agent/scope/resource audience/proxy, token expiry and an opaque credential fingerprint. Session ownership binds caller + proxy + generation. `resolveOutbound(bindingId, upstreamId, generation)` returns a transport-local credential handle; its value is never part of a revision or API response. Provider capabilities identify bearer/API-key, OAuth client-credentials and mTLS support; unsupported delegated exchange is visibly disabled.

- [ ] Test pre-registered client login/resource audience, missing/expired/wrong-proxy token, unknown/rotated `kid`, JWKS refresh failure/maximum age, revoked generation, subject A reusing subject B's MCP session, and forbidden origin. Test valid CLI/non-browser requests without an Origin header separately from an explicitly invalid Origin.

```text
Token A for resource https://edge.test/mcp/proxy-a -> proxy-a allowed if policy permits
Same token -> proxy-b: 401/403, no upstream call
Token B + session created by A -> refused, even inside the same workspace
Inbound bearer canary -> absent from outbound Authorization and all logs
Outbound token canary -> present only at the declared fixture upstream
```

- [ ] Run the real HTTP/SDK auth tests and live Keycloak enrollment case; expect the current static/limited verifier and configuration to expose missing rotation/enrollment behavior.
- [ ] Implement cached issuer-pinned JWKS refresh with bounded unknown-key refresh, exact URL audience validation, metadata/challenge, claims-derived caller context and session ownership on every request. Remove startup-environment caller substitution in tool governance/evidence. Add provider-specific outbound refresh, file confinement and mTLS configuration; do not mix issuer trust roots with arbitrary upstream roots or forward inbound headers.
- [ ] Exercise rotation while requests are active, revoked/expired tokens, token refresh timeout, wrong TLS identity and no-secret scans across DOM, network responses, logs, events and diagnostics. Connect one real external MCP client using the documented pre-registered flow; record its version and limitations without claiming all clients support identical auth UX.
- [ ] Commit: `feat: wire resource-bound MCP authentication and scoped outbound credentials`.

## Task 13: Generic Rust policy, durable approvals and admission leases

**Files**

- Modify `apps/control-plane-api/src/governance.rs`, `src/startup/service/resolvers.rs`, `proxy/service/operations/lifecycle.rs`, `crates/apex-policy/src/{types.rs,traits.rs,execution_types.rs}`.
- Create `apps/control-plane-api/src/governance/{policy_store.rs,approval.rs,admission.rs}` and `tests/proxy_governance_live.rs`.
- Create `deploy/postgres/mcp_proxy_governance.sql`; extend task-1 governance/approval contracts and task-3 scoped bridge.
- Modify gateway `src/live/{governance.ts,managed-runtime.ts}`, `src/managed/managed-executor.ts`; create `src/live/{approvals.ts,admission.ts}` and tests.

**Interfaces**

`Authorize` carries authenticated caller, proxy/revision/generation, upstream/tool/action, resource, classification, policy binding and trace/call IDs. The Rust authority verifies runtime identity against these bindings and resolves a published policy; caller-provided `readOnlyHint` never grants permission.

Approval methods: `RequestProxyApproval`, `GetProxyApproval`, `DecideProxyApproval`, `ConsumeProxyApproval`. An approval is bound to a keyed canonical argument digest, scope/caller/proxy/revision/policy/action, expires after a configured duration, and requires distinct authorized approvers for dual approval. Do not reuse the process-local force-stop approval map as production proxy state.

Admission methods: `ReserveProxyCall`, `FinishProxyCall`; lease IDs bind call and generation, with rate/concurrency/budget units, TTL, release and deduplication. Store authoritative policy/budget in Postgres; existing accelerators may help but cannot grant unrecorded authority.

- [ ] Add tests for unrelated tool authorization, policy change while waiting approval, same-operator double approval, expiry/replay/wrong-input/wrong-proxy approval, concurrent budget overspend, queue saturation, cancelled lease release and non-idempotent uncertain execution. Assert `admit: async () => true` is absent from production composition.

```text
limit concurrency=1
reserve(call-a) -> lease-a
reserve(call-b) -> queued or explicit limited response, no execution
finish(lease-a) -> one release
finish(lease-a) again -> no-op, never increments available capacity twice
```

- [ ] Run `cargo test -p apex-control-plane-api --features postgres --test proxy_governance_live` and gateway approval/admission tests. Record that the current Rust portfolio-only policy cannot authorize the unrelated fixture.
- [ ] Replace hardcoded portfolio constants with a bounded immutable policy-binding store. Keep default deny, exact scope/action roles and metadata-only decisions. Wire durable proxy approval authority at startup and both UI/call approval paths. Reauthorize after approval. Enforce configured queue/deadline/rate/budget/concurrency, including abandoned leases. For writes, record admitted intent before execution and outcome afterward; never automatically retry an ambiguous write or retain raw arguments in approval storage.
- [ ] Run real allow/deny/approval tests on both proxies, including a disposable write fixture whose invocation counter proves at-most-one automatic attempt. Show explicit `outcome_unknown` when a response is lost after execution. Production business integrations remain disabled unless separately published/authorized.
- [ ] Commit: `feat: enforce generic proxy policies approvals and admission limits`.

## Task 14: Connect approved CLI and controlled stdio paths

**Files**

- Modify `apps/mcp-gateway/src/managed/{cli.ts,upstream.ts,managed-executor.ts}`, `src/index.ts`, `package.json`.
- Create `apps/mcp-gateway/src/managed/{cli-adapter.ts,stdio-upstream.ts}`, their `.test.ts` files, and `src/launcher/{index.ts,credentials.ts,bridge.ts}`.
- Modify task-5 compiler, runtime-agent image/profile catalog and task-20 installation artifacts.
- Create `deploy/compose/mcp-working/cli-fixture/` with a fixed JSON-output executable and known digest.

**Interfaces**

`CliAdapter.call(approvedTool, validatedInput, callContext)` resolves only an approved `CliProfile`, executes fixed executable/argv, parses bounded output and returns through the same filtering/evidence path. The immutable executable/profile is selected by reference in the UI; no raw shell or download-on-execute option exists.

`StdioUpstream` uses the MCP SDK subprocess transport with the same executable/credential/filesystem/egress controls. `apex-mcp-connect --proxy-url <allocated-url> --credential-ref <local-reference>` is a local stdio-to-HTTP bridge using SDK transports and OS-confined credentials, not a second local policy mode. It creates a distinct remote MCP session for its client.

- [ ] Add tests for arbitrary executable/profile, dangerous flags, shell metacharacters where not admitted by the argument schema, path traversal, environment leakage, digest mismatch, process descendants, oversized stdout/stderr, allowed exit codes and network bypass. Test stdio stdout purity and session cleanup.

```text
approved executable: fixture-json; fixed argv: ["--format", "json"]
typed input: {"record":"alpha"} -> bounded structured output -> filter -> evidence
caller-supplied executable/argv/workingDirectory -> schema rejection
timeout with child and grandchild -> all gone at bounded teardown
```

- [ ] Run CLI/stdio tests with actual subprocesses and the task-8 network isolation suite. Require G1 before enabling CLI in the production capability response.
- [ ] Route CLI and stdio through generic executor hooks; add process-group termination, bounded stream readers, sanitized env and immutable executable verification. Package approved profile binaries at build time, never fetch packages during a tool call. Implement the local launcher with separate credentials and stderr-only diagnostics. Keep unsupported transport combinations rejected at publish time.
- [ ] Prove CLI and HTTP tools share policy/approval/evidence/trace behavior. Verify pause/retire kills or drains subprocesses and launcher sessions cannot survive revoked generation. Document precisely which launcher OSes are supported; Linux OCI remains the execution environment on Docker Desktop.
- [ ] Commit: `feat: connect governed CLI profiles and controlled stdio transports`.

## Task 15: Correlated durable evidence and real activity queries

**Files**

- Modify `apps/mcp-gateway/src/{contracts.ts,telemetry.ts}`, `src/live/{events.ts,canonical.ts,managed-runtime.ts}`, `src/managed/managed-executor.ts`.
- Modify `crates/apex-policy/src/execution_types.rs`, `apps/control-plane-api/src/proxy/service/operations/inspection.rs`.
- Create `apps/control-plane-api/src/proxy/activity/{query.rs,projection.rs,cursor.rs}` and `tests/proxy_activity_evidence.rs`.
- Create `deploy/postgres/mcp_proxy_activity.sql`; update the existing downstream ClickHouse projection path and `deploy/clickhouse/schema.sql` with additive indexes/projections only as needed.

**Interfaces**

`ManagedCallEvidence` includes call/attempt/event IDs, proxy/revision/generation/upstream, verified subject/agent/scope, tool/action/classification, policy/revision/approval, decision/outcome, sizes, removed-field count, safe error and task-1 timings. Event payloads remain content-free. `ListProxyActivity` returns a scoped stable cursor, authoritative event/receipt IDs and `observedAt`/projection-lag; trace detail joins by actual admitted identifiers.

The activity table is a rebuildable projection of admitted Apex events, not a second audit authority. Lifecycle intents from task 2 and tool events from EventIngest converge into one typed query without pretending a lifecycle row is a tool execution.

- [ ] Add tests for success, denial, pending approval, timeout, upstream `isError`, filtering failure, evidence failure and duplicate replay. Two same-tool calls through different proxies must never appear in the wrong activity stream. Test out-of-order arrivals and paginated reconnect.

```text
proxy-a call-a -> receipt event-a -> ListProxyActivity(proxy-a) contains event-a
ListProxyActivity(proxy-b) does not contain event-a
retry admission(event-a, identical canonical payload) -> same receipt
retry admission(event-a, different payload) -> conflict, never overwrite
```

- [ ] Run `cargo test -p apex-control-plane-api --features postgres --test proxy_activity_evidence` and gateway event/canonical tests; verify the missing proxy/revision fields and seeded feed are not accepted as evidence.
- [ ] Extend metadata and queries, preserving the existing v1 canonical hash and admission pipeline. Generate event ID and measured timestamp once per event and retain them across retry; do not regenerate timestamp/hash on each attempt. Wait for required durable admission before successful tool output. Record authenticated denials; pre-auth failures use bounded anonymous/security metadata without trusting a supplied identity. If evidence is unavailable, return safe failure and expose loss/availability diagnostics, never claim an event was durably recorded.
- [ ] Prove real events through outbox/fanout/query, downstream outage with successful durable admission, replay recovery and sensitive-canary absence. Use this task's narrow portfolio case early to close G1; general tools/CLI cases are added as tasks 11-14 land.
- [ ] Commit: `feat: expose correlated durable proxy activity and evidence receipts`.

## Task 16: Microsecond measurement, propagation, persistence and query

**Files**

- Create `apps/mcp-gateway/src/telemetry/{clock.ts,spans.ts,context.ts,clock.test.ts,spans.test.ts}`; refactor existing `src/telemetry.ts` as a small facade.
- Modify `src/managed/{http-server.ts,managed-executor.ts,mcp-http-transport.ts,cli.ts}`, `src/live/{events.ts,uuid.ts,grpc.ts}`.
- Create `crates/apex-telemetry/{Cargo.toml,src/lib.rs,src/clock.rs,src/context.rs}` and tests; register it in the workspace and add only the consuming application dependencies.
- Instrument `apps/control-plane-api/src/governance.rs`, proxy worker and existing durable admission/replay boundaries; add `apps/control-plane-api/tests/proxy_trace_precision.rs`.
- Extend task-15 projection/query, task-1 trace contract, `deploy/clickhouse/schema.sql` and create `deploy/compose/mcp-working/otel-collector.yaml` plus `contracts/fixtures/mcp-proxy/trace-precision.json`.

**Interfaces**

`durationUs(startNs: bigint, endNs: bigint): bigint`; `ClockSnapshot { monotonicNs: bigint; unixUs: bigint; resolutionNs: bigint; uncertaintyUs?: bigint; source: string }`; `Clock.now(): ClockSnapshot`. Production elapsed clocks use `process.hrtime.bigint()` and Rust `Instant`; production wall anchors use the supported high-resolution platform/SDK time source and disclose measured precision. Test clocks are injected, never deployed as production defaults.

`withStage(name, callContext, operation)` records bounded OTel spans and task-1 stage timing metadata with explicit async context propagation. `GetProxyTrace(scope, proxyId, callId)` returns spans, clock metadata, completion/partial status and event receipts. Scope filters are applied before trace lookup; incoming trace IDs never grant access.

- [ ] Add deterministic clock and serialization tests before instrumentation. Implement gateway tests with its existing Node runner:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { durationUs } from "./clock.js";
test("preserves sub-millisecond elapsed durations", () => {
  assert.equal(durationUs(1_000_000n, 1_001_000n), 1n);
  assert.equal(durationUs(1_000_000n, 1_007_000n), 7n);
  assert.equal(durationUs(1_000_000n, 1_999_000n), 999n);
});
```

- [ ] Run the focused gateway test and `cargo test -p apex-control-plane-api --features postgres --test proxy_trace_precision`. The cross-layer test sends exact decimal-string timestamps/durations through canonical event admission, actual database projection, generated API and a browser assertion. It must detect millisecond truncation; appending three zeros is a failing implementation.
- [ ] Implement the shared clock contract and integer conversion, checking reversed monotonic samples and integer bounds:

```ts
export function durationUs(startNs: bigint, endNs: bigint): bigint {
  if (endNs < startNs) throw new RangeError("monotonic clock moved backwards");
  return (endNs - startNs) / 1_000n;
}
```

Use nanosecond duration metadata for spans under one microsecond. Preserve exact integers via Protobuf or decimal strings, including JSON `Struct`; never convert epoch nanoseconds to `number`. Remove `timestampFromUuidV7()` as the new live-event timestamp default: capture `Clock.now()` once and retain the measured timestamp across evidence retries. UUID time remains an identifier/legacy timestamp aid, not a high-resolution clock. Keep the existing ClickHouse microsecond timestamp type and add integer duration fields/projections. Preserve legacy `latency_ms` for old consumers as a derived field, while new code reads authoritative `duration_us`. Do not rewrite historical events or pretend old millisecond data has gained precision.

- [ ] Instrument ingress/auth/schema/queue/policy/approval/admission/upstream/CLI/filter/evidence/serialization/write and Rust policy/commit/replay/runtime stages. Propagate W3C `traceparent` with bounded allowlisted context; keep UUIDv7 call IDs separate from OTel trace/span IDs. Record independent spans for concurrent RPCs; no module-global current span. Emit complete timings only after a stage completes. Add the linked post-response completion event/span; a missing completion is marked partial, not fabricated in pre-response evidence.
- [ ] Run injected wall-clock regression, skewed-host, 1/7/999-us round-trip, above-2^53 integer, overlapping calls, async error/cancellation, trace exporter outage/queue overflow and log-canary tests. Verify all mandatory admitted-call stage summaries are retained, optional trace loss is observable, and the exporter never enters the governance/admission authority path.
- [ ] Commit: `feat: preserve microsecond MCP traces across execution evidence and queries`.

## Enforcement checkpoint

- [ ] Unrelated structured tools and approved CLI/stdio execute through the real Apex path.
- [ ] Auth, policies, approvals, limits, filtering and evidence failures deny safely.
- [ ] Both proxies have independent caller/session/credential/network/evidence state.
- [ ] Microsecond values survive admission/query exactly, with honest clock/completion metadata.
- [ ] Record backend G2 evidence; complete the actual operator and release gates next.
