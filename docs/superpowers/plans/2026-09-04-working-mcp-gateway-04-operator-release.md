# Working MCP Gateway: Operator and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete operator workflow and prove it on a fresh self-hosted installation using real browser, MCP client, containers, governance and durable evidence.
**Architecture:** UI panels consume generated scoped APIs and observed state. Installation scripts configure the existing authorities and restricted runtime agent. One reusable live harness is the local and CI release gate.
**Tech Stack:** React/TanStack, Vitest/Testing Library, Playwright, MCP SDK, Docker Compose, PostgreSQL, existing CI/security tools.
**Spec:** [Delivery design](../specs/2026-09-04-working-mcp-gateway-design.md); prerequisites in the [execution index](2026-09-04-working-mcp-gateway.md).

## Global constraints

- The browser holds no access tokens, refresh tokens, upstream secrets, or runtime credentials.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Unsupported capabilities are rejected or disabled visibly, never shown as working controls.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.

All other design constraints remain mandatory. Retain the current Apex shell, design tokens, large-plus interaction and focused MCP navigation. Do not redesign unrelated product areas.

## Task 17: Complete creation, discovery, validation and client connection

**Files**

- Modify `apps/operator-ui/src/features/mcp-proxies/{NewProxyWizard.tsx,types.ts,api.ts}`.
- Create `apps/operator-ui/src/features/mcp-proxies/wizard/{IdentityStep.tsx,IngressStep.tsx,UpstreamsStep.tsx,ToolsStep.tsx,CliStep.tsx,GovernanceStep.tsx,ReviewStep.tsx,model.ts}`.
- Create `apps/operator-ui/src/features/mcp-proxies/{ConnectClientPanel.tsx,NewProxyWizard.test.tsx}`.
- Create `apps/operator-ui/e2e/proxy-create.spec.ts`, `playwright.config.ts`; update package scripts/dependency lockfile with Playwright and accessibility tooling.

**Interfaces**

Wizard editing state maps explicitly to generated draft fields, preserving separate ingress and every upstream's endpoint. Server capabilities populate available transport, credential, policy, CLI and image profiles. Create draft once, save with revision guard and UUIDv7, run server validation/discovery, publish the stored revision, then deploy that revision. `ConnectClientPanel` shows the actual allocated URL, supported auth/stdio instructions and public metadata only.

- [ ] Add a failing UI/browser test with two upstreams and distinct ingress; reload the draft and verify all values survive. Test schema drift, credential-reference denial, duplicate alias, missing policy, approval hold, conflict, failed deployment and unsupported capability. Keyboard-only navigation must reach the large plus and all controls.

```ts
import { expect, test } from "@playwright/test";
test("creates a persistent draft through the visible operator flow", async ({ page }) => {
  await page.goto("/mcp-proxies");
  await page.getByRole("button", { name: /new proxy/i }).click();
  await page.getByLabel("Display name", { exact: true }).fill("Acceptance proxy");
  await page.getByRole("button", { name: /save draft/i }).click();
  await page.reload();
  await expect(page.getByLabel("Display name", { exact: true })).toHaveValue("Acceptance proxy");
});
```

The Playwright setup created here signs in through task-3's real OIDC flow for live cases. Unit tests may mock transport, but the acceptance project must not intercept control-plane responses or inject preview stores.

- [ ] Run `pnpm --dir apps/operator-ui test` and `pnpm --dir apps/operator-ui exec playwright test e2e/proxy-create.spec.ts`; verify the current form/reload failure first.
- [ ] Split the wizard by responsibility, wire actual discovery/validation, multi-upstream/tool arrays, approved CLI catalog, auth bindings, canonical approval enums, limits and redacted review. Handle server-issued IDs, validation field paths and conflict refresh without overwriting another operator's draft. Surface connection-test results as probes, never as authorization. Keep a submitted request ID across network retry.
- [ ] Run typecheck/build/UI tests plus the real browser-to-deploy flow. Verify `Connect client` instructions work with the SDK and do not contain raw credentials, private host paths or Docker commands. A tool selection must persist and be reflected by real `tools/list`.
- [ ] Commit: `feat: finish live proxy creation discovery and client setup`.

## Task 18: Functional detail tabs, actions, revisions and approvals

**Files**

- Modify `apps/operator-ui/src/features/mcp-proxies/{ProxyDetailPage.tsx,ProxyTabs.tsx,ProxyCard.tsx,ProxyListPage.tsx}`, `src/app/router.tsx`.
- Create `apps/operator-ui/src/features/mcp-proxies/detail/{OverviewPanel.tsx,UpstreamsPanel.tsx,AuthenticationPanel.tsx,CliPanel.tsx,GovernancePanel.tsx,RuntimePanel.tsx,RevisionsPanel.tsx,ApprovalPanel.tsx}`.
- Create `apps/operator-ui/src/features/mcp-proxies/detail/actions.ts`, `detail.test.tsx`, `apps/operator-ui/e2e/proxy-lifecycle.spec.ts`.

**Interfaces**

Validated route search selects the actual panel. Each panel consumes generated revision/binding/operation/activity data. Actions carry expected revision, stable request ID and reason. UI shows requested versus observed state, last observation, safe error and pending operation. Approval decisions are scoped to the current operator and use the durable task-13 authority.

- [ ] Test that every tab renders distinct data, preserves URL/deep-link navigation and does not reset to overview. Test pause/resume/rotate/rollback/retire in pending, success and failure states; ensure a successful RPC acknowledgment alone never sets `Ready`.

```text
click Pause -> show Pausing and operation ID
server says admission disabled/draining -> still Pausing
server reports PAUSED with fresh observation -> show Paused
server unavailable -> show last-known state plus Stale; do not assert Paused
```

- [ ] Run focused unit tests and `pnpm --dir apps/operator-ui exec playwright test e2e/proxy-lifecycle.spec.ts`; verify the old ignored `?tab=` behavior fails.
- [ ] Implement the panels and real actions, asynchronous operation polling, credential metadata/rotation, revision list/diff/rollback, duplicate-as-new-draft using existing generated create/update operations, and approval review/decision. Never copy credential values or automatically grant policy while duplicating. Add destructive-action confirmation and safe retry/resume behavior; do not offer actions the server does not support.
- [ ] Run two-operator conflict and dual-approval browser cases with real scoped accounts. Inspect actual runtime effects for pause/retire and actual generation/digest for rotation/rollback. Verify tokens, CLI arguments and raw results do not appear in panel markup.
- [ ] Commit: `feat: complete live proxy detail lifecycle and approval workflows`.

## Task 19: Live activity and a microsecond trace waterfall

**Files**

- Create `apps/operator-ui/src/features/mcp-proxies/activity/{ActivityPanel.tsx,TracePanel.tsx,TraceWaterfall.tsx,format-time.ts,format-time.test.ts,activity.test.tsx}`.
- Modify `ProxyDetailPage.tsx`, `ProxyTabs.tsx`, `api.ts`, `src/app/router.tsx`, focused `src/proxy-styles.css` styles.
- Add a bounded scoped SSE endpoint in `apps/control-plane-api/src/browser/activity.rs`; modify browser route registration.
- Create `apps/operator-ui/e2e/proxy-trace.spec.ts`.

**Interfaces**

Activity uses task-15 event cursors and task-16 trace detail. SSE only announces scoped projection updates; generated queries return authoritative data. Reconnect uses a bounded cursor with backoff; show last update, projection lag and stale/offline/partial state. `formatDurationUs(us: string): string` uses `BigInt`; table/waterfall show exact values and separate durations from absolute timestamps.

- [ ] Write formatting tests and a live round-trip test with injected timing fixtures at the instrumented test-clock boundary, not mocked browser data. Test missing spans, unknown clocks, >2^53 integers, two overlapping calls, denied traces and cross-scope trace lookup.

```ts
import { expect, test } from "vitest";
import { formatDurationUs } from "./format-time";
test("does not round microseconds into milliseconds", () => {
  expect(formatDurationUs("7")).toBe("7 µs");
  expect(formatDurationUs("1007")).toBe("1,007 µs");
  expect(formatDurationUs("9007199254740993")).toBe("9,007,199,254,740,993 µs");
});
```

- [ ] Run the formatting tests and `pnpm --dir apps/operator-ui exec playwright test e2e/proxy-trace.spec.ts`; current integer-millisecond activity must not satisfy the new expectation.
- [ ] Implement a semantic list/table with a small SVG/CSS waterfall, keyboard-accessible span selection and details. Compute offsets with integer arithmetic relative to trace/process anchors; only convert bounded display coordinates to `number`. Show stage duration, policy/approval/event IDs, clock source/uncertainty, completion status and loss flags. Preserve exact microsecond text even when zoomed out. Never infer cross-machine wire latency from unsynchronized timestamps or sum overlapping child durations as root time.
- [ ] Exercise live success/denial/CLI/cancel traces, SSE disconnect/reconnect, slow projection and collector outage. Screen-reader labels and narrow/high-contrast layouts must remain usable. The source event's 1/7/999-us values must match the UI and downloadable redacted trace JSON exactly.
- [ ] Commit: `feat: display scoped live activity and microsecond MCP traces`.

## Task 20: Reproducible installation, preflight and onboarding

**Files**

- Create `deploy/compose/compose.mcp-working.yaml`, `deploy/compose/mcp-working/{README.md,.env.example}`.
- Create `scripts/mcp-gateway/{preflight.mjs,bootstrap.mjs,diagnostics.mjs}`; update deployment Dockerfiles and runtime-agent install documentation.
- Create `docs/operations/mcp-gateway-quickstart.md`, `mcp-gateway-recovery.md`.
- Update `apps/mcp-gateway/README.md`, `apps/operator-ui/README.md` and focused `deploy/compose/README.md` references.

**Interfaces**

Supported first deployment: single Linux host or Linux containers on Docker Desktop with the documented host runtime-agent boundary, persistent Postgres and a trusted HTTPS edge. The lab profile uses disposable Keycloak/CA/upstream fixtures; the production profile requires real provider endpoints, trust roots and reference files, never known lab passwords.

`node scripts/mcp-gateway/preflight.mjs --profile production --config <path>` is read-only and returns machine-readable missing prerequisites. `bootstrap.mjs --profile lab --project <unique-name>` starts only the lab's owned resources. Production installation follows explicit operator-reviewed config/identity steps and does not silently modify host trust stores, DNS or firewall rules.

- [ ] Test preflight on missing DB/feature build, Docker/runtime agent, hostname/TLS, image signature, issuer/audience, file permissions, required secrets, unavailable egress enforcement, port collision and insufficient disk. Test that production rejects every lab-only fallback.

```powershell
node scripts/mcp-gateway/preflight.mjs --profile lab
node scripts/mcp-gateway/bootstrap.mjs --profile lab --project apex-mcp-acceptance
```

The bootstrap prints an operator URL and redacted next steps, not passwords/tokens. The live test runner obtains its ephemeral credentials through private temporary files and never writes them into test report bodies.

- [ ] Run a fresh lab install with no existing project volumes or pre-launched gateway. The current standalone fixture Compose overlay is not a passing substitute.
- [ ] Implement the complete profile: PostgreSQL-enabled control plane, browser edge, static UI, runtime agent connection, edge routes, scoped secret/image catalogs, real governance/events, per-proxy egress, optional telemetry collector and existing downstream services. Configure resource-audience enrollment, safe certificate/credential refresh and read-only secret staging. Start gateways dynamically through the API; do not predeclare an already-ready portfolio proxy as the acceptance path.
- [ ] Follow the quickstart on an empty lab project, create two proxies, run calls and restart. Test backup/restore and migration failure recovery using dedicated disposable DBs. Document single-host limits, supported clients, required host capabilities, clocks/µs accuracy limits, approval/secret setup and offline diagnostics. Never prescribe blind retries for uncertain writes.
- [ ] Commit: `feat: ship reproducible managed MCP installation and recovery workflow`.

## Task 21: Real browser-to-MCP acceptance and fault matrix

**Files**

- Complete `scripts/verify-working-mcp-gateway.mjs` and create `scripts/mcp-gateway/acceptance/{cases.mjs,environment.mjs,mcp-client.mjs,evidence.mjs,lifecycle.mjs,tracing.mjs}`.
- Extend `apps/operator-ui/e2e/{proxy-create.spec.ts,proxy-lifecycle.spec.ts,proxy-trace.spec.ts}`.
- Modify `apps/control-plane-api/tests/live_mcp_proxy_control.rs`, `live_mcp_proxy_runtime.rs` where they currently accept incomplete readiness or inspect only hardening flags.
- Create `docs/operations/mcp-gateway-acceptance.md`.

**Interfaces**

The harness implements `--list`, `--profile lab|ci`, `--suite smoke|isolation|failure|tracing|all`, `--artifacts <directory>`, and `--keep-on-failure` (explicit opt-in; never default). It runs real Playwright + SDK clients with production-built modules. Only the issuer, target business system and clock fault injector are test fixtures; Rust governance, runtime agent, gateway entry point, DB/admission/query and UI are production code.

- [ ] Register the complete matrix below as executable cases. A required case not implemented or skipped makes `--suite all` fail.

| Case | Required observation |
| --- | --- |
| Fresh UI create/deploy | No preseeded proxy; a new actual container/route appears |
| Allowed/denied call | Real policy decision, exact upstream counter, durable matching evidence |
| Two proxies | Different credentials/catalogs/state; cross-proxy tokens/sessions/egress denied |
| CLI/stdio | Real subprocess/SDK framing, approved profile, no shell/network bypass |
| Approval/limits | Pending/dual approval/revalidation, bounded queue and exact budget behavior |
| Pause/retire | New and existing-session admissions blocked; runtime drained/stopped/removed |
| Rotate/rollback | New generation/credentials, old sessions invalid, no double routing |
| Controller/runtime crash | Persisted desired state resumes without duplicate execution/provision |
| Governance/identity outage | Fail closed with actionable redacted state |
| Evidence outage | No successful unrecorded result; uncertain execution reported honestly |
| NATS/ClickHouse/archive outage | Durable ACK survives; projection is visibly delayed and later recovers |
| µs precision | 1/7/999-us values and six-digit timestamp fraction survive full path |
| Wall-clock jump/skew | Local durations nonnegative; cross-host uncertainty visible |
| Trace exporter loss | Evidence intact, partial trace/loss metrics visible |
| Backup/restore | Proxy/revision/approval/history restored; fresh readiness before routing |

- [ ] Run `node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all`; keep red results for missing cases during development. Do not catch and reclassify `NotServing`, missing Docker or timeout as success.
- [ ] Implement bounded waits on real health/operations/events rather than arbitrary sleeps. During first integration run `--suite smoke` as soon as tasks 1-10 and narrow UI/evidence dependencies are ready. Finish broader cases after CLI/approval/tracing arrive. Capture redacted logs, runtime metadata, Playwright traces and expected/actual event IDs on failure. Teardown only resources carrying the unique acceptance project/run ownership labels.
- [ ] Run the exact full command twice from fresh projects and once after recovery injection. Prove no orphan containers/processes/test volumes remain. Evidence artifacts must identify commit and actual image digests, with zero required skips and zero unexpected upstream writes.
- [ ] Commit: `test: prove the complete managed MCP operator workflow`.

## Task 22: Security, throughput, trace overhead and final CI release gate

**Files**

- Modify `.github/workflows/ci.yml`, `.github/workflows/live-mtls-e2e.yml`, existing cache overlay and `scripts/check_source_line_limits.py` only if new generated directories require narrowly scoped recognition.
- Extend `deploy/compose/loadtest/mcp_proxy_loadtest.py`; create `scripts/mcp-gateway/benchmark.mjs` and its case data.
- Update `docs/security/mcp-proxy-threat-model.md`, `docs/operations/mcp-gateway-release-evidence.md`, `docs/roadmap.md`.
- Create `docs/performance/working-mcp-gateway-baseline.md` and `docs/operations/mcp-gateway-tracing.md`.

**Interfaces**

`benchmark.mjs --profile live --duration-seconds 300 --clients 32` invokes actual managed endpoints, real governance and evidence admission. Record offered/achieved throughput, p50/p95/p99, stage µs, CPU/RSS, queue depth, timeout/rejection counts, event lag and trace losses. Synthetic executor microbenchmarks are labeled separately.

- [ ] Add executable budgets before optimizing: on a recorded 8-vCPU/16-GiB reference host, two proxies and 32 total clients sustain 100 accepted calls/second combined for five minutes with a bounded 1-KiB fixture result and no unexpected failures. Explicit benchmark policy overrides the default per-proxy rate ceiling. Proposed p95 gateway-plus-Apex overhead is at most 150 ms excluding measured upstream execution; no cross-host timestamp subtraction. Per-proxy limits, queue bounds and memory must remain enforced. These are release targets to measure, not existing performance claims.
- [ ] Add tracing A/B tests at the same load: mandatory microsecond stage evidence is always on; compare optional full spans enabled/disabled. Proposed budget is at most 5% throughput regression and 10% p95 overhead from optional full tracing, with no unbounded queue/memory growth. Document host clock resolution and trace drop counters. If targets fail, report the measured failure and fix it; do not quietly reduce evidence or redefine the test.
- [ ] Run security adversarial cases: JWT/session scope, CSRF, SSRF/rebinding, runtime-agent authority, stale fencing, CLI process/argument escapes, output/schema handling, secret canaries and evidence conflicts. Inspect actual runtime settings and image SBOM/signature policy. Run repository advisory/license checks against final lockfiles and ensure no unrelated fallback is enabled.
- [ ] Integrate the same acceptance command into CI with dependency/build caches, one image build per tested revision, bounded health waits and parallel independent unit jobs. The required aggregate gate depends on all applicable jobs; path filters cannot skip shared-contract/auth/runtime changes. Never run privileged live tests with untrusted fork code and production secrets; use ephemeral fixtures and an appropriately isolated trusted runner. Reuse artifacts rather than rebuilding identical images in sequential jobs.
- [ ] Run final commands:

```powershell
git diff --check
python scripts/check_source_line_limits.py
cargo fmt --all -- --check
cargo test --workspace --locked --all-features
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
pnpm --dir contracts verify
pnpm --dir apps/mcp-gateway test
pnpm --dir apps/mcp-gateway typecheck
pnpm --dir apps/mcp-gateway build
pnpm --dir apps/operator-ui test
pnpm --dir apps/operator-ui typecheck
pnpm --dir apps/operator-ui build
node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all
node scripts/mcp-gateway/benchmark.mjs --profile live --duration-seconds 300 --clients 32
```

Also run the exact advisory/license commands already configured in CI; missing credentials or host prerequisites are reported, not treated as verification. Check Rust default-feature compilation as well as all-features so development mode remains intentional.

- [ ] Review runbooks for first install, secret rotation, stalled approval, failed deploy, unavailable evidence, clock skew, partial traces, restore and retirement. Record actual limitations and accepted image digests. Mark only G0-G3 with fresh evidence as complete in the roadmap. Commit: `release: verify working MCP gateway security performance and recovery`. Merge/push only under execution authorization; confirm required checks for the exact final SHA before calling the release done.

## Final definition of done

A new operator follows the quickstart, signs in, creates two independent proxies through the large plus, connects real MCP clients, executes approved generic HTTP/stdio/CLI tools, observes actual policy/evidence and microsecond traces, and controls/restarts/restores those proxies without editing source code. Failure paths are explicit and safe. Every enabled control corresponds to a tested backend capability. All G0-G3 evidence is attached to the release, and unrelated roadmap work remains on hold.
