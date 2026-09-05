# Working MCP Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a working self-hosted, multi-proxy MCP gateway with real operator workflows, safe runtime control, generic governed tools, durable evidence and microsecond tracing.

**Architecture:** Retain the Rust authority, TypeScript MCP runtime and React console. Add a narrow Rust browser session/API edge and a restricted host runtime agent, then connect immutable revisions, real policy/approval/admission, per-proxy isolation and the existing durable event path.

**Tech Stack:** Rust 2024/tonic/Protobuf/PostgreSQL; Node.js 24 and locked MCP SDK 1.x; React 19/Vite/TanStack; Docker/OCI; OIDC/Keycloak/mTLS; OpenTelemetry and existing NATS/ClickHouse/archive.

**Spec:** [Working gateway delivery design](../specs/2026-09-04-working-mcp-gateway-design.md), supplementing the accepted [platform design](../specs/2026-09-04-mcp-proxy-platform-design.md).

## Global constraints

- Apex remains the only policy and durable evidence authority.
- The browser holds no access tokens, refresh tokens, upstream secrets, or runtime credentials.
- Published revisions are immutable; mutations use lowercase UUIDv7 request IDs and optimistic concurrency.
- One logical proxy has at most one routable revision; a replacement candidate may coexist only during bounded validation and drain.
- Inbound credentials are never passed through to upstreams.
- CLI execution uses approved executables and typed argv with shell interpretation disabled.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.
- Unsupported capabilities are rejected or disabled visibly, never shown as working controls.

## Status and authorization

Execution was authorized by the subsequent request to execute this plan.
Tasks 1-5 are implemented, verified and independently reviewed: publication
restrictions are in `33a053a`, the browser/UI and compiler foundation in
`cc30a1c`, and the complete generated runtime chain in `2ec1297`.
Fresh evidence includes 305 UI tests, three consecutive actual browser journeys,
all 79 startup tests and 435 gateway tests with one existing Windows
symlink skip. The startup subprocess finding is closed. Managed composition remains
deliberately unavailable until real network/admission enforcement is connected.
Task 6's rebuilt image passes the independently reviewed packaging harness.
Explicit startup profiles and truthful bootstrap configuration are committed
in `b973488`; additive launch/readiness contracts are committed in `a6fc19b`.
Pure launch metadata validation is committed in `0ba80dc`; Rust health-wire
precision checks are in `79de522`. The corrected image startup suite passes all
eight cases and rejects the older image's implicit-standalone behavior (`3679446`).
The bounded readiness monitor is committed in `6dafe00` after shutdown/nested
startup regression fixes, independent re-review, and fresh full gateway checks.
The shared report validator is committed in `09c04fa`, and bounded authenticated
loopback health transport in `6c4cc95`, after independent review and fresh
full-suite/typecheck/build checks. Secure staged material and real probe-owner
composition remain open; these checks do not establish managed serving or
end-to-end tracing.
Task 7's pure runtime-agent identity/configuration/inspection boundary is committed
in `b5d0391` (43 tests); authenticated authority and provisioning remain open.
Shared producer/agent manifest hashing and exact certificate-role/scope policy
are committed in `d652276` after independent review and real local mTLS tests.
Their CI coverage reuses the existing Rust job and fixtures (`68d8d77`).
The current PostgreSQL operation/lease/publication lookup is committed in
`aff8ae3` after real database tests and independent review. The authenticated
callback, policy loading/enrollment and actual runtime effects remain open;
neither a peer check nor a point-in-time store snapshot is an execution permit.
The Task 16 integer clock primitives are implemented, not end-to-end tracing.
Full readiness, remaining tasks and G0-G3 aggregate gates are incomplete. See
the [release evidence ledger](../../operations/mcp-gateway-release-evidence.md)
for tested checkpoints and limitations. Execution authorization does not supply
production credentials or enable real mutating business tools.

The assessment baseline is `1a6df0908de0a604415fd5c1631f697656d679ee`. Existing components should be repaired/reused, not rewritten automatically. Earlier plans are context; this task sequence resolves the observed usability gaps and includes the subsequent explicit microsecond-tracing requirement.

## Delivery sequence

| Stage | Tasks | Working deliverable | Gate |
| --- | --- | --- | --- |
| [1. Control and browser foundation](2026-09-04-working-mcp-gateway-01-control.md) | 1-5 | Shared contracts, durable operations, real login/API and production UI data | G0 |
| [2. Runtime and deployment](2026-09-04-working-mcp-gateway-02-runtime.md) | 6-10 | Packaged gateway, constrained provisioning, enforced egress and real lifecycle | G1 runtime portion |
| [3. Tools, governance, evidence and tracing](2026-09-04-working-mcp-gateway-03-enforcement.md) | 11-16 | Generic tools, auth, approvals, admission, CLI/stdio, evidence and microsecond spans | G2 backend portion |
| [4. Operator workflows and release](2026-09-04-working-mcp-gateway-04-operator-release.md) | 17-22 | Complete UI, trace waterfall, fresh installation and integrated release proof | G1-G3 |

First integrate the existing read-only portfolio path. General tool exposure and CLI stay disabled until its real allow/deny/evidence gate passes. Begin the task-21 acceptance harness during task 1; add real cases as each dependency lands. Do not wait until task 21 to find out whether deployment works.

### Task map and dependencies

| ID | Deliverable | Prerequisites |
| --- | --- | --- |
| 1 | Generated management/runtime/trace contracts and fixtures | None |
| 2 | Persistent desired state and transactional lifecycle evidence intents | 1 |
| 3 | Rust OIDC session edge and scoped generated API | 1-2 |
| 4 | Real UI client, truthful status and scope selection | 3 |
| 5 | Validated immutable runtime configuration compiler | 1-2 |
| 6 | Self-contained production gateway image and preflight | 5 |
| 7 | Restricted runtime agent and staged credentials | 2,5-6 |
| 8 | Per-proxy HTTPS routes, private grants and enforced egress | 7 |
| 9 | Durable reconciler, readiness, pause/resume/retire | 2,7-8 |
| 10 | Rotation, rollback and restart recovery | 9 |
| 11 | Generic tool discovery, schemas and deterministic output handling | 5,8-9 |
| 12 | Real inbound enrollment and separate outbound auth modes | 3,7,11 |
| 13 | Rust policy, durable approvals and admission leases | 2,11-12 |
| 14 | Fixed CLI and controlled stdio integration | 8,11-13, G1 |
| 15 | Correlated durable call evidence and activity queries | 1-2; wire 11-14 as they land |
| 16 | Microsecond clocks, distributed spans and precision-preserving storage | 1,15 |
| 17 | Complete large-plus wizard and connection discovery | 4-5,9,11-13 |
| 18 | Real detail tabs, lifecycle, revisions and approvals | 10,13-15,17 |
| 19 | Live activity and microsecond trace waterfall | 15-16,18 |
| 20 | Reproducible self-hosted installation and credential onboarding | 6-19 |
| 21 | Browser-to-MCP release and failure matrix | Skeleton in 1; full gate after 20 |
| 22 | Security, throughput, tracing overhead, CI and release runbooks | 21 |

The numbered order is the default, not a reason to block independent tests. Tasks 4 and 5 can run in parallel after their dependencies. Evidence and clock work can begin while runtime work proceeds. Tasks 17-19 can consume stable contracts as backend tasks land. Contract files, lockfiles, schemas and production startup each have one integration owner; do not concurrently modify those surfaces without coordination.

## Evidence ledger and completion discipline

Execution creates `docs/operations/mcp-gateway-release-evidence.md`. For each gate record the tested Git SHA, image digests, machine profile, exact commands, pass/fail counts, test artifact paths and remaining limitations. Do not put tokens or raw tool data in the ledger.

Each task contains a red/green test, implementation contract, validation commands and commit checkpoint. Commands referencing new tests, scripts or packages become runnable in the task that creates them; they are not claimed to exist at planning time. Run commands from the repository root unless a task says otherwise. Use `pnpm --dir`, not an assumed global TypeScript toolchain. Add dependencies in the task that needs them and commit lockfiles with that task.

Use `codex/working-mcp-gateway` for an implementation branch unless a different branch is requested. Preserve unrelated work. Commit only reviewed task files after fresh checks. Merge/push requires the user's execution authorization; no branch, commit or push is performed by this planning task.

## Unified acceptance command to implement in task 21

```powershell
node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all
```

The harness creates a uniquely named disposable Compose project, boots real dependencies and the runtime agent, provisions proxies only through authenticated APIs/UI, invokes the MCP SDK, checks actual stored evidence and trace values, collects redacted diagnostics and tears down only its own resources in `finally`. Missing Docker or any required dependency is a failure in the release gate, never a skip/pass. Normal installation data is never a teardown target.

Required final journey:

1. Fresh install, operator login, select authorized scope.
2. Click `+ New proxy`; save draft, reload, discover upstream, select tool, publish, deploy.
3. Connect a real MCP client through the published HTTPS endpoint; allow one call and deny another.
4. Read actual durable evidence and a microsecond stage trace in the UI.
5. Create a second proxy with different upstream, credentials, tools and policy; prove isolation.
6. Pause during a call; block new/existing-session admissions, drain, resume.
7. Rotate credentials, deploy another revision, roll back with valid credentials, retire.
8. Restart control plane/runtime agent/gateway and restore from a tested database backup.
9. Invoke unrelated structured tools, an approved CLI profile and controlled stdio paths.
10. Exercise approval, policy, evidence, identity, network and projection failures without false success.

## What is deliberately not counted as complete

- A mocked browser response, fixture-only gateway executor or static activity row.
- A Docker process being `running` without a real readiness handshake.
- A healthcheck that simply exits zero.
- Six printed timestamp digits derived from millisecond time.
- A sampled trace presented as a complete audit record.
- A lifecycle state change without the corresponding runtime effect.
- General tool support with `portfolio.read` still hardcoded in live authorization.
- A source checkout test when the deployed image cannot load its contracts/configuration.

## Plan review checklist

- [ ] G0-G3 evidence is fresh and attached to the release SHA.
- [ ] All 22 implementation tasks are complete; no required case is skipped.
- [ ] Both Rust and TypeScript enforce the agreed generic contracts.
- [ ] Microsecond values survive gateway, RPC/JSON, durable store, query and UI without rounding.
- [ ] Cross-host clock uncertainty and incomplete spans are visible.
- [ ] Unrelated roadmap work remains on hold.

Recommended execution mode: one implementer per bounded task, independent security/contract review at stage boundaries, and an integration owner running the growing real acceptance harness throughout. If agent tools are unavailable, use the same checkpoints inline; do not invent a successful external review.
