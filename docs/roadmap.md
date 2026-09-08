# Apex execution roadmap

**Status:** Active
**Effective:** 2026-09-04
**Status reconciled:** 2026-09-06
**Source decision record:** `apex_architecture_assessment_and_mcp_plan.md` (assessment snapshot: 2026-09-03)

This is the execution source of truth until it is replaced by a new decision. It changes delivery priority. It does not rewrite historical progress or invalidate architecture and contract documents.

## Current objective

Build the managed MCP proxy platform: operators must be able to create, configure, govern, deploy, observe, pause, rotate, roll back, and retire multiple MCP proxies, with one hardened isolated container per proxy:

```text
Operator UI
  |
Rust control-plane API
  |
Proxy lifecycle controller
  |
One isolated OCI container per proxy
  |
Approved MCP server, API, or CLI runner
  |
Apex authorization and evidence
  |
Filtered tool result
  |
Operator activity
```

The product boundary for this roadmap is:

> Apex is the enforcement and evidence layer between enterprise AI agents and the systems they use.

Apex observes, governs, controls, and proves agent actions. MCP remains a thin data plane that calls approved tools, but the managed proxy platform adds isolated runtime and lifecycle controls around that data plane. MCP does not become a second policy or audit authority.

## Active work, in order

Only work that advances the objective below is active.

## Usability execution plan

The 2026-09-04 assessment of revision `1a6df0908de0a604415fd5c1631f697656d679ee` distinguishes implemented components from a usable managed product. That assessment found preview UI state. The MCP proxy routes now use the real browser edge, authenticated sessions and management API. Production serving, runtime lifecycle effects, generic tool governance, complete operator workflows and live activity still need integrated delivery. Historical narrow-slice and fixture verification below does not establish full operator readiness.

The requested [working MCP gateway execution plan](superpowers/plans/2026-09-04-working-mcp-gateway.md) contains 22 tasks across control/browser integration, runtime deployment, governance/evidence/tracing, and operator/release verification. Its [delivery design](superpowers/specs/2026-09-04-working-mcp-gateway-design.md) supplements the accepted platform design. Execution is active: Tasks 1–5 are complete, Tasks 6–7 are partial, and the aggregate release gates remain open. The current continuation connects the runtime authority boundary; it does not resume any work listed in **Explicit hold**.

### Remaining task count

The parent plan has **5 complete tasks and 17 tasks not fully closed**. This is
an acceptance-status count, not an estimate of remaining effort. Several open
tasks already contain reviewed and tested components.

| Parent task IDs | Remaining area | Not fully closed |
| --- | --- | ---: |
| 6–10 | Production runtime, routing, lifecycle and recovery | 5 |
| 11–16 | Tools, authentication, governance, evidence and microsecond tracing | 6 |
| 17–22 | Operator workflows, installation, integrated acceptance and release | 6 |

The runtime continuation has its own numbering. Its Tasks 1–3 are complete within
their stated boundaries; Tasks 4–5 remain open, with nine aggregate acceptance
checkboxes. Those **two continuation tasks are not the whole remaining roadmap**.
Do not add them to the 22 parent tasks or count completed sub-slices as completed
parent tasks. The [execution index](superpowers/plans/2026-09-04-working-mcp-gateway.md)
defines the parent task map and completion rules.

### Current integration boundary

The [runtime execution continuation](superpowers/plans/2026-09-05-runtime-execution-continuation.md) now connects publication-bound launch/material selection, authenticated production agent ingress, durable container provisioning, guarded paired start/recovery and the control-plane reconciliation client. Managed deployment/call authority, durable evidence admission, protected stage readers, credential preflight, guarded upstream execution, guard relays and stage-bound control transports have component and scoped native acceptance coverage. Empty-network inspection alone does not authorize execution; Task4Z separately revalidates current authority, signatures and sealed stages before guarded start and still returns NotServing. The [integration checkpoint](operations/managed-runtime-checkpoint.md) records the exact remaining boundaries.

The reviewed [guard-stage data producer](operations/managed-guard-stage-producer.md) is committed in `71dc905`. It derives exact bounded configuration, manifest and environment from the current publication/catalog and original validated topology. Actual Rust output passes the unchanged TypeScript consumers, including integer expiry above 2^53. This produces data only, not a written stage or execution permission.

The implemented and independently reviewed [Task 4W guard-staging boundary](operations/managed-guard-staging.md), committed in `cdbcd1f`, connects real signature verification to durable intent, protected sealing and exact restart recovery. Linux storage/native refusal checks pass; positive production staging with approved signed Apex images remains unproven. It stages only the guard configuration and remains NotServing; it does not complete paired staging or container execution. Remote CI must be checked against the exact integration SHA.

Task4X adds [protected paired gateway staging](operations/managed-gateway-staging.md), committed in `4ca8cb1` and integrated in `003fd45`. Verification, scoped review and both remote workflows passed for that integration, as recorded in the [checkpoint](operations/managed-runtime-checkpoint.md). Docker recovered on 2026-09-07. Task4Y [stopped-pair creation/inspection/recovery](operations/managed-paired-containers.md) and Task4Z [guard-first process start/recovery](operations/managed-paired-start.md) are implemented and reviewed locally, not committed, with independent Linux, Windows and native component checks passing. Combined integration review and the documentation-only re-review passed with no open findings on 2026-09-08. Unsigned running-process fixtures do not establish a signed production deployment or Serving. Actual HTTPS/admission composition, safe running lifecycle and end-to-end tracing remain open; parent task counts do not change.

Next implementation: compose the actual HTTPS/session root, readiness, route selection, admission renewal and safe lifecycle drain/cleanup. Do not redo the implemented paired creation/start/recovery boundaries. The managed gateway entry still fails closed. Production usability and end-to-end trace projection/query/UI remain open; integer-microsecond fields and isolated transport tests do not close those gates.

The added tracing requirement is microsecond-level elapsed measurement and precision-preserving evidence, queries and UI. Clock source, uncertainty and incomplete spans must be visible; millisecond timestamps padded with zeros do not pass.

Completion requires the real journey: fresh install and login, large-plus creation, dynamic deployment, MCP allow/deny, durable activity and microsecond traces, a second isolated proxy, safe lifecycle controls, restart/restore, and the complete release gate. All unrelated work in **Explicit hold** remains paused.

## Current implementation status

- The Rust workspace boundary is implemented for the shared event contract, domain validation/errors, authentication, security findings, and durability/fanout foundations.
- `crates/apex-policy` now defines the transport-neutral governance boundary: validated scope and identity metadata, authorization/policy/approval decisions, content-free tool evidence, and replaceable async Apex adapters.
- `event-ingest` and `control-plane-api` now consume shared crates directly; the control-plane application no longer depends on the ingest application.
- Durable admission remains enqueue-only: the admission call commits the local outbox and returns, while a separate replay worker owns downstream publication and recovery.
- The thin TypeScript stdio MCP gateway is implemented in `apps/mcp-gateway` and exposes one validated read-only MCP tool over stdio without recreating governance.
- The deterministic local `portfolio.read` path is implemented with strict input validation, exact-scope local authorization, gateway-side filtering, and metadata-only execution events.
- The live TypeScript MCP-to-Apex authorization/event path is now proven against real mTLS containers, durable admission, downstream fanout, and operator-visible event storage. CI run `33834884799` and live run `33834884797` passed the full gate.
- The earlier controlled hardening/refactor established the 600-line source/test baseline, stricter endpoint/secret/container checks, and a measured gateway serialization improvement. Its evidence is recorded in [`codebase-hardening-baseline.md`](architecture/codebase-hardening-baseline.md), [`codebase-hardening-review.md`](security/codebase-hardening-review.md), and [`gateway-throughput-baseline.md`](performance/gateway-throughput-baseline.md). These historical results do not close the current managed-product security or throughput release gates.

The foundation boundary is complete: the dependency-direction check and the durable ACK-before-downstream regression checks are green in the full workspace verification.

### 1. Create one Rust workspace

- Add a single workspace root for the Rust code.
- Extract reusable responsibilities from `apps/event-ingest` into shared crates.
- Start with the assessment boundaries: contracts, domain, auth, policy, durability, security, telemetry, and cost.
- Keep `event-ingest`, `control-plane-api`, and `agent-supervisor` as applications that depend on shared crates, not on another application.
- Preserve the existing Protobuf contracts and compatible behavior while moving code.

**Exit gate:** all existing Rust applications build and test from the workspace, and no application imports reusable implementation code from another application.

### 2. Separate durable admission from downstream fanout

Make the normal path:

```text
Validate and authorize
  -> durable local commit
  -> ACK the agent
  -> background fanout to NATS, ClickHouse, archive, and processors
```

The admission path must not wait for every downstream destination. Preserve idempotency, bounded retries, durable replay, and stricter durability options for genuinely high-impact actions.

**Exit gate:** a downstream outage does not prevent an accepted event from being durably committed and acknowledged; worker, retry, idempotency, and recovery tests prove the behavior.

### 3. Define Apex governance interfaces

**Status:** Implemented in `crates/apex-policy`; integration begins with the TypeScript MCP gateway.

Define the smallest interfaces needed by the MCP data plane:

```text
ApexGovernance.authorize(request)
ApexGovernance.get_policy(scope)
ApexEvents.emit(event)
ApexApproval.request(action)
```

The interfaces must carry the existing scope, identity, policy, trace, and classification semantics. They must make denial, redaction, approval, and event failures explicit and testable.

**Exit gate:** the gateway can call Apex for authorization and event capture without owning policy rules, audit storage, or mutable governance state.

### 4. Build one thin TypeScript MCP gateway

**Status:** Implemented locally/test-only in `apps/mcp-gateway`.

Create `apps/mcp-gateway` as a small service. It owns:

- MCP transport;
- tool schemas and input validation;
- routing and adapter execution;
- response filtering and data minimization; and
- structured tool-call telemetry.

Use a local adapter first if that shortens the path. Replace it with a live Apex client only at the integration boundary. Do not add a second governance system.

**Exit gate:** the gateway exposes one validated tool, applies response filtering, and delegates authorization and event capture through the Apex interfaces.

### 5. Add one RIA read-only tool

**Status:** Implemented locally/test-only as the deterministic `portfolio.read` path.

Start with `portfolio.read` or an equivalent read-only portfolio tool.

- Return only fields required for the request.
- Use deterministic retrieval, filtering, sorting, joins, and calculations.
- Remove restricted or unnecessary fields before the result reaches the model.
- Do not expose direct trade execution.

**Exit gate:** allowed and denied requests are both tested, the tool cannot mutate portfolio state, and sensitive fields are removed by the gateway rather than by model instructions.

### 6. Prove and harden the live vertical slice

**Status:** Complete for the narrow active slice. The follow-on hardening gate is complete locally and is being integrated through CI.

Connect the real path end to end. The operator must be able to see:

- who called the tool and within which scope;
- whether Apex policy allowed or denied it and which policy applied;
- backend status, latency, and retries;
- input, source, filtered, and output sizes;
- restricted-field removal;
- the complete trace, event, and evidence record; and
- the relevant cost correlation metadata without raw prompts or full client records.

**Completion gate:** one real request traverses the full sequence above and the result is visible from server-derived operator data. This is the only product slice required before the roadmap may expand.

The completed gate includes the real gateway image, mTLS, product SDK proof, governed MCP stdio proof, operator command path, Postgres replicas, cross-replica Valkey admission, Keycloak operator credentials, adversarial event corpus, compose validation, and teardown. The controlled hardening pass adds the 600-line readability gate, responsibility-based Rust/TypeScript/Python splits, strict live-target and secret handling, read-only gateway root filesystem, and the equivalent Struct serialization benchmark. No held roadmap feature was started.

### 7. Build the managed MCP proxy platform

**Status:** Active milestone. The approved design is [`2026-09-04-mcp-proxy-platform-design.md`](superpowers/specs/2026-09-04-mcp-proxy-platform-design.md); the research source ledger is [`report-source.md`](mcp-proxies/report-source.md). Execute the [22-task working gateway plan](superpowers/plans/2026-09-04-working-mcp-gateway.md) and its [runtime continuation](superpowers/plans/2026-09-05-runtime-execution-continuation.md). The [original platform plan](superpowers/plans/2026-09-04-mcp-proxy-platform.md) remains design context, not a second active task queue.

Build the deep MCP proxy capability as one focused product slice:

- Add versioned proxy resources and lifecycle operations to the control-plane contract.
- Store drafts and publish immutable, content-addressed proxy revisions.
- Reconcile desired state into one hardened OCI container per logical proxy.
- Keep each proxy's identity, credentials, sessions, caches, files, network policy, resource budget, and evidence namespace isolated.
- Add `MCP proxies` to the existing React operator UI with a prominent large `+ New proxy` action.
- Implement the guided creation flow for identity, ingress, upstreams, tool exposure, CLI profiles, authentication, governance, and deployment review.
- Support MCP stdio and Streamable HTTP with explicit per-transport security rules.
- Use separate inbound and outbound credentials; never pass inbound tokens through to upstreams.
- Route every call through Apex authorization, approval, filtering, and durable evidence.
- Provide fixed CLI command profiles with typed argument arrays, executable identity, sandbox, egress, timeout, and output limits. Do not provide arbitrary shell execution.
- Provide deploy, pause, resume, rotate, rollback, retire, health, readiness, revision, and activity workflows.
- Verify scope isolation, container hardening, protocol safety, SSRF resistance, CLI safety, secret handling, evidence behavior, accessibility, and throughput.

**First acceptance slice:** a read-only `portfolio.read` proxy follows the existing live vertical path through an isolated runtime and appears in the operator UI as server-derived activity. Broader MCP domains and high-impact writes remain queued until the shared proxy patterns pass this gate.

## Explicit hold

The following work is paused. Do not start it, expand it, or use it to define the next milestone unless it is required to unblock an active step or fix a security defect, regression, or data-integrity issue:

- additional static or illustrative operator dashboards and UI routes unrelated to the approved MCP proxy surface;
- the broader Operator UI feature suite, including unrelated Agent Story, Security Center, compliance, evaluation, and cost surfaces;
- more archive-provider backends or deployment profiles;
- identity providers beyond the immediate vertical-slice need;
- large evaluation and replay subsystems;
- complex cost forecasting before attribution is reliable;
- high-availability cache architecture;
- a broad workflow engine inside Apex;
- direct autonomous trade execution;
- a separate MCP governance or audit system; and
- expansion to additional MCP domains before the first gateway and tool patterns are stable.

Existing phase, security, Valkey, onboarding, UI, deployment, and domain roadmaps remain useful reference material. They are not active execution queues while this roadmap is active.

## Guardrails

- Preserve Protobuf, Rust Apex core, Python SDK, React/TypeScript UI, NATS JetStream, PostgreSQL control state, ClickHouse analytics, portable immutable archive, and the separate supervisor for dangerous controls.
- Do not log raw prompts, full client records, or full tool responses by default.
- Keep cache and live UI systems out of the authority path for policy, audit, and durable events.
- Keep strong negative-path, scope-isolation, data-minimization, and failure testing with every active change.
- Treat business writes, high-impact approvals, and additional MCP domains as queued follow-on work after the completion gate, not as parallel work.

## Roadmap disposition

The former README build order is superseded by this sequence. Other roadmap lists in architecture and progress documents describe their original scope or future possibilities; they do not override this hold decision.
