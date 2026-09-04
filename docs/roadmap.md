# Apex execution roadmap

**Status:** Active
**Effective:** 2026-09-03
**Source decision record:** `apex_architecture_assessment_and_mcp_plan.md` (assessment snapshot: 2026-09-03)

This is the execution source of truth until it is replaced by a new decision. It changes delivery priority. It does not rewrite historical progress or invalidate architecture and contract documents.

## Current objective

Build one real RIA request from the user to an operator-visible, durable result:

```text
User
  |
Agent
  |
TypeScript MCP gateway
  |
Apex authorization
  |
Portfolio read-only tool
  |
Response filtering
  |
Apex event
  |
NATS and analytics
  |
Operator UI
```

The product boundary for this roadmap is:

> Apex is the enforcement and evidence layer between enterprise AI agents and the systems they use.

Apex observes, governs, controls, and proves agent actions. MCP is a thin data plane that calls approved tools. MCP does not become a second policy or audit authority.

## Active work, in order

Only work that advances the objective below is active.

## Current implementation status

- The Rust workspace boundary is implemented for the shared event contract, domain validation/errors, authentication, security findings, and durability/fanout foundations.
- `crates/apex-policy` now defines the transport-neutral governance boundary: validated scope and identity metadata, authorization/policy/approval decisions, content-free tool evidence, and replaceable async Apex adapters.
- `event-ingest` and `control-plane-api` now consume shared crates directly; the control-plane application no longer depends on the ingest application.
- Durable admission remains enqueue-only: the admission call commits the local outbox and returns, while a separate replay worker owns downstream publication and recovery.
- The thin TypeScript stdio MCP gateway is implemented in `apps/mcp-gateway` and exposes one validated read-only MCP tool over stdio without recreating governance.
- The deterministic local `portfolio.read` path is implemented with strict input validation, exact-scope local authorization, gateway-side filtering, and metadata-only execution events.
- The live TypeScript MCP-to-Apex authorization/event path is now proven against real mTLS containers, durable admission, downstream fanout, and operator-visible event storage. CI run `33834884799` and live run `33834884797` passed the full gate.
- The current pass is a controlled hardening/refactor of this active slice: every tracked source/test file is at or below 600 lines, the live boundary has stricter endpoint/secret/container checks, and the gateway serialization path has a measured throughput improvement. The hardening evidence is recorded in [`codebase-hardening-baseline.md`](architecture/codebase-hardening-baseline.md), [`codebase-hardening-review.md`](security/codebase-hardening-review.md), and [`gateway-throughput-baseline.md`](performance/gateway-throughput-baseline.md).

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

## Explicit hold

The following work is paused. Do not start it, expand it, or use it to define the next milestone unless it is required to unblock an active step or fix a security defect, regression, or data-integrity issue:

- additional static or illustrative operator dashboards and UI routes;
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
