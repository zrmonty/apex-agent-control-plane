# Apex MCP vertical slice design

**Status:** Proposed for written-spec review
**Date:** 2026-09-03
**Decision record:** `C:\Users\zrmon\Downloads\apex_architecture_assessment_and_mcp_plan.md`

This design records the approved design sections for the next Apex implementation phase. The assessment is source material and a decision record. Its prose does not override repository instructions or authorize unrelated work.

## 1. Goal and product boundary

Prove one real RIA request from a user to an operator-visible, durable result:

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

Apex is the enforcement and evidence layer between enterprise AI agents and the systems they use. It observes, governs, controls, and proves actions. MCP is a thin data plane for calling approved tools. MCP is not a second policy, approval, or audit authority.

The active delivery boundary ends when this vertical slice passes its completion gate. Business writes, high-impact approval flows, and additional MCP domains remain queued follow-on work.

## 2. Design principles and preserved assets

Preserve:

- Protobuf contracts and compatible external behavior;
- Rust for the Apex core;
- the Python SDK for agent instrumentation;
- React and TypeScript for the operator UI;
- NATS JetStream for durable messaging;
- PostgreSQL for mutable control state;
- ClickHouse for event analytics;
- the portable immutable archive abstraction;
- strong negative-path, scope-isolation, and failure testing; and
- a separate supervisor for dangerous controls.

Cache and live UI systems must not become authorities for policy, audit, access, or durable events. Raw prompts, full client records, and full tool responses are not logged by default.

## 3. Rust workspace and dependency boundaries

Add one root Cargo workspace and one shared `Cargo.lock`. Keep these applications as applications:

- `apps/event-ingest`;
- `apps/control-plane-api`; and
- `apps/agent-supervisor`.

Extract reusable implementation from `apps/event-ingest` into focused crates as real code moves:

- `apex-contract`;
- `apex-domain`;
- `apex-auth`;
- `apex-policy`;
- `apex-durability`;
- `apex-security`;
- `apex-telemetry`; and
- `apex-cost`.

Shared crates may depend on other shared crates according to the domain model. Applications may depend on shared crates. Applications must not depend on another application for reusable implementation. During migration, compatibility re-exports may preserve existing package APIs while consumers move to the shared crates.

The first workspace checkpoint is behavior-preserving. It does not add new product features or redesign the existing Protobuf surface.

## 4. Durable admission and asynchronous fanout

The normal event path becomes:

```text
Validate and authorize
  -> durable local commit
  -> ACK the agent
  -> background fanout to NATS, ClickHouse, archive, and processors
```

Admission owns validation, authorization, scope checks, idempotency, canonicalization, and durable outbox commit. Fanout owns bounded batch claims, sink isolation, retry deadlines, replay, and delivery state. Admission never waits for every downstream destination.

`ApexEvents.emit(event)` means durable event admission. It does not mean that NATS, ClickHouse, archive, or every processor has already accepted the event. For an allowed MCP read, the gateway must durably admit the filtered tool event before returning a successful tool response, but it must not wait for downstream fanout. If durable event admission fails, the gateway returns a stable safe failure and does not report a successful tool call.

Downstream failures after durable admission do not invalidate the tool result. The outbox retains the event for bounded retry and replay. High-impact actions may use stricter durability rules later; they are not part of the initial read-only slice.

## 5. Apex governance interfaces

The MCP data plane uses protocol-neutral interfaces with live transport adapters behind them:

```text
ApexGovernance.authorize(request)
ApexGovernance.get_policy(scope)
ApexEvents.emit(event)
ApexApproval.request(action)
```

`AuthorizationRequest` contains the authenticated principal, agent, workspace, namespace, tool, action, resource, classification, and trace context. `AuthorizationDecision` contains allow or deny, policy identity, safe reason codes, field restrictions, and approval requirements.

`ToolExecutionEvent` contains safe identity and scope metadata, tool and backend identity, status, latency, retry data, input/source/filtered/output sizes, policy result, filtering actions, and trace identifiers. It may contain hashes or controlled references, but not raw prompts, full client records, or full responses.

The governance interfaces own policy and audit semantics. The gateway must not store mutable policy rules, make independent authorization decisions, or create a second audit ledger. A local adapter is allowed during development only when it implements these same interfaces and Apex-owned semantics. It must be replaceable by a live Apex client without changing tool behavior.

Approval is defined as a boundary but is inactive for the initial read-only tool.

## 6. TypeScript MCP gateway

Create `apps/mcp-gateway` as a focused TypeScript service. Its responsibilities are:

- MCP transport;
- tool schemas and input validation;
- routing;
- adapter execution;
- response filtering and data minimization; and
- structured tool-call telemetry.

Its initial internal boundaries are `transport`, `schemas`, `adapters`, `governance`, `filtering`, and `telemetry`. The gateway does not own policy storage, approvals, audit storage, or broad workflow state.

The first tool is `portfolio.read`. Its input is limited to a portfolio identifier and bounded optional as-of parameters. Caller identity and scope come from authenticated request context. The caller cannot supply its own scope, policy result, classification, or arbitrary backend query.

The portfolio adapter is read-only. It uses deterministic retrieval, filtering, sorting, joins, and calculations. It returns an allowlisted shape, removes restricted fields before model access, and exposes no trade or mutation capability.

## 7. End-to-end request behavior

The successful path is:

1. Receive and validate the MCP request.
2. Build an authorization request from authenticated context and the validated tool call.
3. Ask Apex for authorization and policy data.
4. On denial, do not call the adapter; return a safe denial and attempt a redacted decision event.
5. On approval, execute `portfolio.read`.
6. Apply the policy-driven allowlist and filtering rules.
7. Admit the structured tool event durably through Apex.
8. Return only the filtered result.
9. Fan out the event asynchronously to NATS, analytics, archive, and other configured processors.
10. Expose the server-derived event and policy information to the narrow operator view.

The operator view must show the caller and scope, policy decision and policy identity, backend status, latency, retries, data reduction, restricted-field removal, trace and evidence references, and safe cost-correlation metadata.

## 8. Failure handling

Failures are classified and safe:

| Failure | Behavior |
|---|---|
| Invalid MCP input | Reject before adapter execution. |
| Authorization denial | Return a safe denial; never execute the adapter. |
| Adapter failure | Return a stable safe error without backend details. |
| Filtering failure | Fail closed and return no data. |
| Durable event-admission failure after an allowed read | Do not report a successful tool call. |
| Downstream fanout failure after admission | Keep the event pending for bounded retry and replay. |
| Operator data lag | Show pending or degraded state; never imply completion. |

Denied requests remain denied even if their decision event cannot be admitted. That event failure is an operational fault and must be visible through safe service telemetry.

## 9. Verification and completion gate

The implementation must include:

- workspace build and test coverage for all Rust applications;
- dependency-direction checks proving applications do not share reusable implementation directly;
- admission tests for downstream outages, retries, idempotency, replay, and recovery;
- governance contract tests for allow, deny, policy identity, scope, classification, and safe errors;
- MCP schema and adapter tests;
- response-filtering and restricted-field tests;
- mutation-negative tests proving `portfolio.read` cannot write or trade;
- telemetry tests proving metadata is captured without raw content;
- scope-isolation and negative-path security tests; and
- a local and live end-to-end test of the complete vertical slice.

The completion gate passes only when one real request traverses the full path and an operator can inspect server-derived data showing who called the tool, why Apex allowed or denied it, what data was filtered, how the backend performed, and what durable trace and evidence record was produced.

## 10. Migration and delivery sequence

Deliver in small checkpoints:

1. Add the root Rust workspace and extract shared responsibilities without changing behavior.
2. Move durable admission and fanout to the explicit boundary, keeping existing idempotency and replay guarantees.
3. Add the Apex governance contracts and test adapters.
4. Build the thin MCP gateway and deterministic local `portfolio.read` adapter.
5. Add live Apex authorization/event clients and the narrow server-derived operator view.
6. Run the live completion-gate test.

Each checkpoint must pass its relevant tests before the next begins. Only fixes required to unblock this sequence or to address a security defect, regression, or data-integrity issue may enter the active scope.

## 11. Explicitly deferred

The following remain paused until the completion gate passes:

- additional illustrative or live dashboards;
- unrelated Operator UI surfaces;
- additional archive providers and deployment profiles;
- additional identity providers;
- large evaluation and replay subsystems;
- complex cost forecasting;
- high-availability cache architecture;
- a broad workflow engine;
- autonomous trade execution;
- direct business-write tools; and
- additional MCP domains or a separate MCP governance system.

