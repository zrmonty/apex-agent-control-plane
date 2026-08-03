# Telemetry and Control Semantics

**Status:** Accepted  
**Date:** 2026-08-03

This document closes the telemetry and control-plane decisions required to build Apex securely at scale. It is the source of behavior for the event contract, ingest service, policy engine, SDKs, and operator UI.

## 1. Core model

Apex has two distinct planes:

| Plane | Purpose | Authoritative storage | Rule |
|---|---|---|---|
| **Telemetry plane** | Record what happened: agent activity, decisions, cost, evaluations, audit, and failures. | Immutable event stream plus analytical/archive stores. | Never changes runtime state merely because an event was observed. |
| **Control plane** | Declare and enforce what is allowed or should happen: configuration, policy, commands, approvals, and reconciliation. | Transactional control store plus immutable audit events. | Every consequential control action emits an auditable result. |

No agent may use telemetry as an authorization source, and no control action may silently disappear into a dashboard-only state.

## 2. Canonical telemetry contract

Every production event uses the versioned Protobuf envelope and contains these fields:

```text
event_id             UUIDv7; globally unique and idempotency key
schema_version       immutable contract version
event_type           stable, namespaced type (for example apex.run.started)
occurred_at          UTC timestamp asserted by producer
received_at          UTC timestamp assigned by ingest
producer             workload identity, SDK version, source instance
scope                installation, workspace, namespace, AgentGroup, agent, environment
correlation          trace_id, span_id, parent_span_id, run_id, turn_id, command_id when applicable
classification       public | internal | confidential | restricted
payload              type-specific structured data, field-classified
integrity            payload hash and optional producer signature reference
```

`event_id` is mandatory and never reused. Ingest validates schema, field limits, scope, producer identity, classification, and event-type authorization before durable acknowledgement. Rejected input produces a separate security/audit record without retaining prohibited payload content.

### Required event families

| Family | Required v1 events |
|---|---|
| Lifecycle | run/turn started, completed, failed, cancelled |
| Execution | model request/result, tool request/result, retry/fallback, workflow transition |
| Governance | policy evaluated, policy denied, approval requested/decided, control command lifecycle |
| Security | authentication/authorization result, identity change, secret-access metadata, export/archive action, security rejection |
| Quality | evaluation started/result/gate decision, replay result |
| FinOps | usage observed, rate-card decision, ledger entry, budget decision, allocation/adjustment |
| Reliability | typed error, diagnostic report created, recovery/reconciliation result |

Memory and content-bearing events are optional by policy, but the memory operation metadata (retrieve/write/consolidate, source, classification, and outcome) is still recorded when permitted.

LLM events include model-execution attribution for requested/effective provider, model, reasoning effort, billable usage categories, and evidence provenance. The detailed schema and truthfulness rules are defined in [Model Execution Attribution](Model%20Execution%20Attribution.md).

## 3. Data protection, capture, and retention

1. **Metadata first:** standard production telemetry records structural metadata, identifiers, sizes, hashes, classifications, and outcomes—not prompts, completions, secrets, raw tool payloads, or credentials.
2. **Explicit content capture:** content capture is disabled by default, enabled per namespace and classification, redacted before durable storage, encrypted, access-controlled, and retention-bound.
3. **Prohibited data:** secrets, access tokens, private keys, session cookies, and raw payment-card data are rejected or redacted at the producer SDK and ingest boundary. Policy can prohibit all restricted-content capture.
4. **Server-side redaction:** access decisions and field redaction occur before data reaches the browser, export, or diagnostic bundle.
5. **Retention is a policy:** each event is assigned a named retention policy with hot, analytical, archive, and deletion/disposition behavior. Legal hold suspends deletion. Strict regulated profiles require a validated immutable archive capability; they do not infer it from a storage product name.

## 4. Delivery, ordering, and sampling

### Delivery

- The telemetry plane provides **at-least-once delivery**.
- A producer retries a timed-out write using the same `event_id`.
- Consumers deduplicate by `event_id`; a durable consumer acknowledges only after its transaction/storage write succeeds.
- The control-plane transactional outbox publishes control/audit events after the state change commits. No control decision depends on a best-effort log write.
- Backpressure returns an explicit retryable rejection. It never silently discards security, audit, cost, or control events.

### Ordering

Global ordering is neither promised nor required. Apex preserves a producer `source_sequence` and treats order as meaningful only within a single `run_id`/producer stream. Consumers use `occurred_at`, `received_at`, and `source_sequence` to display late, duplicated, or out-of-order events honestly. State-changing control commands are ordered by resource version, not event arrival time.

### Sampling

- **Never sampled:** security, audit, policy, approval, control-command, cost-ledger, evaluation-gate, and error/diagnostic events.
- **Run-coherent capture:** when high-volume execution tracing needs reduction, sampling is decided at run start and remains consistent across that run.
- **Tail retention:** failed, anomalous, policy-denied, budget-affected, or slow runs are retained in full even when normal successful runs are sampled.
- Metrics may be aggregated, but raw event retention and metric labels are bounded to prevent cardinality-based denial of service.

OpenTelemetry trace context and standard GenAI fields are mapped in one adapter. Apex's envelope, scope, classification, and ledger IDs remain authoritative, which prevents semantic drift as external conventions evolve.

## 5. Control resources and lifecycle

Control resources include policy, retention policy, archive provider, identity integration, AgentGroup, agent configuration, execution profile, rate card, budget, and approval rule.

Each resource has:

```text
resource_id | scope | spec | status | generation | resource_version | created/updated audit identity
```

- `spec` is the desired state requested by an authorized actor.
- `status` is observed/reconciled state reported by trusted controllers.
- `generation` increments for every accepted desired-state change.
- `resource_version` enables compare-and-set updates; stale writes are rejected with the current version and a conflict report.

Deletion is normally a **disable → drain → archive/disposition → delete** workflow. Direct destructive deletion is not a routine operator action.

## 6. Policy, scope, and enforcement

Policy is evaluated at installation, workspace, namespace, AgentGroup, agent, and run scope. The effective decision is:

```text
platform security floor
  → selected deployment/compliance profile
  → workspace policy
  → namespace policy
  → AgentGroup policy
  → agent/run request
```

A lower scope may add safeguards but cannot weaken an inherited prohibition, classification boundary, retention requirement, identity requirement, or approval rule. Policy evaluation returns `allow`, `deny`, `require_approval`, or `allow_with_obligations`; it always returns a reason code and policy version.

Enforcement occurs at all relevant boundaries:

| Boundary | Examples |
|---|---|
| Admission | scope, identity, budget envelope, policy profile, execution profile |
| Runtime | iteration/time/token limits, model/provider allowance, policy revocation |
| Tool execution | egress, identity, command allowlist, resource limits, data classification |
| Data handling | content capture, export, archive, retention, legal hold |
| Administrative change | role grants, identity configuration, policy/archive changes, break-glass actions |

The browser may explain a decision, but only server-side policy enforcement grants or denies it.

## 7. Commands, approvals, and recovery

Commands are explicit resources, never informal flags. Supported v1 commands are `pause`, `resume`, `drain`, `stop`, `cancel_run`, `quarantine`, `replay`, and `rotate_credential_reference`.

```text
requested → admitted | rejected | awaiting_approval
awaiting_approval → admitted | rejected | expired
admitted → dispatched → acknowledged → executing
executing → completed | failed | cancelled | expired
```

Every transition is an immutable audit/control event linked to actor, target scope, policy decision, expected resource version, reason, and diagnostic report when applicable. Command execution is idempotent on `command_id`.

| Action class | Default authorization |
|---|---|
| Read operational data | Scoped read permission and server-side redaction |
| Stop/cancel a run | Namespace operator or higher; audit reason required |
| Pause/drain/quarantine AgentGroup | Namespace admin or a delegated custom role; policy may require approval |
| Replay | AI engineer with an approved sandbox execution profile; never replays against production side effects by default |
| Change policy, archive, identity, or role delegation | Admin plus approval according to the effective policy |
| Installation owner transfer or break-glass | Owner-controlled, MFA-protected, time-limited, fully audited; break-glass never bypasses immutable audit or legal hold |

### Failure behavior

| Condition | Behavior |
|---|---|
| Policy/authorization unavailable | Deny new privileged or content-sensitive actions; existing workload follows its declared safe-degradation policy. |
| Control API unavailable | Existing workloads continue only within their already-admitted limits; new control commands remain pending client-side and are not assumed successful. |
| Telemetry ingest unavailable | Workloads buffer only within a bounded encrypted local queue; once full, strict profiles stop or reject the workload rather than lose required events. |
| Archive unavailable | Record health failure; strict retention profiles block actions that would create unarchived required records after their defined grace policy. |
| Identity provider unavailable | Existing short-lived sessions remain valid until expiry; new login, privilege elevation, and sensitive change are denied. |

Trusted controllers reconcile desired and observed state continuously. A mismatch creates a visible degraded condition and diagnostic report; reconciliation never silently overwrites a newer desired state.

## 8. Build acceptance criteria

Before a production profile is enabled, tests must prove:

1. Duplicate, late, malformed, oversized, and unauthorized events cannot corrupt state or bypass policy.
2. A producer retry yields one logical event/ledger effect.
3. Scope cannot be forged or crossed through event, API, query, export, or UI parameters.
4. Required audit/control/cost/security events survive load, restart, and consumer replay.
5. Policy changes, concurrent updates, approvals, expiry, and break-glass actions have complete immutable traces.
6. Each failure mode above is tested and visibly represented in the operator UI.
7. Restricted content never appears in a lower-privilege view, export, error report, browser log, or AI diagnostic bundle.
8. Security findings and containment follow the accepted [Security Alerts and Detection](../security/Security%20Alerts%20and%20Detection.md) model.
