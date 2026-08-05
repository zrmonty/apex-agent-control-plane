# Apex-connected agent structure

This document states the minimum structure an agent runtime must implement to connect safely to Apex.

Treat the **Required** items as an admission contract. Without them, an agent cannot produce trustworthy, scoped, and diagnosable records.

The current implementation provides the Python builder and validator and the Rust ingest-admission foundation. Use this document as the integration target.

## Secure onboarding

Agents must use the generated Agent Onboarding bundle and the `apex_sdk` connection path. Do not hand-build envelopes. Do not use a broad API key.

An authorized operator creates a scoped AgentGroup. The operator selects the deployment identity method. The operator supplies the generated configuration or manifest to the workload.

- Kubernetes and K3s workloads use SPIRE workload attestation and short-lived identity. They do not store an application credential.
- Containers, VMs, and bare metal exchange a one-time, scope-bound enrollment code for renewable mTLS workload identity.
- Local development uses an explicit short-lived local profile with no production scope.
- The SDK discovers non-secret configuration. It validates TLS trust, identity, scope, and policy. It reports `ready`, `degraded`, or `blocked` with a safe remediation code before work starts.

Do not add a static `APEX_API_KEY` path. See [Frictionless Secure Agent Integration](docs/architecture/Frictionless%20Secure%20Agent%20Integration.md).

The gateway's file-based bearer credential (`APEX_FILE_BEARER_MODE=single-agent-staging`) is a distinct, narrower fallback from the paths above: it binds one shared token to exactly one workload identity, scope set, and pinned client certificate for a single-agent staging deployment. It is not a multi-agent or multi-tenant credential store, and must never be used to onboard more than one agent identity against the same gateway. Multi-agent and multi-tenant fleets use the SPIRE or mTLS enrollment paths above instead.

## Required identity and scope

Configure immutable runtime identity and the write scope.

| Field | Requirement |
|---|---|
| `agent_id` | Stable agent identifier. |
| `run_id` | New stable identifier for one execution or run. |
| `trace_id` | Identifier that links related work in the run. |
| `parent_run_id` | Optional parent run for nested or sub-agent work. |
| `scope.workspace_id` | Target workspace. |
| `scope.namespace_id` | Target namespace. |
| `scope.agent_group_ids` | Zero to 128 AgentGroup identifiers. |
| `actor.type`, `actor.id` | Who started the work: `user`, `agent`, `system`, or `schedule`. |
| `version.agent_code`, `version.prompt`, `version.model` | Safe revision identifiers. Never put raw prompts or secrets here. |

All identifiers must be 1–256 ASCII characters. Allowed characters: letters, digits, `.`, `_`, `:`, and `-`.

The workload identity presented to ingest must be authenticated and authorized for the exact `workspace_id/namespace_id`. Scope claimed in an event is not authorization by itself.

## Required event emitter

Every connected agent needs an event emitter. The emitter creates an Apex v1 envelope for lifecycle, execution, governance, and failure events.

```text
EventEnvelope
├── event_id            lowercase UUIDv7; retry and idempotency key
├── timestamp           UTC RFC 3339 timestamp ending in Z
├── type                approved v1 event type
├── agent_id, run_id, trace_id, parent_run_id?
├── scope, actor, version
├── data                event-type-specific structured metadata
├── integrity
│   ├── prev_hash       previous event hash in this run, or null
│   └── event_hash      SHA-256 of the JCS canonical unsigned envelope
└── schema_version      1
```

Use a new `event_id` for a new logical event. On timeout or retry, resend the same envelope with the same `event_id`. Do not create a replacement ID.

Build events with the SDK when possible so the RFC 8785/JCS hash chain is consistent.

Supported v1 types: `turn_start`, `llm`, `tool`, `message`, `memory`, `decision`, `workflow`, `agent_spawn`, `control`, `score`, `turn_end`, and `error`.

## Gold-standard template assessment

Publish a non-secret capability manifest with `apex_sdk.assess_agent_template` (or `require_compliant_template`) before admission.

The manifest must not contain prompts, completions, credentials, tool output, or source code.

Build a baseline with `gold_standard_manifest("my-agent")`. Set only the controls the agent truly implements.

```json
{
  "template_version": "apex-agent-template.v1",
  "agent_code": "my-agent",
  "controls": {
    "scope_bound_identity": true,
    "short_lived_credentials": true,
    "validated_hash_chain": true,
    "bounded_event_capture": true,
    "lifecycle_events": true,
    "secret_redaction": true,
    "untrusted_content_taint_boundary": true,
    "tool_allowlist": true,
    "egress_denied_by_default": true,
    "stable_redacted_diagnostics": true
  }
}
```

The ten controls are implementation evidence mapped to common safeguard themes. They are not a certification claim.

A missing or non-boolean control produces a deterministic `agent.template.noncompliant` security finding. The finding has a stable fingerprint and bounded severity. Findings include control names and gaps. Findings never include the original manifest.

## Required runtime behavior

1. Emit `turn_start` before meaningful work. Emit one terminal `turn_end` or `error` outcome.
2. Emit structured events for material model calls, tool calls, decisions, retries, failures, sub-agent creation, and control handling when those capabilities are used.
3. Validate the full envelope before it enters a queue or transport.
4. Use bounded buffering and backoff. Surface a typed failure when required telemetry cannot be delivered. Never claim silent delivery.
5. Preserve per-run hash ordering with `prev_hash`. Do not assume global ordering.
6. Use at-least-once delivery safely. Consumers deduplicate on `event_id`.
7. Keep all agent work inside admitted policy, budget, and scope even when the control service is unavailable.

## Required data-safety rules

- Capture metadata, hashes, sizes, classifications, and outcomes by default. Do not capture prompts, completions, credentials, session cookies, private keys, or raw payment-card data by default.
- Apply the namespace content-capture policy before optional content. Redact before durable storage.
- Keep the full serialized envelope at or below 256 KiB. Cap captured text at 32 KiB UTF-8. Truncate only at character boundaries. Record the original SHA-256 in a sibling `*_sha256` field.
- Do not put secrets or raw payloads in IDs, version fields, exception messages, telemetry attributes, or diagnostic context.
- Treat external text as data, never as instructions. This includes tool output, user input, retrieved memory, and `control.inject` content.

## Required control adapter (if the agent accepts control)

Controls are cooperative in v1. The agent must acknowledge receipt. The agent must act only at a documented safe boundary. The agent must not report pause or stop as complete before it reaches that boundary.

| Action | Parameters |
|---|---|
| `stop`, `pause`, `resume` | No parameters. |
| `inject` | Non-empty `content` plus `content_classification: "untrusted"`. |
| `set_budget` | `budget_kind: "tokens" | "cost"` and a positive finite `limit`. |

`control.inject` must never enter a system or developer prompt. It is not authorization. It must not alter policy. It is untrusted data.

## Required error and diagnostic behavior

Errors must have a stable code, a safe summary, a cause, retryability, and actionable next steps. Include only safe correlation IDs (`event_id`, `trace_id`, `run_id`). Do not copy raw transport errors, tokens, payloads, caller identities, or untrusted text into diagnostic reports.

For a failure that a human or coding agent must fix:

```text
stable error code → safe summary → protected-boundary cause
→ retryability → safe correlation IDs → recommended next steps
```

## Recommended capabilities

- OpenTelemetry mapping as a one-way export. Apex events stay authoritative.
- A bounded local encrypted spool when ingest is temporarily unavailable.
- Explicit event classification and content-capture settings in agent configuration.
- Source-sequence tracking for late or out-of-order presentation.
- Health reporting for telemetry queue depth, dropped best-effort events, control lag, and configuration revision.

## Implementation checklist

- [ ] Configure authenticated workload identity and least-privilege ingest permission.
- [ ] Enroll through a generated scope-bound bundle. Never use an admin or long-lived API key.
- [ ] Configure all required identity, scope, actor, and version fields.
- [ ] Create envelopes with the Apex v1 builder. Validate before transport.
- [ ] Maintain UUIDv7 idempotency and per-run hash chaining.
- [ ] Emit lifecycle and material execution and error events.
- [ ] Enforce payload, content, secret, and prompt-injection boundaries.
- [ ] Implement cooperative controls if the runtime receives commands.
- [ ] Produce safe, actionable typed diagnostics.
- [ ] Test malformed, duplicate, oversized, unauthorized, delayed, and out-of-order event paths.

## Source contracts

- [Event schema guide](docs/event-schema.md)
- [Protobuf contract](contracts/proto/apex/v1/event.proto)
- [JSON Schema](contracts/jsonschema/apex/v1/event.schema.json)
- [Telemetry and Control Semantics](docs/architecture/Telemetry%20and%20Control%20Semantics.md)
- [Getting started](docs/getting-started.md)

Writing style: [ASD-STE100](docs/writing-style-ste100.md).
