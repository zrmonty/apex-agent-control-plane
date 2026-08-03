# Apex-connected agent structure

This is the minimum structure an agent runtime must implement to connect safely to the Apex Agent Control Plane. Treat the items in **Required** as an admission contract: without them, an agent cannot produce trustworthy, scoped, and diagnosable records.

The current implementation provides the Python builder/validator and the Rust ingest-admission foundation. The networked gRPC ingest adapter is still being completed; until then, use this document as the integration target rather than assuming a public endpoint is ready.

## Frictionless secure onboarding

Agents should use the generated Agent Onboarding bundle and `apex_sdk` connection path, not hand-built envelopes or a broad API key. An authorized operator creates a scoped AgentGroup in the GUI, chooses the deployment identity method, and supplies the generated configuration/manifest to the workload.

- Kubernetes/K3s workloads use SPIRE workload attestation and short-lived identity without an application credential.
- Containers, VMs, and bare metal exchange a single-use, scope-bound enrollment code for renewable mTLS workload identity.
- Local development uses an explicit short-lived local profile with no production scope.
- The SDK discovers non-secret configuration, validates TLS trust, identity, scope, and policy, then reports `ready`, `degraded`, or `blocked` with a safe remediation code before work begins.

Do not add a static `APEX_API_KEY` integration path. The generated bundle, enrollment, and SDK requirements are defined in [Frictionless Secure Agent Integration](docs/architecture/Frictionless%20Secure%20Agent%20Integration.md).

## Required identity and scope

An agent must be configured with immutable runtime identity and the scope it is allowed to write to:

| Field | Requirement |
|---|---|
| `agent_id` | Stable agent identifier. |
| `run_id` | New stable identifier for one execution/run. |
| `trace_id` | Identifier linking related work across the run. |
| `parent_run_id` | Optional parent run identifier for nested/sub-agent work. |
| `scope.workspace_id` | Target workspace. |
| `scope.namespace_id` | Target namespace. |
| `scope.agent_group_ids` | Zero to 128 AgentGroup identifiers. |
| `actor.type`, `actor.id` | Who initiated the work: `user`, `agent`, `system`, or `schedule`. |
| `version.agent_code`, `version.prompt`, `version.model` | Safe revision identifiers for the code, prompt, and model configuration. Never place raw prompts or secrets here. |

All identifiers must be 1–256 ASCII characters using only letters, digits, `.`, `_`, `:`, and `-`. The workload identity presented to ingest must be authenticated and authorized for the exact `workspace_id/namespace_id`; scope claimed in an event is not authorization by itself.

## Required event emitter

Every connected agent needs an event emitter that creates an Apex v1 envelope for lifecycle, execution, governance, and failure events.

```text
EventEnvelope
├── event_id            lowercase UUIDv7; retry/idempotency key
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

Use a new `event_id` for a new logical event. On a timeout or retry, resend the exact same envelope with the same `event_id`; do not generate a replacement ID. Build events with the SDK where possible so the RFC 8785/JCS hash chain is generated and validated consistently.

The supported v1 types are `turn_start`, `llm`, `tool`, `message`, `memory`, `decision`, `workflow`, `agent_spawn`, `control`, `score`, `turn_end`, and `error`.

## Gold-standard template assessment

Every connected agent should publish a non-secret capability manifest using `apex_sdk.assess_agent_template` before it is admitted. The manifest is intentionally small and declarative; it must not contain prompts, completions, credentials, tool output, or source code.

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

The ten controls are implementation evidence mapped to SOC 2, HIPAA, SEC records, and FedRAMP-oriented safeguards; they are not a certification claim. A missing or non-boolean control produces a deterministic `agent.template.noncompliant` security finding with a stable fingerprint, bounded severity, and `require_approval` policy decision. The finding contains only control names and counts. Emit the returned `event_data()` as a `score` or `error` event, then block, quarantine, or require operator review according to the deployment policy. Never include the original manifest in an event or diagnostic.

## Required runtime behavior

1. Emit `turn_start` before meaningful work, and one terminal `turn_end` or `error` outcome.
2. Emit structured events for material model calls, tool calls, decisions, retries, failures, sub-agent creation, and control handling when those capabilities are used.
3. Validate the full envelope before it enters a queue or transport.
4. Use bounded buffering and backoff. Surface a typed failure when required telemetry cannot be delivered; never silently claim delivery.
5. Preserve per-run hash ordering with `prev_hash`. Global ordering is not assumed.
6. Use at-least-once delivery safely: consumers deduplicate on `event_id`.
7. Keep all agent work within the runtime’s admitted policy, budget, and scope even when the control service is unavailable.

## Required data-safety rules

- Capture metadata, hashes, sizes, classifications, and outcomes by default—not prompts, completions, credentials, session cookies, private keys, or raw payment-card data.
- Apply the namespace content-capture policy before emitting optional content. Redact before durable storage.
- Keep the complete serialized envelope at or below 256 KiB. Captured text is capped at 32 KiB UTF-8; truncate only at character boundaries and record the original SHA-256 in a sibling `*_sha256` field.
- Do not place secrets or raw payloads in IDs, version fields, exception messages, telemetry attributes, or diagnostic context.
- Render external text as data, never as instructions. This includes tool output, user input, retrieved memory, and `control.inject` content.

## Required control adapter, if the agent accepts control

Controls are cooperative in v1. The agent must acknowledge receipt and act only at a documented safe boundary; it must not report a pause or stop as complete before it actually reaches that boundary.

| Action | Parameters |
|---|---|
| `stop`, `pause`, `resume` | No parameters. |
| `inject` | Non-empty `content` plus `content_classification: "untrusted"`. |
| `set_budget` | `budget_kind: "tokens" | "cost"` and a positive finite `limit`. |

`control.inject` must never be concatenated into a system/developer prompt, treated as authorization, or allowed to alter policy. It is untrusted data subject to the agent’s explicit handling policy.

## Required error and diagnostic behavior

Errors must have a stable code, a safe summary, a cause, retryability, and actionable next steps. Include only safe correlation IDs (`event_id`, `trace_id`, `run_id`). Do not copy raw transport errors, tokens, payloads, caller identities, or untrusted text into diagnostic reports.

For a failure that a human or coding agent must troubleshoot, provide:

```text
stable error code → safe summary → protected-boundary cause
→ retryability → safe correlation IDs → recommended next steps
```

## Recommended capabilities

- OpenTelemetry mapping as a one-way interoperability export; Apex events remain authoritative.
- A bounded local encrypted spool for required events when ingest is temporarily unavailable.
- Explicit event classification and content-capture settings in agent configuration.
- Source-sequence tracking for late/out-of-order presentation.
- Health reporting for telemetry queue depth, dropped best-effort events, control lag, and configuration revision.

## Implementation checklist

- [ ] Configure authenticated workload identity and least-privilege ingest permission.
- [ ] Enroll through a generated scope-bound bundle; never use an admin or long-lived API key.
- [ ] Configure all required identity, scope, actor, and version fields.
- [ ] Create envelopes with the Apex v1 builder and validate before transport.
- [ ] Maintain UUIDv7 idempotency and per-run hash chaining.
- [ ] Emit lifecycle and material execution/error events.
- [ ] Enforce payload, content, secret, and prompt-injection boundaries.
- [ ] Implement cooperative controls if the runtime receives commands.
- [ ] Produce safe, actionable typed diagnostics.
- [ ] Test malformed, duplicate, oversized, unauthorized, delayed, and out-of-order event paths.

## Source contracts

- [Event schema guide](docs/event-schema.md)
- [Protobuf contract](contracts/proto/apex/v1/event.proto)
- [JSON Schema](contracts/jsonschema/apex/v1/event.schema.json)
- [Telemetry and Control Semantics](docs/architecture/Telemetry%20and%20Control%20Semantics.md)
