# Security Alerts and Detection

**Status:** Accepted  
**Date:** 2026-08-03

The first Phase 0 implementation slice is now present in the Rust ingest
foundation: immutable scoped findings, hashed evidence references, stable
scope-aware fingerprints, append-only status/containment updates, bounded
capacity, redacted typed errors, a deterministic redacted signal adapter, and a
bounded JSONL journal for restart-safe replay. The ingest gateway can opt into
redacted findings for scope denials and idempotency conflicts; PostgreSQL/control-plane
integration and broader detector wiring remain open work.

## Purpose

Security Alerts turns trusted Apex telemetry and policy results into scoped, explainable, actionable security findings. It protects agent workloads from prompt injection, malicious tools, data exposure, identity abuse, control-plane tampering, and telemetry integrity failures without treating untrusted content as instructions.

This is a control-plane capability, not a generic log-alerting feature. A finding links to redacted evidence, the detector/policy version, scope, and a safe response path.

## Security finding contract

`SecurityFinding` is an immutable derived record, created by the detection service and linked to canonical event IDs. It does not change the frozen v1 agent event vocabulary.

```text
finding_id             UUIDv7
type                   stable category, for example prompt_injection.indirect
severity               info | low | medium | high | critical
confidence             deterministic | corroborated | heuristic
status                 open | acknowledged | contained | resolved | false_positive
scope                  workspace, namespace, AgentGroup, agent, run
detector               rule/model version and configuration revision
evidence_refs          event IDs and safe field paths/hashes only
policy_decision        allow | deny | require_approval | containment action
fingerprint            stable deduplication key
created_at/updated_at  UTC timestamps
```

Findings are append-only. Status changes, suppression, exception, containment, and resolution create linked audit events; they do not overwrite the original finding. The record never embeds raw prompts, model output, tool output, credentials, or restricted content.

## Detection and response model

The Rust detector boundary accepts only `DetectionInput`: a signal category,
validated scope, UUIDv7 event ID, safe field path, and lowercase SHA-256 value
hash. `detect_and_record` maps the signal to a fixed detector version, severity,
policy decision, and finding type, then delegates to the append-only store.
Raw hostile content is not part of the API and cannot enter a finding through
this path.

| Lane | Implementation | Allowed result |
|---|---|---|
| **Inline prevention** | Deterministic policy at admission, model/tool request, egress, export, and control boundaries. | Deny, redact, require approval, or contain before the risky action completes. |
| **Asynchronous detection** | Durable consumers correlate event metadata, policy decisions, hashes, and bounded behavioral signals. | Create a finding, notify, open an incident, or request an authorized response. |
| **Optional analytical enrichment** | Offline or sandboxed analysis over redacted/minimized evidence. | Add context only; never the sole basis to grant access, execute a tool, or silently take destructive action. |

An LLM is never the only prompt-injection detector or policy decision-maker. It may assist a reviewer only after data classification, redaction, and explicit approval requirements are met.

## Detection catalog

| Category | Signals | Default response |
|---|---|---|
| **Direct and indirect prompt injection** | Untrusted user, retrieval, memory, tool, or `control.inject` content attempts to override system/developer instructions, policy, identity, tool permissions, or data boundaries. Taint crosses from untrusted content into instruction/authorization fields. | Block the taint crossing inline; create a high-severity finding when attempted. Preserve hashes/references, not the injected text. |
| **Malicious or compromised tool** | Unapproved tool identity/version, manifest/signature mismatch, unexpected endpoint, privilege/mount request, shell execution, unsafe file path, SSRF-like destination, egress-policy violation, or tool output attempting instruction escalation. | Deny execution/egress; quarantine the tool binding or AgentGroup only under a high-confidence policy; alert administrators. |
| **Data exfiltration or secret exposure** | Secret/token/private-key patterns, restricted classification sent to an unauthorized model/tool/export, anomalous outbound volume/destination, sensitive content in a diagnostic/export field. | Redact/block at the boundary, revoke ephemeral capability where configured, and create a critical finding. |
| **Identity and authorization abuse** | Repeated denials, impossible scope use, role-grant escalation, expired/invalid workload identity, suspicious break-glass use, or a service identity acting outside its delegated scope. | Deny inline; notify scoped administrators; require review for privileged changes. |
| **Policy and control tampering** | Attempts to weaken inherited policy, bypass an approval, change archive/retention controls, replay into production side effects, or submit stale/conflicting resource versions repeatedly. | Reject inline, create audit/finding records, and escalate according to policy. |
| **Telemetry integrity attack** | Invalid event hash, broken run hash chain, duplicate ID with changed content, malformed/oversized event flood, producer clock anomaly, or unauthorized event type. | Reject/quarantine input, rate limit where applicable, and alert platform security. |
| **Runaway or evasive agent behavior** | Budget/iteration evasion, abnormal retry/loop patterns, rapid permission denials, unexpected model/tool switching, or deviation from the approved workflow/execution profile. | Enforce admitted limits; create a finding; pause new work only if the effective policy authorizes it. |
| **Agent template noncompliance** | The bounded, non-secret `apex-agent-template.v1` manifest is missing a required control or contains a non-boolean declaration. | Emit a deterministic `agent.template.noncompliant` finding with a stable fingerprint; require approval or quarantine according to deployment policy. Never persist the original manifest. |

## Severity and containment

| Severity | Meaning | Notification and action |
|---|---|---|
| Info/low | Informational or isolated weak signal. | Security Center only; grouped by fingerprint. |
| Medium | Actionable, but containment would risk undue disruption. | Scoped notification and review queue. |
| High | Strong policy violation or corroborated attack signal. | Immediate Security Center alert, incident creation, and configured on-call notification. |
| Critical | Deterministic block of secrets/restricted-data exfiltration, integrity compromise, or high-confidence malicious execution. | Block/contain at the boundary, notify immediately, and require explicit resolution/audit. |

Automated containment is allowlisted and reversible: deny a request, disable a tool binding, pause new work, or quarantine an AgentGroup. It never deletes data, changes retention/legal hold, transfers ownership, alters policy, or takes action outside the target scope. A containment policy names who can release it and when approval is required.

## Security Center GUI

The Operator UI includes **Security Center** as a first-class view:

- clear counts by severity, scope, category, status, and time;
- an attack timeline that joins the finding to redacted trace, policy, tool, and control events;
- plain-language explanation of what was blocked or observed, why, and what a user may safely do next;
- one-click scoped actions only when the viewer has the required permission: acknowledge, request review, pause, quarantine, or open a diagnostic bundle;
- visible detector version, confidence, evidence references, suppression/exception expiry, and false-positive feedback;
- text/table equivalents, keyboard support, high-contrast support, and no raw hostile content rendering.

External notifications are optional adapters. They receive a scoped, redacted finding summary and deep link; no prompt, tool output, token, secret, or restricted content is sent to email, chat, SIEM, or an AI assistant by default.

## Permissions and operations

- `security.finding.read` permits a scoped finding summary. Evidence still follows data classification and redaction policy.
- `security.finding.manage` permits acknowledgement, case management, and time-limited suppression in scope.
- `security.containment.execute` permits an already-policy-allowed pause/quarantine/disable action; it does not grant policy administration.
- `security.policy.manage` and `security.exception.approve` remain separate, higher-risk permissions.
- Suppressions require reason, owner, scope, expiry, matching fingerprint, and an audit event. They may reduce notification noise but cannot suppress a deterministic inline block.

## Delivery roadmap

### Phase 0 — prevention and evidence foundation

1. Implement the `SecurityFinding` store/contract, immutable audit linkage, fingerprints, severities, and scoped RBAC.
2. Emit findings for malformed/integrity-invalid telemetry, scope/identity denial, untrusted `control.inject` boundary violation, secret/redaction block, tool allowlist/egress denial, and agent-template noncompliance.
3. Implement deterministic inline controls: untrusted-to-instruction taint block, signed/approved tool identity, denied-by-default egress, bounded execution profiles, and server-side redaction.
4. Test every block, finding, deduplication, redaction, scope-isolation, and containment path under replay, restart, and load.

The current journal is intentionally a local persistence seam: it requires an
absolute path inside a trusted non-symlink base, rejects symlinked targets,
caps records at 1 MiB and the journal at 256 MiB, flushes and syncs each
accepted record, and replays immutable findings before status updates. It is
appropriate for local development and deterministic tests; an authoritative
single-writer seam, not a multi-writer database, and an authoritative
PostgreSQL/control-plane store is still required for production. Scoped RBAC,
enrollment, and policy-engine integration are not yet present in the runnable
binary; compliance language for those controls describes the target surface,
not an assertion that production enforcement already exists.

`control.inject` content is untrusted data, never an instruction source. Every
future consumer must preserve that taint and reject promotion into system or
developer instructions, authorization, policy, or tool permissions.

### Phase 1 — visual response

1. Deliver Security Center, finding timeline, acknowledgements, severity/status filters, and scoped case workflow.
2. Add redacted SIEM/webhook adapters and policy-controlled notification routing.
3. Add safe containment actions with approval/expiry and full audit trails.

### Phase 2 — correlated detection

1. Add behavioral rules for retry loops, tool/model drift, repeated denials, anomalous egress, and budget evasion.
2. Add detector health, rule simulation, false-positive feedback, and expiry-bound suppression.

### Phase 3 — continuous assurance

1. Add cross-signal attack campaigns, detection coverage reporting, and compliance evidence export.
2. Add optional redacted analytical enrichment under explicit policy; keep enforcement deterministic and local.

## Release gate

No production security profile is complete until an untrusted tool result and indirect prompt-injection attempt are demonstrably prevented from changing system/developer instructions, authorization, policy, or tool permissions; the blocked attempt must appear as a redacted, scoped, immutable finding in Security Center.
