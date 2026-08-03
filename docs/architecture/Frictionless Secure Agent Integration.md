# Frictionless Secure Agent Integration

**Status:** Accepted  
**Date:** 2026-08-03

## Decision

Apex makes the secure integration path the shortest path: an operator creates a scoped AgentGroup in the GUI, selects an identity method appropriate to the deployment, and the SDK performs policy-aware telemetry and control wiring by default.

Agents never receive a broad, long-lived API key. A bootstrap artifact can enroll exactly one workload in exactly one approved scope; it is exchanged for automatically renewed short-lived workload identity and then becomes unusable.

## The five-minute operator-to-first-trace flow

1. In **Agent Onboarding**, an authorized operator selects workspace, namespace, AgentGroup, environment, classification, approved execution profile, and telemetry retention profile.
2. Apex displays effective policy, tool/egress rules, and a plain-language readiness check before creating any bootstrap artifact.
3. The operator selects an enrollment method and receives an expiry-bound setup command, generated configuration, or deployment manifest.
4. The agent starts with `apex_sdk`; it obtains/renews workload identity, runs a signed policy preflight, and emits a health/registration event before doing work.
5. The GUI shows **Connected**, **Blocked**, or **Needs attention** with one safe remediation. The first successful run opens directly in Trace Explorer.

The wizard does not ask an application developer to hand-wire mTLS, schema fields, certificate rotation, broker topology, or redaction.

## Enrollment methods

| Environment | Secure frictionless method | What the agent stores |
|---|---|---|
| Kubernetes/K3s | SPIRE workload attestation using service account, namespace, pod labels, and image/workload identity; SDK reads the local workload API. | No application credential; short-lived SVID only. |
| Container, VM, or bare metal | One-time enrollment code binds a generated workload public key to the selected scope and execution profile. The server exchanges it for short-lived mTLS identity and a renewal channel. | Private key in OS/container secret store; short-lived certificate only. |
| Local developer machine | Explicit `local-development` profile issues a tightly scoped, short-lived development identity. | Local OS secret-store entry; no production namespace access. |
| Enterprise workload identity | Validated OIDC workload-token exchange to the same short-lived Apex mTLS identity. | Existing provider token only; no Apex long-lived secret. |

Bootstrap codes are single-use, hashed at rest, scope-bound, time-bound (default 10 minutes), and audited. They cannot grant owner/admin privileges, change scope, or authorize tool egress. An operator can revoke an identity or all identities in an AgentGroup from the GUI; renewal then stops and new admissions are denied.

## SDK experience

The SDK works without a framework and adds adapters for common runtimes later. The target public API is intentionally small:

```python
from apex_sdk import Apex

apex = Apex.connect()  # discovers generated config and workload identity

with apex.run("customer-support"):
    result = apex.model.complete(messages)
    answer = apex.tool("knowledge_search").call(query=result.query)
```

This is a target API, not a claim that these exact names are implemented today. It must:

- discover only generated non-secret configuration or injected secret references;
- verify server identity and trust bundle before connecting;
- renew short-lived identity automatically and never place it in logs, events, diagnostics, or browser-visible configuration;
- validate scope, schema, payload limits, and classification locally before queueing;
- emit lifecycle, model, tool, decision, error, and cost metadata automatically;
- wrap approved tools so identity, egress, timeout, resource, and content rules are applied consistently;
- return typed, safe errors with a deep-linkable remediation code instead of generic connection failures.

Low-level envelope APIs remain available for custom runtimes but are not required for ordinary integration.

## Generated integration bundle

The onboarding wizard produces an `apex-agent.yaml` bundle and, where relevant, a Kubernetes manifest/Helm values fragment. It contains only the endpoint/trust-bundle reference, immutable scope/AgentGroup reference, selected profile revisions, identity socket or secret reference, and bounded queue/safe-degradation settings.

The bundle is signed by Apex and verified by the SDK. It contains no private credential material. Deployment-specific values remain in the platform's secret/config mechanism.

## Secure defaults without busywork

| Developer need | Default behavior | Security benefit |
|---|---|---|
| Get connected | Auto-discover generated config and workload identity; preflight at startup. | Eliminates copied endpoints, scopes, and static tokens. |
| Emit telemetry | Context manager/decorator and adapters create complete hashed envelopes. | No hand-built trace IDs or inconsistent events. |
| Call a tool | Named registry wrapper checks version, identity, egress, classification, and limits. | Prevents ungoverned tool calls. |
| Handle failure | Typed error includes safe remediation code and correlation IDs. | Faster repair without prompt/secret disclosure. |
| Run locally | Explicit short-expiry local profile with no production scope. | Prevents development bypasses reaching production. |
| Change access | Operator changes AgentGroup/policy once; agent receives it on renewal. | No redeploy to rotate a token or narrow access. |

## Preflight and readiness contract

`connect()` verifies identity, TLS trust, scope admission, policy revision, required event-sink health, execution-profile compatibility, and time skew. It returns:

```text
ready       identity and required controls are valid
degraded    allowed only by declared policy; reason and expiry are explicit
blocked     work must not start; safe remediation is provided
```

Production/strict profiles fail closed when mandatory identity, policy, telemetry, or archive prerequisites cannot be met. Local development can use bounded best-effort telemetry only after explicit profile selection; it is visibly marked and cannot impersonate production readiness.

## Roadmap and acceptance criteria

### Phase 0

1. Define signed bundle, one-time enrollment, workload identity exchange/renewal/revocation, and typed preflight errors.
2. Implement `Apex.connect()` config discovery, trust validation, scope/policy preflight, automatic lifecycle/error instrumentation, and bounded offline behavior.
3. Prove a reference agent reaches a secure first trace without manually assembling an envelope.
4. Add negative tests for expired/reused bootstrap code, scope mismatch, copied bundle, untrusted endpoint, renewal failure, revoked identity, and secret/log leakage.

### Phase 1+

Build Agent Onboarding, generated manifests, readiness/remediation UI, one-click revocation, tool wrappers, framework adapters, and an integration doctor.

Acceptance requires a developer to connect a reference agent to a local profile and see a scoped first trace in under 10 minutes using generated setup material only. Kubernetes workloads require no static Apex credential. No default path asks a developer to disable TLS, redact manually, use an admin credential, or select a security-sensitive telemetry field.
