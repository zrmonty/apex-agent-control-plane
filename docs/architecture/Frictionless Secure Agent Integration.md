# Frictionless Secure Agent Integration

**Status:** Accepted  
**Date:** 2026-08-03

## Decision

Apex makes the secure integration path the shortest path.

An operator creates a scoped AgentGroup in the GUI. The operator selects an identity method for the deployment. The SDK performs policy-aware telemetry and control wiring by default.

Agents never receive a broad, long-lived API key. A bootstrap artifact enrolls exactly one workload in exactly one approved scope. The artifact is exchanged for automatically renewed short-lived workload identity. Then the artifact becomes unusable.

## Operator-to-first-trace flow

1. In **Agent Onboarding**, an authorized operator selects workspace, namespace, AgentGroup, environment, classification, approved execution profile, and telemetry retention profile.
2. Apex shows effective policy, tool and egress rules, and a plain-language readiness check before it creates any bootstrap artifact.
3. The operator selects an enrollment method. The operator receives an expiry-bound setup command, generated configuration, or deployment manifest.
4. The agent starts with `apex_sdk`. It obtains or renews workload identity. It runs a signed policy preflight. It emits a health or registration event before work.
5. The GUI shows **Connected**, **Blocked**, or **Needs attention** with one safe remediation. The first successful run opens in Trace Explorer.

The wizard does not ask an application developer to hand-wire mTLS, schema fields, certificate rotation, broker topology, or redaction.

## Enrollment methods

| Environment | Secure method | What the agent stores |
|---|---|---|
| Kubernetes/K3s | SPIRE workload attestation with service account, namespace, pod labels, and image or workload identity. SDK reads the local workload API. | No application credential. Short-lived SVID only. |
| Container, VM, or bare metal | One-time enrollment code binds a generated workload public key to scope and execution profile. Server exchanges it for short-lived mTLS identity and a renewal channel. | Private key in OS or container secret store. Short-lived certificate only. |
| Local developer machine | Explicit `local-development` profile issues a tightly scoped, short-lived development identity. | Local OS secret-store entry. No production namespace access. |
| Enterprise workload identity | Validated OIDC workload-token exchange to the same short-lived Apex mTLS identity. | Existing provider token only. No Apex long-lived secret. |

Bootstrap codes are single-use, hashed at rest, scope-bound, time-bound (default 10 minutes), and audited. They cannot grant owner or admin privileges, change scope, or authorize tool egress.

An operator can revoke one identity or all identities in an AgentGroup from the GUI. Renewal then stops. New admissions are denied.

## SDK experience

The SDK works without a framework. Adapters for common runtimes can be added later. The target public API is small:

```python
from apex_sdk import Apex

apex = Apex.connect()  # discovers generated config and workload identity

with apex.run("customer-support"):
    result = apex.model.complete(messages)
    answer = apex.tool("knowledge_search").call(query=result.query)
```

This is a target API. It is not a claim that every name is implemented today.

The SDK must:

- Discover only generated non-secret configuration or injected secret references.
- Verify server identity and trust bundle before connect.
- Renew short-lived identity automatically. Never place identity material in logs, events, diagnostics, or browser-visible configuration.
- Validate scope, schema, payload limits, and classification locally before queueing.
- Emit lifecycle, model, tool, decision, error, and cost metadata automatically.
- Wrap approved tools so identity, egress, timeout, resource, and content rules apply consistently.
- Return typed, safe errors with a deep-linkable remediation code.

Low-level envelope APIs remain available for custom runtimes. They are not required for ordinary integration.

## Generated integration bundle

The onboarding wizard produces an `apex-agent.yaml` bundle. Where relevant, it also produces a Kubernetes manifest or Helm values fragment.

The bundle contains only:

- Endpoint and trust-bundle references
- Immutable scope and AgentGroup reference
- Selected profile revisions
- Identity socket or secret reference
- Bounded queue and safe-degradation settings

Apex signs the bundle. The SDK verifies the signature. The bundle contains no private credential material. Deployment-specific values stay in the platform secret or config mechanism.

Lab install today creates the signing authority and trust pack. See [Getting started](../getting-started.md) and [deploy/lab/README.md](../../deploy/lab/README.md).

## Secure defaults without busywork

| Developer need | Default behavior | Security benefit |
|---|---|---|
| Get connected | Auto-discover generated config and workload identity. Preflight at startup. | Removes copied endpoints, scopes, and static tokens. |
| Emit telemetry | Context manager, decorator, and adapters create complete hashed envelopes. | No hand-built trace IDs or inconsistent events. |
| Call a tool | Named registry wrapper checks version, identity, egress, classification, and limits. | Prevents ungoverned tool calls. |
| Handle failure | Typed error includes safe remediation code and correlation IDs. | Faster repair without prompt or secret disclosure. |
| Run locally | Explicit short-expiry local profile with no production scope. | Prevents development bypasses from reaching production. |
| Change access | Operator changes AgentGroup or policy once. Agent receives it on renewal. | No redeploy to rotate a token or narrow access. |

## Preflight and readiness contract

`connect()` verifies identity, TLS trust, scope admission, policy revision, required event-sink health, execution-profile compatibility, and time skew. It returns:

```text
ready       identity and required controls are valid
degraded    allowed only by declared policy; reason and expiry are explicit
blocked     work must not start; safe remediation is provided
```

Production and strict profiles fail closed when mandatory identity, policy, telemetry, or archive prerequisites cannot be met.

Local development can use bounded best-effort telemetry only after explicit profile selection. The local profile is visibly marked. It cannot impersonate production readiness.

## Roadmap and acceptance criteria

### Phase 0

1. Define signed bundle, one-time enrollment, workload identity exchange, renewal, revocation, and typed preflight errors.
2. Implement `Apex.connect()` config discovery, trust validation, scope and policy preflight, automatic lifecycle and error instrumentation, and bounded offline behavior.
3. Prove a reference agent reaches a secure first trace without manual envelope assembly.
4. Add negative tests for expired or reused bootstrap code, scope mismatch, copied bundle, untrusted endpoint, renewal failure, revoked identity, and secret or log leakage.

### Phase 1 and later

Build Agent Onboarding, generated manifests, readiness and remediation UI, one-click revocation, tool wrappers, framework adapters, and an integration doctor.

Acceptance requires a developer to connect a reference agent to a local profile and see a scoped first trace in under 10 minutes with generated setup material only. Kubernetes workloads require no static Apex credential. No default path asks a developer to disable TLS, redact manually, use an admin credential, or select a security-sensitive telemetry field.

Writing style: [ASD-STE100](../writing-style-ste100.md).
