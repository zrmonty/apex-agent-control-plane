# Supporting Tool Decisions

**Status:** Proposed phased additions  
**Date:** 2026-08-03

Add tools only when they reduce risk or operator work more than they add operational burden.

Apex remains functional without managed SaaS. Apex does not replace its own control, audit, telemetry, or security semantics with a third-party tool.

| Tool | Decision | Value to Apex | When |
|---|---|---|---|
| **Valkey** | Adopt as optional acceleration layer. | Rate limits, attack counters, redacted cache, realtime fan-out. | Phase 0. See [Valkey plan](Valkey%20Acceleration%20Layer.md). |
| **Trivy** | Adopt in CI and release pipeline. | Filesystem, image, and SBOM vulnerability and license scanning. Trivy can scan SPDX and CycloneDX SBOMs. [Trivy](https://trivy.dev/docs/latest/guide/target/sbom/) | Phase 0. |
| **Cosign** | Adopt in CI and release pipeline. | Sign and verify container images, artifacts, and attestations. Supports identity-based signing and SBOM attachment. [Cosign](https://docs.sigstore.dev/cosign/signing/signing_with_containers/) | Phase 0. |
| **OpenTelemetry Collector** | Optional interoperability deployment. | Vendor-neutral receive, process, and export boundary for external telemetry ecosystems. Apex contracts remain canonical. [Collector](https://opentelemetry.io/docs/collector/) | Phase 1. |
| **OpenBao** | Optional production secrets and PKI provider. | Identity-based secrets, encryption, leases, renewal, and revocation for customers without an approved secret manager. [OpenBao](https://openbao.org/docs/what-is-openbao/) | Phase 1. |
| **Kyverno** | Optional Kubernetes admission profile. | Validates secure Kubernetes resources, verifies images, and supports policy-as-code with exceptions. [Kyverno](https://kyverno.io/docs/introduction/) | Phase 2 or regulated Kubernetes profile. |
| **Cilium** | Optional Kubernetes network-security profile. | Default-deny, identity-aware ingress and egress enforcement for tool and service isolation. [Cilium policy](https://docs.cilium.io/en/stable/security/policy/) | Phase 2 or production Kubernetes profile. |
| **Falco** | Optional runtime-detection profile. | Detects suspicious host, container, or Kubernetes activity, including unexpected process execution, privilege escalation, and network behavior. [Falco](https://falco.org/docs/) | Phase 3 or high-regulation profile. |

## Explicit non-additions for now

- No second durable broker. JetStream owns durable events and replay.
- No second transactional database. PostgreSQL owns control state.
- No generic policy engine until Apex scoped policy semantics require an external evaluator. Avoid duplicate authorization authority.
- No SIEM requirement. Security Center emits redacted integration events. The product remains useful without a SIEM.
- No mandatory service mesh, hosted cache, hosted secrets manager, or managed observability provider.

Writing style: [ASD-STE100 Simplified Technical English](../writing-style-ste100.md).
