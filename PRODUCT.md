# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated decision: **React 19 + TypeScript + Vite** for the operator UI. The console is a static single-page application served separately from, or by, the Rust control-plane edge. It uses TanStack Router for typed, file-based routes and TanStack Query for server state. The production UI does not require a Node.js server, React Server Components, or a managed frontend host.

Use `pnpm` for JavaScript package management. Keep browser state minimal and local; server state belongs in TanStack Query and authoritative state belongs in the control-plane API. Use accessible, unstyled primitives and project-owned design tokens rather than a pre-styled component suite. Use OpenAPI/Protobuf-derived TypeScript clients; do not hand-maintain a second API type system.

## Users

- Platform owners who configure installation-wide identity, security, archive, retention, and policy controls.
- Administrators and AI engineers who operate AgentGroups, create visual evaluation flows, manage approved integrations, and investigate incidents.
- Operators who need a fast, visual view of fleet health, runs, failures, and remediation actions.
- Compliance reviewers and auditors who need read-oriented access to evidence, annotations, policy posture, retention, and scoped exports.
- Finance and engineering users who need accountable cost attribution, budgets, and operational cost decisions.

## Product Purpose

Apex is a self-hosted, cloud-agnostic control plane for operating AI agents safely at scale. It makes agent activity observable, governable, evaluable, diagnosable, and financially accountable across local, on-premises, and cloud deployments.

Success means a company can operate a growing fleet of agents through a clear GUI and API while maintaining least privilege, evidence-quality auditability, durable records, and actionable cost controls.

## Positioning

Apex joins an event-first agent runtime control plane with Kubernetes-style scope, deep diagnostics, policy enforcement, regulated-deployment evidence, immutable archive adapters, visual operations, and agent-specific FinOps. It does not require a proprietary hosted control plane.

## Operating Context

Users operate in an installation, workspace, namespace, AgentGroup, agent, and run hierarchy. They use a browser-based operator console and audited APIs to inspect agent turns, model calls, tool calls, decisions, memory activity, workflow topology, evaluations, incidents, policy changes, archive state, and cost.

Deployments must support a single-host local profile and a high-availability Kubernetes profile without a contract or data-model rewrite. Organizations may self-host identity and connect it to local accounts, LDAP/AD, Google Workspace, Microsoft Entra ID, or other OIDC/SAML providers.

## Capabilities and Constraints

- Rust services ingest versioned Protobuf events over gRPC and use durable event processing.
- Mutable control state, analytical trace storage, and immutable/WORM archive storage are separate concerns behind portable provider contracts.
- The scope model is installation → workspace → namespace → AgentGroup → agent → run. Scope is mandatory for production events.
- A single installation owner exists; built-in and administrator-defined custom roles are composed from atomic permissions and bounded by scope and delegation.
- The GUI must be accessible, keyboard-operable, high-contrast capable, and safe when displaying untrusted agent, tool, trace, and diagnostic content.
- Deep error reports are append-only, correlated, redacted by default, and can form a user-approved safe diagnostic bundle for AI-assisted troubleshooting.
- Cost Lens distinguishes actual, reconciled, estimated, allocated, and forecast cost. It covers model/provider, tool/API, evaluation, infrastructure, and data-lifecycle cost.
- Deployment must remain cloud-agnostic and economical for self-hosting. A mandatory managed SaaS dependency is not acceptable.
- Archive providers must prove retention, legal hold, retrieval, and verification capabilities before strict records profiles are enabled.
- Raw payment-card data is out of scope for the initial release.

## Brand Commitments

- Product name: **Apex Agent Control Plane**.
- Voice: clear, calm, precise, and operational; no hype or invented compliance claims.
- The interface must make advanced controls approachable for ordinary company users without weakening security.

## Evidence on Hand

- Confirmed product requirements are captured in this repository's `README.md`.
- No customer logos, testimonials, benchmarks, pricing claims, or visual identity assets have been provided. Do not fabricate any of them.
- No frontend implementation or incumbent visual system exists yet.

## Product Principles

1. Secure defaults, with enough guidance that least-privilege operation remains practical.
2. Every important action is scoped, traceable, and explainable.
3. Local and self-hosted deployments are first-class; scale is an operational configuration, not a rewrite.
4. Visual workflows should clarify complex systems and lead directly to safe action.
5. Cost information must be useful and truthful, never a hidden allocation or unsupported prediction.

## Accessibility & Inclusion

The operator console must support keyboard navigation, text/table alternatives for charts and topology, clear focus states, semantic labels, configurable density, high-contrast operation, and server-side redaction based on the viewer's scope and permissions.
