# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Delegated decision: **React 19 + TypeScript + Vite** for the operator UI.

The console is a static single-page application. Serve it with the Rust control-plane edge or serve it separately. Use TanStack Router for typed, file-based routes. Use TanStack Query for server state.

The production UI does not need a Node.js server, React Server Components, or a managed frontend host.

Use `pnpm` for JavaScript packages. Keep browser state small and local. Put server state in TanStack Query. Put authoritative state in the control-plane API.

Use accessible, unstyled primitives and project design tokens. Do not use a pre-styled component suite as the system of record. Use OpenAPI/Protobuf-derived TypeScript clients. Do not hand-maintain a second API type system.

## Users

- Platform owners who configure installation-wide identity, security, archive, retention, and policy.
- Administrators and AI engineers who operate AgentGroups, build evaluation flows, manage integrations, and investigate incidents.
- Operators who need a fast visual view of fleet health, runs, failures, and remediation.
- Compliance reviewers and auditors who need read access to evidence, annotations, policy posture, retention, and scoped exports.
- Finance and engineering users who need cost attribution, budgets, and cost decisions.

## Product purpose

Apex is a self-hosted, cloud-agnostic control plane for AI agents. It makes agent activity observable, governable, evaluable, diagnosable, and financially accountable. It runs on local, on-premises, and cloud systems.

Success means a company can operate a growing agent fleet through a clear GUI and API. The company keeps least privilege, audit evidence, durable records, and useful cost controls.

## Positioning

Apex joins an event-first agent control plane with Kubernetes-style scope, deep diagnostics, policy enforcement, regulated-deployment evidence, immutable archive adapters, visual operations, and agent FinOps. It does not require a proprietary hosted control plane.

## Operating context

Users work in this hierarchy: installation, workspace, namespace, AgentGroup, agent, and run.

They use a browser console and audited APIs. They inspect turns, model calls, tool calls, decisions, memory activity, workflow topology, evaluations, incidents, policy changes, archive state, and cost.

Deployments must support a single-host local profile and a high-availability Kubernetes profile without a contract rewrite. Organizations can self-host identity. They can connect local accounts, LDAP/AD, Google Workspace, Microsoft Entra ID, or other OIDC/SAML providers.

## Capabilities and constraints

- Rust services ingest versioned Protobuf events over gRPC. They use durable event processing.
- Mutable control state, analytical trace storage, and immutable archive storage are separate. They use portable provider contracts.
- Scope model: installation → workspace → namespace → AgentGroup → agent → run. Scope is mandatory for production events.
- One installation owner exists. Built-in and custom roles use atomic permissions. Roles are bounded by scope and delegation.
- The GUI must be accessible, keyboard-operable, high-contrast capable, and safe when it shows untrusted content.
- Deep error reports are append-only and correlated. They are redacted by default. They can form a user-approved safe diagnostic bundle for AI-assisted troubleshooting.
- Cost Lens separates actual, reconciled, estimated, allocated, and forecast cost. It covers model, tool, evaluation, infrastructure, and data-lifecycle cost.
- Deployment must stay cloud-agnostic and economical for self-hosting. A mandatory managed SaaS dependency is not acceptable.
- Archive providers must prove retention, legal hold, retrieval, and verification before strict records profiles are enabled.
- Raw payment-card data is out of scope for the first release.

## Brand commitments

- Product name: **Apex Agent Control Plane**.
- Voice: clear, calm, precise, and operational. No hype. No invented compliance claims.
- The interface must make advanced controls usable for ordinary company users without weaker security.

## Evidence on hand

- Confirmed product requirements are in this repository `README.md`.
- No customer logos, testimonials, benchmarks, pricing claims, or visual identity assets are provided. Do not invent them.
- No frontend implementation or incumbent visual system exists yet.

## Product principles

1. Use secure defaults. Give enough guidance that least-privilege operation stays practical.
2. Keep every important action scoped, traceable, and explainable.
3. Treat local and self-hosted deployments as first-class. Scale is configuration, not a rewrite.
4. Use visual workflows to clarify complex systems and lead to safe action.
5. Keep cost information useful and truthful. Do not hide allocation. Do not invent unsupported predictions.

## Accessibility and inclusion

The operator console must support:

- Keyboard navigation
- Text and table alternatives for charts and topology
- Clear focus states
- Semantic labels
- Configurable density
- High-contrast operation
- Server-side redaction based on viewer scope and permissions

## Documentation style

Write product documentation in [ASD-STE100 Simplified Technical English](docs/writing-style-ste100.md).
