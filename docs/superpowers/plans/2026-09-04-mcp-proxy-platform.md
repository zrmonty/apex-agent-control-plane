# Managed MCP Proxy Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a governed MCP proxy platform where operators create and manage multiple proxies, with one hardened OCI container per logical proxy.

**Architecture:** Extend the existing Apex control plane with a versioned proxy resource contract, durable desired state, immutable revisions, and an idempotent runtime reconciler. Keep the TypeScript MCP gateway as the proxy data-plane seed, add per-proxy transport/auth/CLI boundaries, and add the focused MCP proxy surface to the existing React operator UI.

**Tech Stack:** Rust 2024, tonic/Protobuf, PostgreSQL control state, existing Apex outbox and policy crates, TypeScript/Node.js 24, `@modelcontextprotocol/sdk` 1.x compatibility, React 19, Vite, TanStack Router/Query, Docker/OCI, mTLS, OAuth/OIDC, OpenTelemetry, Vitest/Testing Library, Playwright, and the existing live Compose proof.

**Spec:** `docs/superpowers/specs/2026-09-04-mcp-proxy-platform-design.md`

## Global Constraints

- Runtime isolation: one hardened OCI container per logical proxy.
- Apex remains the only policy and durable evidence authority.
- The browser requests and displays state; it never owns policy, identity, secrets, or deployment authority.
- Secret values never enter control state, browser state, events, logs, errors, or diagnostic bundles.
- CLI tools use fixed profiles with typed argv; arbitrary shell execution is prohibited.
- Inbound MCP credentials are separate from per-upstream outbound credentials; inbound tokens are never passed through.
- Published revisions are immutable, content-addressed, and rollback-capable.
- The first end-to-end acceptance slice is read-only `portfolio.read`.
- No unrelated dashboards, archive providers, broad workflow orchestration, direct autonomous trade execution, or second MCP governance system is included.
- Every changed source and test file must remain at or below the repository readability limit of 600 lines.

## Execution order

1. `2026-09-04-mcp-proxy-control-plane.md` — contracts, state, validation, lifecycle, and operator API.
2. `2026-09-04-mcp-proxy-runtime-security.md` — isolated runtime, MCP transports, auth, upstreams, CLI profiles, and enforcement.
3. `2026-09-04-mcp-proxy-operator-ui.md` — inventory, large-plus wizard, detail tabs, revisions, and live activity.
4. `2026-09-04-mcp-proxy-integration.md` — Compose provider, live proof, CI gates, performance evidence, and release handoff.

Each subplan produces a testable deliverable and ends with its own commit. Execute the plans in order because the runtime consumes the control-plane revision contract, the UI consumes the generated management client, and integration consumes all three.

## Cross-plan handoffs

The control-plane plan produces:

```text
McpProxy
McpProxyRevision
McpProxyStatus
ProxySpec
ProxyStore
ProxyRuntimeProvider
McpProxyService
```

The runtime plan consumes `ProxySpec` and produces a proxy process that reports readiness, health, revision, and bounded call metadata.

The UI plan consumes generated management operations and produces operator actions that map only to server-authorized mutations.

The integration plan proves that a proxy created through the UI can be validated, deployed, governed, observed, paused, rotated, rolled back, and retired without cross-proxy access.

## Final acceptance gate

Run from the repository root:

```powershell
python scripts/test_check_source_line_limits.py
cargo test --workspace --locked
pnpm --dir apps/mcp-gateway typecheck
pnpm --dir apps/mcp-gateway test
pnpm --dir apps/operator-ui typecheck
pnpm --dir apps/operator-ui test
pnpm --dir apps/operator-ui build
docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.gateway-ref.yaml config
```

Then run the live proxy acceptance script defined by the integration plan. The gate must prove server-derived UI activity, Apex authorization, metadata-only evidence, container isolation, CLI rejection of unsafe input, credential separation, revision rollback, and clean teardown.
