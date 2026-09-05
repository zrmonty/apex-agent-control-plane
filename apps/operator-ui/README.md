# Apex Operator UI

Browser console for the Apex Agent Control Plane. It is a React 19 + TypeScript + Vite application with TanStack Router and TanStack Query, and a typed `@apex/contracts` client generated from the Protobuf contracts.

Only the `MCP proxies` routes call a backend. They talk to the optional loopback browser edge that the `control-plane-api` binary can serve: `GET /api/session`, `POST /auth/logout`, and `McpProxyService` management calls with a cookie session and a CSRF token. That browser edge is a development checkpoint (Keycloak login, PostgreSQL-backed sessions), not a published production surface. See [docs/operations/mcp-browser-edge.md](../../docs/operations/mcp-browser-edge.md).

The root route redirects to `/mcp-proxies`. Every other route (agent groups, events, findings, evidence, retention, deployment, settings) is a placeholder with an explicit empty state and calls nothing. UI work outside the `MCP proxies` surface is on hold per [docs/roadmap.md](../../docs/roadmap.md).

## Run locally

```bash
pnpm install
pnpm dev
```

Vite binds to `127.0.0.1:4173` by default. Without a backend, the `MCP proxies` routes show their unauthenticated state.

To use a real backend, run `control-plane-api` with its browser edge enabled (`APEX_CONTROL_BROWSER_BIND_ADDR` and `APEX_CONTROL_BROWSER_CONFIG_FILE`; Postgres and Keycloak are required) and set `APEX_UI_BROWSER_EDGE=http://127.0.0.1:<port>` before `pnpm dev`. The dev server then proxies `/api` and `/auth` to that origin. It does not rewrite `Origin`, redirects, or cookies, so the Rust edge's origin, session, and CSRF checks still apply. The value must be an explicit loopback `http://127.0.0.1:port` origin or Vite refuses to start.

Other commands:

```bash
pnpm test        # vitest
pnpm typecheck
pnpm build       # typecheck + static production bundle
pnpm audit       # not in CI; run manually for dependency CVEs
```

## Routes

| Route | State |
|---|---|
| `/mcp-proxies` | Live list over `McpProxyService` |
| `/mcp-proxies/new` | Live guided creation wizard |
| `/mcp-proxies/$proxyId` | Live detail view |
| `/mcp-proxies/$proxyId/activity` | Live activity view |
| `/` | Redirects to `/mcp-proxies` |
| `/agents`, `/events`, `/findings`, `/evidence`, `/retention`, `/deployment`, `/settings` | Placeholder with empty state, no backend calls |

Do not put authority, identity, or policy decisions in browser state. The session object held in memory is display context only; the server decides what a caller may do.

## Safety

- Treat all event content, error details, evidence, proxy names, and agent-supplied labels as untrusted text.
- Render API text as text, never injected HTML.
- Enforce scope and redaction on the server; the UI is not an authorization boundary.
- Keep any sample or fixture data separate from real operational state.
