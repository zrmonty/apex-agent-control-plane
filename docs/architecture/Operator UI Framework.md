# Operator UI Framework Decision

**Status:** Accepted  
**Date:** 2026-08-03

## Decision

Build `apps/operator-ui` as a **React 19 + TypeScript + Vite** single-page application (SPA), managed with `pnpm`.

Use:

- **TanStack Router** with file-based routes for typed path/search parameters and explicit scope-aware navigation.
- **TanStack Query** for remote data, invalidation, optimistic mutation, and cache lifecycle.
- **Typed API clients generated from the versioned Apex OpenAPI/Protobuf contracts.** UI code does not define an alternate source of API truth.
- **Accessible, unstyled component primitives** plus project-owned semantic design tokens. A pre-styled design-system dependency is not the visual authority.
- **CSS variables and token-backed utilities** for theme, density, high-contrast support, and clear visual hierarchy.
- **Browser-native SSE or WebSocket clients** for scoped real-time operational updates, with reconnect/backoff and explicit stale/offline state.

## Why this fits Apex

The operator console is an authenticated, information-dense operational application: Fleet Canvas, Trace Explorer, Policy Studio, Compliance Center, Evaluation Lab, Cost Lens, and incident workflows. It needs fast navigation, rich filtering, virtualized data views, keyboard interaction, live state, and a stable design system—not search-engine rendering or a second server runtime.

Vite supports a first-party React/TypeScript template and produces static production assets. React 19 is the current major release. TanStack Router provides type-safe route definitions and TanStack Query supports React 18+ server-state management. [Vite](https://vite.dev/guide/), [React versions](https://react.dev/versions), [TanStack Router type safety](https://tanstack.com/router/latest/docs/guide/type-safety), [TanStack Query](https://tanstack.com/query/latest/docs/framework/react/installation)

## Deployment boundary

```text
Browser
  ├─ static Apex UI assets (Vite build)
  └─ HTTPS to control-plane edge
       ├─ OIDC/BFF session boundary
       ├─ REST/gRPC-web/SSE endpoints
       └─ Rust control-plane services
```

- Build assets once; serve them from the Rust edge, Caddy/Nginx, or any static object/filesystem server.
- Use path-based browser routing when the serving edge supports the normal SPA fallback. A hash-router fallback is permitted for constrained self-hosted environments.
- Do not make a Node.js runtime, Vercel-like host, or any managed frontend service a production requirement.
- Keep tokens out of browser storage. The control-plane edge owns OIDC Authorization Code + PKCE and secure, HTTP-only session cookies.

## Security and quality baseline

- Strict TypeScript, ESLint, and generated-client compatibility checks are release gates.
- Content from agents, tools, traces, errors, and diagnostic bundles is untrusted: render as text; never inject raw HTML or executable URLs.
- Use a restrictive content-security policy, anti-framing protection, CSRF defenses for cookie-backed mutations, and no-store responses for sensitive views.
- Apply server-side authorization and redaction before rendering; client-side route guards improve UX but never grant access.
- Test with Vitest + Testing Library, Playwright end-to-end tests, and automated accessibility checks. Include keyboard, high-contrast, narrow-screen, long-data, error, offline, and permission-denied paths.

## Explicit non-decisions

- No application-wide client state store is selected. Add one only for proven shared ephemeral UI state; it must not become an API cache or authorization source.
- No chart, grid, form, or component library is selected yet. Select each behind a small adapter after the first operator surface proves its needs, license, keyboard behavior, bundle impact, and CSP compatibility.
- No visual world is selected in this decision. That is established with the first concrete operator surface and recorded in `DESIGN.md`.

## Consequences

This is a strong default for a self-hosted control plane: it minimizes runtime infrastructure, keeps the backend and frontend independently deployable, and gives the application mature typed routing and query primitives. The trade-off is that server-side rendering is not a default feature. If a future public documentation or marketing surface needs SEO/SSR, it should be a separate surface rather than changing the authenticated operator console's architecture.
