# Apex Operator UI

Phase 1 browser scaffold for the Apex Agent Control Plane. It is a static React 19 + TypeScript + Vite application with TanStack Router and TanStack Query ready for typed control-plane API clients.

The current overview uses clearly labelled sample records. It does not call an ingest, identity, archive, or control-plane endpoint yet.

## Run locally

```bash
pnpm install
pnpm dev
```

Vite binds to `127.0.0.1:4173` by default. Use `pnpm build` to create the static production bundle.

## Route seam

The shell already reserves routes for overview, AgentGroups, events, findings, evidence, retention, deployment, and settings. Each route has an explicit empty state until an OpenAPI/Protobuf-derived client is connected. Do not put authority, identity, or policy decisions in browser state.

## Safety

- Treat all event content, error details, evidence, and agent-supplied labels as untrusted text.
- Render API text as text, never injected HTML.
- Enforce scope and redaction on the server; the UI is not an authorization boundary.
- Keep the preview data separate from real operational state.
