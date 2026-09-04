# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access over stdio.

The thin stdio gateway and deterministic local `portfolio.read` path are implemented. This package remains local/test-only today: live Apex authorization and event clients plus the operator-visible end-to-end vertical slice are deferred to later active tasks.

## Behavior

- Exposes exactly one MCP tool: `portfolio.read`
- Parses strict input before authorization
- Builds an authorization request from injected authenticated context
- Authorizes before any adapter access
- Verifies the exact-scope policy identity for allowed reads
- Filters seeded sensitive fields before returning structured content
- Emits metadata-only execution events after filtering and before returning

## Local usage

1. Copy `.env.example` into your local environment.
2. Build the package with `pnpm build` or a direct TypeScript runner if policy wrappers block `pnpm`.
3. Start the gateway with `pnpm start`.

The current wiring is local/test-only: `StaticLocalApex` and `LocalPortfolioAdapter` are the only active execution path today. `StaticLocalApex` provides fixed local governance/event behavior and `LocalPortfolioAdapter` serves the seeded `northstar-401k` portfolio snapshot. Live Apex governance and event clients, plus the operator-visible end-to-end slice, are deferred to later active tasks.
