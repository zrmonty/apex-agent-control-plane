# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access over stdio.

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

The current wiring is local/test-only: `StaticLocalApex` and `LocalPortfolioAdapter` are the only active execution path today. Live Apex governance and event clients are deferred to a later task. `StaticLocalApex` provides fixed local governance/event behavior and `LocalPortfolioAdapter` serves the seeded `northstar-401k` portfolio snapshot.
