# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access over stdio.

The thin stdio gateway and deterministic local `portfolio.read` path are implemented. Live mode uses a dedicated mTLS/bearer governance client and the existing certificate-bound event-ingest admission client.

## Behavior

- Exposes exactly one MCP tool: `portfolio.read`
- Parses strict input before authorization
- Builds an authorization request from injected authenticated context
- Authorizes before any adapter access
- Verifies the exact-scope policy identity for allowed reads
- Filters seeded sensitive fields before returning structured content
- Uses an opaque, Rust-compatible resource reference in governance requests and events
- Validates durable UUIDv7 event receipts before returning an allowed result
- Emits bounded metadata-only execution events after filtering and before returning

## Local usage

1. Copy `.env.example` into your local environment.
2. Build the package with `pnpm build` or a direct TypeScript runner if policy wrappers block `pnpm`.
3. Start the gateway with `pnpm start`.

Local mode uses `StaticLocalApex` and `LocalPortfolioAdapter`. Live mode selects the same seeded read-only portfolio adapter but obtains authorization and policy metadata from `control-plane-api` and admits metadata-only TOOL evidence through `event-ingest`. Live mode fails closed when any required client credential is missing.
