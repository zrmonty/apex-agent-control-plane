# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access
over stdio or a managed Streamable HTTP revision.

The thin stdio gateway and deterministic local `portfolio.read` path are
implemented. Managed Streamable HTTP mode uses the official MCP server/client
transports, dedicated inbound verification, outbound credentials, live Apex
governance, and the existing certificate-bound event-ingest admission client.
See [`docs/operations/mcp-proxy-live-integrations.md`](../../docs/operations/mcp-proxy-live-integrations.md)
for the deployment contract and recovery guidance.

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

Local mode uses `StaticLocalApex` and `LocalPortfolioAdapter`. Live mode
selects the same seeded read-only portfolio adapter but obtains authorization
and policy metadata from `control-plane-api` and admits metadata-only TOOL
evidence through `event-ingest`. Live mode fails closed when any required
client credential is missing.

When a validated revision sets `ingress.transport` to `streamable-http`, the
entrypoint requires live dependencies, discovers every declared HTTP upstream
before binding, and starts the managed listener only after those checks pass.
Stdio upstreams remain unavailable in this production slice.

## Generated configuration and image checks

The new strict generated runtime consumer is a compiler-boundary component.
Production startup migration and runtime enforcement remain in progress; its
manifest checksum is not proof of publication or deployment authorization.

The contract tests require the actual Rust exporter artifact, not a copied
handwritten fixture. Run `cargo test -p apex-control-plane-api --test
export_runtime_fixture -- --nocapture` from the repository root and set
`APEX_RUNTIME_FIXTURE_PATH` to its printed absolute artifact path before running
gateway tests. CI collects that same generated file from its dedicated test
temporary directory and transfers it from the Rust job to the gateway job.
Missing or ambiguous artifacts fail the check.

Build the image from the repository root:

```powershell
docker build -f apps/mcp-gateway/Dockerfile -t apex-mcp-gateway:working-test .
```

The image packages the generated JavaScript contracts and live gRPC schemas.
This packaging check alone does not certify startup readiness, host egress
enforcement, or a working deployed proxy.
