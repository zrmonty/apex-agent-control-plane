# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access
over stdio or a managed Streamable HTTP revision.

The deterministic local `portfolio.read` development path is implemented.
Managed HTTP components use the official MCP transports, separate inbound and
outbound credentials, Apex governance and certificate-bound event admission.
The production managed factory deliberately refuses construction until real
network and admission enforcement are connected; it does not supply permissive
defaults. Component availability is not a working deployed gateway.
See [`docs/operations/mcp-proxy-live-integrations.md`](../../docs/operations/mcp-proxy-live-integrations.md)
for the deployment contract and recovery guidance.

## Existing read-only components

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

Managed startup accepts only a bounded file containing the complete generated
`RuntimeConfiguration`, not the old handwritten revision model or inline JSON.
It checks the generated metadata, executable capabilities and caller scope,
then refuses before secrets, clients, discovery or listeners while enforcement
is unavailable. Managed stdio/CLI remain disabled. Task 6 is also replacing the
old no-config standalone selection with an explicit development-only profile;
do not use the development path as a production fallback.

## Generated configuration and image checks

The strict generated consumer now feeds the complete managed runtime path.
Publication rejects unsupported executable capabilities before mutation.
A manifest checksum still does not prove publication or deployment authority.

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
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-test --suite packaging
```

The packaging suite loads actual generated contracts and live gRPC descriptors,
rejects compiled test/fixture artifacts and embedded private-key markers in
the app dist tree, and verifies confinement and exact owned-container cleanup.
It uses UID 10001, a read-only filesystem and no network. It is not a whole-image
secret audit. Missing Docker, failed inspection or unconfirmed cleanup fails.
The suite explicitly reports `readinessVerified: false`: it does not certify
startup readiness, host egress enforcement or a working deployed proxy.
