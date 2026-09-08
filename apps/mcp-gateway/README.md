# Apex MCP Gateway

Thin TypeScript MCP gateway for governed, read-only `portfolio.read` access
over stdio or a managed Streamable HTTP revision.

The deterministic local `portfolio.read` development path is implemented.
Managed HTTP components use the official MCP transports, separate inbound and
outbound credentials, Apex governance and certificate-bound event admission.
The managed executable now owns the sealed-stage runtime, guarded outbound
clients, admission/readiness checks, authenticated health and HTTPS ingress.
It starts only from the agent's protected isolated-network handoff and does not
admit business calls until current SERVE authority and readiness are both valid.
Signed deployment, controller lifecycle and complete trace/UI acceptance remain
open; a verified component runtime is not yet a production-ready deployed app.
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

1. Export the development settings in `.env.example` into your local environment;
   copying a file alone does not load it into the Node process.
2. Build the package with `pnpm build`.
3. Start the gateway with `pnpm start`.

Standalone requires both exact selectors `NODE_ENV=development` and
`APEX_MCP_PROFILE=development-standalone`, with both
`APEX_MCP_PROXY_REVISION_CONFIG` and `APEX_MCP_PROXY_REVISION_CONFIG_FILE`
absent (even an empty supplied value is rejected). Managed stage, installation,
network and listen-override metadata are also forbidden in standalone. The default profile is
`managed`; setting only `NODE_ENV=development` does not enable standalone.

Local mode uses `StaticLocalApex` and `LocalPortfolioAdapter`. Live mode
selects the same seeded read-only portfolio adapter but obtains authorization
and policy metadata from `control-plane-api` and admits metadata-only TOOL
evidence through `event-ingest`. Live mode fails closed when any required
client credential is missing.

Managed startup requires the exact agent-owned `sealed-stage-v2` environment,
including `APEX_MCP_GOVERNANCE_MODE=live`, the `isolated-bridge-v1` network binding,
and fixed `/apex/runtime` paths. The OS reader verifies the complete bounded,
read-only stage, its ownership and manifest before runtime construction. Caller
identity env, legacy configuration-file/inline selectors, arbitrary listen paths
and ambient transport overrides are rejected. The legacy metadata-only factory
remains a refusal-only component; the executable no longer calls it.
Health listens only at `127.0.0.1:8081`; HTTPS binds the sealed gateway address
at port 8080. PREPARE performs nine checks without accepting business sessions.
SIGINT/SIGTERM await actual resource closure and completion handoff. Unresolved
completion returns a failure requiring reconciliation; fatal unproved cleanup
terminates the process rather than pretending a timer proved physical closure.
Managed stdio/CLI remain disabled. Do not use the development path as a
production fallback.

The legacy Compose overlay explicitly selects managed/live and has its old
always-success healthcheck disabled. It is a bootstrap/startup-refusal fixture,
not a ready deployment. Authenticated health and guarded runtime composition
have passed an unsigned isolated component fixture; the legacy overlay does not
provide the new protected stage. A disabled healthcheck does not establish readiness.

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
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-test --suite startup
```

The packaging suite loads actual generated contracts and live gRPC descriptors,
rejects compiled test/fixture artifacts and embedded private-key markers in
the app dist tree, and verifies confinement and exact owned-container cleanup.
It uses UID 10001, a read-only filesystem and no network. It is not a whole-image
secret audit. Missing Docker, failed inspection or unconfirmed cleanup fails.
The suite explicitly reports `readinessVerified: false`: it does not certify
startup readiness, host egress enforcement or a working deployed proxy.

The startup suite runs the original image entrypoint through eight fixed
profile/configuration cases. Explicit development cases supply valid fixture
identity; managed cases omit legacy caller identity so its rejection cannot
mask a missing-stage/profile refusal.
It verifies process exit, confinement and owned cleanup, including explicit
development startup with closed stdin. It does not perform an image-level MCP
handshake or configured managed-health check; both corresponding report flags
remain false. Source tests separately exercise real SDK initialization/listing.
