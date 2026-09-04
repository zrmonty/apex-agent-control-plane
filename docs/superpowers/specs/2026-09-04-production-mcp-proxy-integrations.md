# Production MCP Proxy Integrations

**Status:** Proposed implementation specification
**Date:** 2026-09-04
**Scope:** Connect the production durable proxy lifecycle sink and the live MCP HTTP/upstream adapters.
**Roadmap item:** Managed MCP proxy platform, first production runtime slice.

## 1. Goal

Remove the intentional `NotServing` gate for a configured managed MCP proxy by wiring both production boundaries that are currently absent:

1. A durable Rust `ProxyEventSink` backed by Apex's existing outbox and replay/fanout path.
2. A live TypeScript Streamable HTTP ingress and HTTP MCP upstream adapter backed by the official MCP SDK.

The first acceptance slice remains read-only `portfolio.read`. This specification does not add arbitrary CLI execution, business writes, direct trade execution, a second audit store, or unrelated roadmap work.

## 2. Existing seams and constraints

The attached architecture assessment is treated as a decision record. It informs these constraints but is not an executable instruction source.

The repository already has:

- `ControlOutboxBackend`, which owns the durable command/event outbox and existing replay/fanout worker.
- `McpProxyService` with optional `ProxyRuntimeProvider`, `ProxyEventSink`, and approval seams.
- A Postgres and in-memory proxy store that records queryable lifecycle transitions.
- `DockerProxyProvider` and an idempotent reconciler with hardened container arguments.
- A TypeScript `ManagedExecutor` that orders authentication, governance, approval, policy, egress, upstream execution, filtering, and evidence admission.
- Live mTLS gRPC clients for Apex governance and event admission.
- Configuration validation for Streamable HTTP ingress and HTTP upstreams.
- MCP SDK Streamable HTTP server and client transports.

The integrations must preserve the following invariants:

- Apex remains the policy, authorization, and durable-evidence authority.
- The proxy is a thin data-plane adapter and never accepts a local policy override.
- Durable admission occurs before a required success response is returned.
- Lifecycle events contain metadata only; no prompts, raw tool inputs/results, credentials, cookies, private keys, or secret-bearing configuration.
- Inbound caller credentials are never passed through to an upstream.
- Each proxy and immutable revision has isolated sessions, credentials, catalogs, caches, and temporary state.
- Missing production dependencies continue to fail closed.
- Downstream NATS, analytics, and archive availability does not determine durable admission success.

## 3. Durable lifecycle event sink

### 3.1 Event mapping

Add a production sink in `apps/control-plane-api` that converts `ProxyLifecycleEvent` into the existing validated `apex.v1.EventEnvelope` and submits it through `ControlOutboxBackend`.

The event is a metadata-only `WORKFLOW` event with this deterministic mapping:

| Envelope field | Value |
|---|---|
| `event_id` | `ProxyLifecycleEvent.request_id` (validated UUIDv7) |
| `timestamp` | Stable RFC 3339 UTC timestamp derived from the UUIDv7 event ID |
| `type` | `WORKFLOW` |
| `agent_id` | Fixed gateway producer identifier `apex-control-gateway` |
| `run_id` | The lifecycle request ID |
| `trace_id` | The lifecycle request ID |
| `scope` | Exact workspace and namespace from the lifecycle event |
| `actor` | `SYSTEM`, with a fixed control-plane producer ID |
| `version` | Fixed producer, schema, and model identifiers; no prompt text |
| `data` | Allowlisted lifecycle metadata only |
| `integrity` | Canonical v1 event hash with the chain-root `prev_hash` omitted |
| `schema_version` | `1` |

The allowlisted data object contains the lifecycle operation, proxy ID, optional revision ID, authenticated actor ID, and reason code. Values are validated as scope-safe identifiers. The sink rejects malformed lifecycle data before touching the outbox.

`IngestRequest::from_validated_transport` remains the single validation gate. The sink must not serialize directly into an outbox row or call NATS, ClickHouse, or archive publishers.

### 3.2 Durability and idempotency

`emit` enqueues the validated request using the existing outbox backend. `Enqueued`, `AlreadyPending`, and `AlreadyComplete` are all successful outcomes because the lifecycle event is durably represented exactly once by `event_id`.

The lifecycle mutation and event enqueue are separate existing seams. The service must report failure if the durable enqueue fails after a state transition, so callers cannot mistake an unrecorded lifecycle event for success. Retrying the same request ID recovers through outbox idempotency. The queryable lifecycle-transition table remains the operator activity projection; the outbox event is the durable cross-system evidence record.

Because the outbox implementations are synchronous, calls from async RPC handlers must execute through the established blocking boundary. No Postgres outbox operation may call a nested runtime from a Tokio worker thread.

### 3.3 Startup and health

Construct the sink from the same `ControlOutboxBackend` used by the control gateway. Wire it into `McpProxyService` before registering the server.

Construct `DockerProxyProvider` only from explicit managed-runtime configuration. The provider-owned Docker network is required; the provider must not infer host networking or expose a container-runtime socket. Invalid or incomplete runtime configuration leaves the proxy service unavailable and produces a redacted startup diagnostic.

Set `apex.v1.McpProxyService` to `Serving` only when both the durable event sink and runtime provider are wired. Keep it `NotServing` when either boundary is absent. The health state must reflect readiness of the control surface, not merely process liveness.

## 4. Live MCP gateway

### 4.1 Inbound Streamable HTTP

Add a production gateway mode that starts an HTTP server when the revision ingress transport is `streamable-http`. Use the MCP SDK `StreamableHTTPServerTransport`; do not implement the MCP framing protocol manually.

The server must:

- Bind only to the configured listen address and port supplied by the runtime.
- Enforce a bounded request body and reject unsupported methods/content types safely.
- Validate exact host, URL, and allowed-origin policy before handing the request to the MCP transport.
- Return a standards-compatible bearer challenge for missing/invalid credentials.
- Authenticate every request with the configured inbound verifier and bind claims to proxy, workspace, namespace, audience, issuer, expiry, and required scope.
- Maintain stateful session transports only within one proxy revision, or run explicitly stateless when configured; never share sessions across revisions.
- Register only the configured exposed tools and use stable aliases.
- Convert handler failures to safe MCP errors without returning upstream credentials or raw internal diagnostics.
- Close all transports and server resources during graceful shutdown.

The existing stdio mode remains available for local development and continues to write only MCP protocol messages to stdout.

### 4.2 Outbound HTTP MCP upstream

Implement a concrete `UpstreamTransport` for configured Streamable HTTP upstreams using the MCP SDK `Client` and `StreamableHTTPClientTransport`.

For each configured upstream:

- Validate the normalized HTTPS destination, declared host, safe port, resolved address set, redirect target, and TLS identity before connecting.
- Resolve credentials through the configured outbound credential provider only.
- Send a distinct upstream credential; never forward inbound `Authorization`, cookies, or caller headers.
- Establish a per-upstream client/session and close it on revision shutdown or transport failure.
- Perform bounded `listTools` discovery and preserve the existing quarantine/explicit-exposure checks.
- Call only the selected upstream tool name after alias resolution and validate the result against gateway limits.
- Bound request, response, decompression, timeout, and retry behavior.
- Treat protocol, schema, destination, and credential drift as safe adapter failures and never broaden exposure automatically.

The first live implementation is HTTP upstreams. Stdio upstreams remain configuration-valid but unavailable in this production slice unless a separate controlled transport is explicitly implemented and tested.

### 4.3 Managed executor integration

Refactor the gateway wiring so an HTTP request reaches the existing `ManagedExecutor` with the request's authenticated caller context while preserving the existing order:

```text
authenticate
  -> parse and validate input
  -> resolve alias and upstream session
  -> Apex authorization
  -> approval when required
  -> rate/budget policy
  -> egress policy
  -> upstream MCP call
  -> output filtering
  -> Apex evidence admission
  -> response
```

Multiple upstream sessions must remain independently addressable. A configured tool alias maps to exactly one upstream and tool name. A discovery result cannot add a callable tool, destination, credential, or policy binding.

The current live governance and event clients remain the only Apex integration for the gateway. Local fake adapters remain test-only and must not be selected by production startup configuration.

## 5. Configuration and failure behavior

Production wiring is explicit and fail-closed:

- Missing live Apex endpoints, mTLS material, inbound verifier, outbound secret resolver, runtime network, or required upstream endpoint prevents serving the affected mode.
- Local development may continue to use the existing static adapters under an explicit local mode.
- Configuration and startup errors identify the missing boundary and correlation ID but redact paths, tokens, certificate contents, and raw config values where sensitive.
- A durable event-admission failure prevents a successful tool response, even if the upstream call completed.
- A downstream fanout failure after outbox commit does not fail the already-admitted lifecycle or tool event.
- A failed or unready runtime never receives routable traffic.

## 6. Test and acceptance matrix

### Rust control plane

- Build a lifecycle envelope with deterministic ID, timestamp, metadata, scope, actor, version, and canonical hash.
- Reject malformed IDs, scopes, reason values, revision values, and secret-like metadata.
- Enqueue through an in-memory outbox and verify pending bytes decode as the expected event.
- Enqueue the same lifecycle event twice and verify duplicate/idempotent behavior.
- Verify Postgres/file backend calls occur through the blocking boundary.
- Verify startup wiring produces `Serving` only when runtime and sink are present and `NotServing` otherwise.
- Verify provider configuration rejects missing network/image/runtime requirements and preserves hardened Docker arguments.

### TypeScript gateway

- Start a real Streamable HTTP server with a fake governed upstream and call `portfolio.read` through the MCP SDK client.
- Reject wrong host, origin, method, body size, token, issuer, audience, proxy binding, and scope.
- Verify per-session and per-upstream isolation.
- Verify discovery quarantine and configured alias allowlisting.
- Verify inbound bearer credentials are absent from upstream requests.
- Verify governance denial, approval hold, filter failure, upstream failure, and evidence-admission failure remain safe and ordered.
- Verify graceful close terminates sessions and does not leave handles open.

### Live acceptance

The Compose-backed live gate must demonstrate:

1. The Rust control plane starts with a configured durable sink and Docker runtime provider.
2. `McpProxyService` reports `Serving`.
3. A proxy revision provisions one hardened container and reaches readiness.
4. The gateway accepts a real Streamable HTTP MCP request.
5. The gateway discovers and invokes a real HTTP MCP upstream.
6. Apex governance authorizes the request and Apex event admission succeeds.
7. Durable lifecycle and tool evidence are visible in the expected activity/outbox projection.
8. Removing either production dependency returns the service to `NotServing` and rejects calls safely.

## 7. Non-goals

This item does not include:

- A new event database or publisher path.
- Arbitrary shell or CLI execution.
- OAuth provider implementation beyond the configured verifier/metadata seams.
- Direct business writes or autonomous trading.
- Browser UI changes beyond any minimal configuration/documentation needed to expose the already-designed runtime state.
- Performance tuning unrelated to connection reuse, bounded concurrency, and startup/readiness of this live path.

## 8. Definition of done

The roadmap item is complete when the implementation passes the Rust and TypeScript unit/integration suites, the Compose-backed live acceptance matrix, security checks, and repository CI; the MCP proxy service is `Serving` only with both production boundaries active; and the durable sink and live adapter behavior are documented with operational failure/recovery guidance.
