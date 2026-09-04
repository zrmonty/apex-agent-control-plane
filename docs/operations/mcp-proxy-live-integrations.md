# Managed MCP proxy live integrations

This document describes the first production runtime slice for a managed MCP
proxy: a read-only `portfolio.read` tool served over Streamable HTTP, routed to
an approved Streamable HTTP upstream, authorized by Apex, filtered by the
gateway, and durably recorded by Apex.

The proxy remains a thin data-plane adapter. It does not contain a local policy
override, a second audit ledger, or a credential passthrough path.

## Runtime boundaries

There are two independent production boundaries.

| Boundary | Owner | Failure behavior |
| --- | --- | --- |
| Proxy lifecycle evidence | `control-plane-api` and its `ControlOutboxBackend` | Lifecycle RPCs fail safely if durable enqueue fails. Duplicate request IDs remain idempotent. |
| Managed MCP data plane | `apps/mcp-gateway` | The HTTP runtime is not started unless live Apex dependencies, inbound verification, and all upstream discoveries succeed. |

The control-plane MCP proxy health service is `Serving` only when the durable
event sink and an explicitly configured runtime provider are both present. Set
`APEX_CONTROL_MCP_PROXY_RUNTIME_NETWORK` to the provider-owned network name in a
deployment that has the approved runtime command boundary. If it is absent, the
control API remains available for unrelated control operations, while
`apex.v1.McpProxyService` stays `NotServing` and deploy/reconcile calls fail
closed.

## Managed gateway startup

The gateway selects its mode from the validated revision file or serialized
configuration:

- no managed revision: existing stdio/local development mode;
- `ingress.transport = "stdio"`: existing stdio path;
- `ingress.transport = "streamable-http"`: live managed mode only.

Managed HTTP mode requires:

1. `APEX_MCP_GOVERNANCE_MODE=live`;
2. the live governance and event mTLS endpoint/material variables described in
   `.env.example`;
3. `APEX_MCP_TRUSTED_SECRET_BASE`, containing only staged trusted material;
4. `APEX_MCP_INBOUND_JWKS_FILE`, confined beneath the trusted secret base;
5. authenticated runtime identity variables (`APEX_MCP_PRINCIPAL`,
   `APEX_MCP_AGENT_ID`, `APEX_MCP_WORKSPACE_ID`,
   `APEX_MCP_NAMESPACE_ID`, and `APEX_MCP_TRACE_ID`); and
6. an explicit listener address through `APEX_MCP_LISTEN_HOST` and
   `APEX_MCP_LISTEN_PORT` when the deployment does not use the defaults
   `127.0.0.1:8080`.

TLS is expected to terminate at the deployment edge. The gateway still treats
the configured ingress endpoint as HTTPS and validates the exact host,
pathname, query, origin, method, content type, body bound, and session header
before handing a request to the MCP SDK transport. The protected-resource
metadata URL advertised in `WWW-Authenticate` is served by the gateway and
contains no token, secret, proxy ID, or internal configuration.

Startup discovers every configured HTTP upstream before the listener becomes
available. A failed discovery closes already-open sessions and aborts startup.
Stdio upstreams are configuration-valid for the broader platform but are not
available in this production HTTP slice.

## Request path

Every MCP request follows this order:

```text
HTTP boundary and origin checks
  -> bearer verification against local trusted JWKS
  -> proxy/scope/expiry/scope-claim binding
  -> strict tool input validation
  -> Apex authorization
  -> approval and admission gates
  -> exact alias-to-upstream resolution
  -> declared HTTPS and resolved-address checks
  -> MCP upstream call with outbound credential only
  -> deterministic response filtering
  -> Apex event admission
  -> MCP response
```

Inbound `Authorization`, cookies, and arbitrary caller headers are not copied
to the upstream. Upstream credentials are resolved only from a `secret://`
reference and are installed as the outbound bearer header for that upstream
session. The HTTP client revalidates the destination on every request, rejects
redirects, applies bounded request/response sizes, and enforces a timeout.

Discovery is quarantined and hashed. A discovered tool is callable only when
the immutable revision explicitly exposes its upstream ID, tool name, and
stable alias. Discovery cannot add a tool or destination to the revision.

## Durable lifecycle evidence

`DurableProxyEventSink` converts each validated `ProxyLifecycleEvent` into the
existing `apex.v1.EventEnvelope` and submits it through the same outbox used by
the control gateway. It does not call NATS, ClickHouse, or archive providers
directly.

The envelope is a metadata-only `WORKFLOW` event:

- `event_id`, `run_id`, and `trace_id` are the lifecycle request UUIDv7;
- the timestamp is deterministically derived from that UUIDv7;
- scope is copied exactly from the lifecycle request;
- actor is the fixed system producer `apex-control-plane`;
- producer metadata is fixed to `apex-control-gateway` and
  `proxy-lifecycle-v1`;
- data contains only operation, proxy ID, optional revision ID, actor ID, and
  reason code; and
- integrity uses the shared canonical event hash.

The sink validates all metadata before enqueue. `Enqueued`, `AlreadyPending`,
and `AlreadyComplete` are successful durable outcomes. Downstream fanout may
be unavailable after enqueue without invalidating the lifecycle admission.
Synchronous outbox calls from async RPC handlers run on a blocking boundary;
the Postgres backend must never be constructed or called from an entered
Tokio worker thread.

## Failure and recovery

| Symptom | Meaning | Recovery |
| --- | --- | --- |
| `McpProxyService` is `NotServing` | Runtime network/provider is absent or invalid, or the sink could not be constructed | Correct the deployment boundary and restart/reconcile. Do not bypass health. |
| Gateway exits with `GOVERNANCE_UNAVAILABLE` | Live Apex, trusted JWKS, mTLS material, or runtime identity is incomplete/unavailable | Restore the missing trusted material or Apex endpoint, then restart. |
| Gateway exits during upstream discovery | An upstream endpoint, DNS answer, credential, TLS identity, or MCP catalog failed validation | Correct the immutable revision or upstream service; do not broaden the allowlist automatically. |
| A governed call returns `EVENT_ADMISSION_FAILED` | Upstream work completed but Apex did not durably admit the evidence | Retry with the same request context after Apex recovers; the gateway never reports a successful result without admission. |
| Lifecycle call fails after a state transition | Store mutation succeeded but lifecycle evidence enqueue did not | Retry the same UUIDv7 request ID. Outbox idempotency and lifecycle request idempotency converge the state and event. |

On shutdown, the HTTP listener stops accepting new connections, revision-scoped
MCP sessions close, and the upstream sessions close. Close is idempotent. A
revision must never reuse a session, credential cache, catalog, or temporary
state from another revision.

## Verification checklist

Run from the repository root unless noted:

```text
cargo test -p apex-control-plane-api
cd apps/mcp-gateway
pnpm build
node ./node_modules/typescript/bin/tsc --noEmit -p tsconfig.json
$files = rg --files src | Where-Object { $_ -like '*.test.ts' }
node ./node_modules/tsx/dist/cli.mjs --test $files
```

The live acceptance gate must additionally prove a real configured revision,
the control-plane health state, one hardened runtime, an SDK HTTP request, a
real HTTP upstream discovery/call, live governance and event admission, and
server-derived durable activity. Unit and fixture tests are not a substitute
for that deployment gate.
