# Working MCP Gateway: Delivery Design

**Status:** Approved execution baseline; implementation is underway. Release gates remain unproven; see the [evidence ledger](../../operations/mcp-gateway-release-evidence.md).
**Date:** 2026-09-04
**Assessed revision:** `1a6df0908de0a604415fd5c1631f697656d679ee`
**Request:** Turn the current application into a working managed MCP gateway, including microsecond-level tracing.
**Parent design:** [Managed MCP proxy platform](2026-09-04-mcp-proxy-platform-design.md)
**Plan:** [Execution index](../plans/2026-09-04-working-mcp-gateway.md)

## 1. Outcome and scope

An operator can install the supported self-hosted profile, sign in, click the large `+ New proxy`, configure independent proxies, test upstream connectivity, publish and deploy, connect an MCP client, execute governed tools, inspect real evidence and microsecond timings, and safely pause, resume, rotate, roll back, retire, and recover after restart.

The first integrated gate uses `portfolio.read`. That is an intermediate milestone, not the definition of a general-purpose gateway. The release gate additionally uses unrelated structured tools and an approved CLI profile without adding tool-name-specific branches to the gateway.

Implementation stays within the existing MCP roadmap. Unrelated dashboards, archive providers, trading, general workflow orchestration, Kubernetes, and multi-region/high-availability redesign remain on hold. Do not silently enable mutating business integrations: prove the common write/approval machinery with a disposable fixture, then require an explicit published policy and approved binding for any real write tool. Direct autonomous trade execution stays disabled.

## 2. Evidence that changes execution priority

The browser's `previewProxyApi` mutates maps, not the Rust API. Ingress and upstream URLs share one form field; most tabs are not implemented. Rust and TypeScript both restrict live governance to the portfolio tool. The runtime provider omits deployment configuration and credentials, has no working discovery/test connection, and treats a running container as ready. Pause does not stop execution; retirement uses provisioning reconciliation. The packaged gateway lacks the Protobuf files loaded by live clients. Proxy storage defaults to memory. Tool evidence and UI activity are disconnected.

Timing also needs correction: `EventEnvelope.timestamp` and ClickHouse already support six fractional digits, but `timestampFromUuidV7()` pads a millisecond UUID timestamp with zeros and tool latency is measured in milliseconds. Formatting is not microsecond measurement.

Earlier documents remain historical records of component/fixture work. Their completion language must not be used to waive the integrated gates below.

## 3. Architecture decision

### Chosen: connect the existing authorities, add two narrow boundaries

```text
Browser -- HTTPS / HttpOnly session --> Rust browser edge
                                         |
                                 existing authenticated RPCs
                                         |
                              Rust control plane / PostgreSQL
                                |                     |
                    durable desired state       scoped activity queries
                                |
                    mTLS restricted runtime agent (host service)
                                |
                    per-proxy OCI runtime + scoped egress
                                |
MCP client -- HTTPS edge --> TypeScript MCP gateway --> approved upstream / CLI
                                |
                         Apex governance + durable evidence
                                |
                      existing fanout / ClickHouse / archive
```

The Rust browser edge lives in `apps/control-plane-api`, with separate modules/listener for OIDC sessions and generated-contract HTTP requests. It forwards the authenticated operator credential through the existing authorization boundary; it cannot substitute a global administrator credential. Static Vite assets are served by the deployment edge. No new Node frontend server is required.

The proposed `apps/proxy-runtime-agent` is a small Rust host service with its own mTLS identity and a fixed OCI operation contract. It is the only Apex component allowed to use the deployment-owned, preferably rootless Docker socket. It owns approved image resolution, secret staging, network enforcement, and container operations. The control-plane container, browser, gateway, and CLI child receive no runtime socket. Existing dangerous agent controls remain in `apps/agent-supervisor`; do not make applications depend on each other.

The agent accepts typed operations, not shell strings, Docker flags, arbitrary mounts, paths, ports, or image names. It validates its own ownership labels, lease fencing token, approved image catalog, host policy, and reference namespace even when the caller has valid mTLS.

### Alternatives considered

1. **Repair direct Docker calls inside the control-plane container:** fewer processes, but requires runtime privileges in the general control service and does not solve browser identity or safe secret provisioning. Not selected.
2. **Replace the platform with another gateway or a large rewrite:** introduces migration and governance duplication before proving usability. Not selected.
3. **Connect existing components through the narrow boundaries above:** additional contract work, but preserves Rust authority, the static UI, current TypeScript runtime, and the existing durable event path. Selected for this plan.

These are proposed implementation choices, not claims of already-deployed infrastructure.

## 4. Global constraints

- Apex remains the only policy and durable evidence authority.
- The browser holds no access tokens, refresh tokens, upstream secrets, or runtime credentials.
- Published revisions are immutable; mutations use lowercase UUIDv7 request IDs and optimistic concurrency.
- One logical proxy has at most one routable revision; a replacement candidate may coexist only during bounded validation and drain.
- Inbound credentials are never passed through to upstreams.
- CLI execution uses approved executables and typed argv with shell interpretation disabled.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.
- Unsupported capabilities are rejected or disabled visibly, never shown as working controls.

Use Rust 2024 and the current Rust workspace; Node.js 24 and the repository-locked MCP SDK 1.x; React 19, Vite, TanStack Router/Query; existing PostgreSQL, mTLS, OIDC/Keycloak, NATS and ClickHouse. Pin any added dependency in lockfiles and pass the existing license/advisory checks. No blanket dependency upgrade is part of this work.

## 5. Contract and persistence decisions

Protobuf remains the source of truth. Generate Rust, TypeScript management types, and Protobuf-JSON serialization together. Do not maintain competing UI and runtime configuration schemas without a tested compiler between them.

Keep `mcp_proxy.proto` compatible: add messages/fields/RPCs without reusing field numbers. Split new runtime, approval, and trace contracts into small files. Add revision listing, operation status, installation capabilities, binding metadata, approval inspection/decision, and trace detail operations needed by the UI. The browser edge maps an allowlisted RPC name to generated request/response types at `/api/apex/v1/<Service>/<Method>`; arbitrary RPC dispatch is forbidden.

Create returns server-issued proxy/draft IDs. During migration, a supplied legacy proxy ID remains valid only through the existing validation/idempotency rules. Empty new IDs are generated once inside the idempotent transaction. The browser generates only a request ID, using a tested UUIDv7 utility.

Compile each validated immutable control-plane revision into a versioned runtime configuration. Carry distinct ingress/upstream endpoints, exact resource URL audience, upstream and CLI catalogs, approved schemas, output handling, credentials by reference, policy/approval bindings, runtime limits, private-destination grants, and telemetry settings. Reject unknown schema versions or lossy conversions. Verify a separately computed runtime-manifest digest; never confuse a config hash with an image digest.

Require Postgres for the managed production profile. Desired state, operation journal, revision history, controller leases/fencing tokens, approval state, and activity cursors survive restart. Journal the lifecycle mutation and evidence intent in the same database transaction, then relay that intent idempotently through the existing Apex outbox. No state change may depend on a browser retry to recover missing evidence. Historical event hashes are immutable.

## 6. Provisioning and lifecycle

A runtime deployment contains an approved image reference, config digest, per-revision read-only config/secret mounts, dedicated workload identity, health identity, listener settings, resource profile, and per-proxy network grants. Raw secrets never enter process arguments, Docker environment inspection, browser responses, database revision JSON, or logs. The agent resolves references through a deployment-owned provider; initially a confined file-backed provider is sufficient.

The HTTPS edge routes a stable resource URL to the active ready revision using control-plane route state. It must support MCP streaming and avoid proxy buffering. Proxy cookies are not operator cookies. Endpoints are allocated server-side, not taken from arbitrary browser routing instructions.

Readiness verifies config/digests, current workload identity, inbound verifier, upstream initialization/catalog validation, policy binding, evidence admission availability, and the configured network policy. It has a timestamp and bounded freshness. Liveness only means the process is alive. `NotServing`/degraded diagnostics identify the failed dependency without secrets.

Reconciliation runs on startup, commands, and a bounded periodic interval. Database leases and fencing prevent two controllers from routing competing revisions. Fix Docker inspect parsing, reattach by ownership labels, and quarantine unknown/mismatched containers rather than deleting them.

Pause stops new admission and disables routing, drains with a deadline, then stops the runtime. Existing sessions cannot bypass pause. Retire disables routing, terminates the owned runtime, revokes its identity and approved credentials, and retains audit history. Resume rebuilds readiness. Rotation stages fresh credentials and a new revision; rollback creates a new deployment generation of an approved old configuration, never revives revoked credentials. Only the active generation accepts new calls.

## 7. Supported protocol, authentication, and tools

Release scope includes Streamable HTTP ingress/upstreams, controlled stdio upstreams, a local stdio-to-managed-HTTP launcher for clients needing stdio, and fixed CLI profiles. The launcher is transport-only and targets a managed proxy; it never exposes a host Docker socket or substitutes the legacy local portfolio adapter. Stdio cannot be configured as a shared multi-client network listener.

Negotiate the supported MCP revision with the pinned SDK and test the `2025-11-25` baseline. Advertise only implemented capabilities: tools, initialization, cancellation, bounded sessions and applicable notifications. Resources, prompts, sampling, elicitation, experimental tasks, and legacy HTTP+SSE are not silently proxied. Their absence does not block this tools-gateway release. See the versioned [transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [tool contract](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

Operator login uses Authorization Code + PKCE through the Rust session edge; encrypted server-side token storage, opaque Secure/HttpOnly/SameSite cookies, CSRF and Origin checks, bounded session expiry, refresh rotation, logout and revocation. MCP clients use separate resource-bound tokens from the configured provider, not the browser session. Pre-registered OAuth clients are the initial supported enrollment path; implement usable enrollment instructions and resource audience provisioning. Automatic public client registration and arbitrary delegated exchanges are not required. Follow the pinned [MCP authorization contract](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

Inbound verification binds subject, agent, issuer, resource audience, scope, proxy, expiry and session ownership on every request. Scope/trace fields in request JSON cannot replace authenticated claims. Outbound adapters support separate bearer/API-key references, mTLS, and provider-managed OAuth client credentials with bounded refresh. Both directions support rotation/revocation with no token disclosure.

Discovery is an isolated non-routable probe, not an executing production tool. Store server identity, normalized schemas and catalog hashes; expose only approved aliases. Validate bounded JSON Schema without remote `$ref` fetching. Structured results use explicit policy-owned allow/remove paths; text/binary results require a declared bounded handling profile or are rejected. Never promise arbitrary-content redaction. Unknown tools, unsafe schema drift, and unhandled result blocks fail closed.

Generalize Rust policy lookup and TypeScript execution together. Tool descriptions and read-only annotations are untrusted hints, not authorization. Resource resolution comes from a validated mapping in the revision, not a portfolio-specific helper or arbitrary executable code.

Approvals are durable and bound to subject/scope, proxy/revision, policy revision, tool/action, keyed argument digest, expiry, and distinct approvers. Do not retain raw arguments to support a pending approval. A client retries with the same call ID and identical input; the gateway reauthorizes and consumes the approval once. Uncertain non-idempotent execution is never automatically retried.

## 8. Network and admission enforcement

Application URL checks and runtime egress restrictions are both required. Bind outbound connections to the validated DNS result while retaining TLS hostname verification; reject unsafe redirects. Explicit server-approved private grants include hostname, port and IP/CIDR intersection; they are not an `allow all private` switch. Metadata, loopback, host-control and other proxy networks remain denied. CLI subprocesses must be subject to the same network policy even if they ignore proxy environment variables.

A provider-owned per-proxy network path/egress guard enforces these grants. If the host cannot enforce isolation, the installation preflight refuses managed serving. No unguarded shared bridge is a substitute. Docker control is a privileged trust boundary; the [Docker security guidance](https://docs.docker.com/engine/security/) informs host-service confinement.

Initial configurable ceilings: 16 concurrent calls, 64 queued calls, 60 calls/minute with burst 10, 1 MiB input, 4 MiB result, 30-second call deadline, 128 sessions and 15-minute idle expiry per proxy. These are proposed defaults, not measured capacity. Tests override limits explicitly for load runs. Per-proxy Apex admission leases enforce rate/budget/concurrency across replacement generations; release on cancellation/failure and expire abandoned leases. Budget means a defined unit and period, not an unimplemented currency field.

## 9. Microsecond tracing requirement

### Measurement contract

Record each call and attempt with UUIDv7 `call_id`, `event_id`, `proxy_id`, `revision_id`, `upstream_id`, authenticated subject and separate W3C/OTel `otel_trace_id` and `span_id`. Keep existing legacy trace fields compatible. Accept external trace context only through bounded validation; links do not confer scope or identity, and baggage is allowlisted.

Use Node `process.hrtime.bigint()` and Rust `Instant` for elapsed time. Retain nanoseconds internally and convert once with integer division for microseconds; keep optional nanoseconds when displaying a sub-microsecond span. Never derive elapsed time from `Date.now()`, UUID time, rounded milliseconds, or subtraction of timestamps from different hosts. Correlate monotonic clocks with the process wall-clock anchor and report the anchor's actual resolution/uncertainty. A millisecond-resolution anchor must not be described as a measured microsecond-accurate wall clock.

Each timing record carries `started_at_unix_us`, `duration_us`, optional `duration_ns`, `clock_source`, `clock_resolution_ns`, nullable `clock_uncertainty_us`, `process_instance_id`, and trace/span ancestry. Use Protobuf `uint64` or decimal strings; JSON `Struct` values carrying these integers must be strings, not floating-point numbers. UI arithmetic uses `BigInt`. Preserve six fractional digits and the existing ClickHouse `DateTime64(6, 'UTC')` column; use integer microsecond durations and additive query indexes/projections.

Instrument ingress validation, authentication, queue wait, schema validation, Apex authorization, approval wait/consume, admission reservation, DNS/connect/TLS when observable, upstream/CLI execution, output validation/filtering, evidence admission, serialization, and response write. Record upstream response `isError`, cancellation, timeout and failure phases. Instrument Rust governance, durable commits, runtime provisioning/readiness, and async fanout with linked spans. Opaque third-party upstream internals are unavailable unless that service emits compatible spans.

The UI shows a scoped waterfall, exact microsecond values, parent/child relationships, policy/event links, and clock uncertainty. It never infers network latency by subtracting unrelated wall clocks or sums overlapping children as total duration. Absolute cross-host accuracy of one microsecond is not promised: that needs independently validated clock synchronization, potentially PTP/hardware support. OpenTelemetry supports higher-resolution timestamps, but representation alone does not establish clock accuracy. [OTel trace time model](https://opentelemetry.io/docs/specs/otel/trace/api/#time)

### Durability, sampling, and performance

Always capture the bounded gateway stage summary in required evidence for every admitted call: at most 32 aggregate stages and 64 KiB of timing metadata, inside the existing 256-KiB envelope bound. Aggregate retry spans separately instead of growing the mandatory summary without limit. Default full tracing is 100% for this single-host release, with hard limits of 128 spans/call, 64 attributes/span and an 8 MiB async export queue per process. If optional detail is dropped, emit loss counters and show `partial`, never a silently complete trace. Audit/evidence is never sampled. Trace exporter/collector outages do not bypass evidence or block otherwise valid admitted calls.

The pre-response durable event includes completed stage timings and marks response completion pending. Evidence-commit, response-write and remote-client receipt cannot truthfully be included in an event committed before those actions. Emit a linked completion span/event afterward; absence means incomplete completion telemetry, not a fabricated zero or reversal of the earlier admission receipt. The server can measure socket write completion, not the time the remote client renders a result.

Clock-injected tests must preserve 1, 7 and 999 microsecond differences through serialization, admission, projection, query and UI. Include exact large-integer round trips, a backwards wall-clock jump, overlapping async calls, skewed remote clocks, collector loss, and no-secret assertions. Do not use operating-system sleeps to assert one-microsecond accuracy.

## 10. Release gates

- **G0: truthful control surface.** Signed-in operator CRUD reaches authenticated Rust handlers and persistent state; no preview fallback; exact contract/runtime config round-trip.
- **G1: usable read-only path.** A UI-created portfolio proxy provisions dynamically from a packaged image, accepts a real MCP client, allows/denies through real Apex, emits durable evidence, and survives pause/resume/restart. Use tasks 1-10, the HTTP/auth/policy portions of 11-13, the narrow portfolio portions of 15-19, and the task-21 harness. CLI task 14 is not a prerequisite; enable its capabilities only after this gate. G1 is not the final release.
- **G2: general managed gateway.** Two proxies, unrelated tools, all supported credential modes, fixed CLI and stdio adapters, real approvals/limits, rotation, rollback and retire work without test adapters in production startup.
- **G3: observable and recoverable release.** Microsecond trace round-trip, fault/security matrix, fresh-install/restore, real browser plus MCP SDK tests, and declared performance budgets pass against the exact release image digests.

“Fully working” means G0-G3 are recorded with commit, image digest, commands and evidence. A green unit suite or a manually launched fixture cannot close a gate.
