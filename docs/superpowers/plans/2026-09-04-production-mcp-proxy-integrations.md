# Production MCP Proxy Integrations Implementation Plan

> **Execution note:** Follow this plan task-by-task. For every behavior change, write the smallest failing test first, run it to observe the failure, implement the minimum change, then rerun the focused test before moving on.

**Goal:** Wire the Rust control plane to a durable proxy lifecycle event sink and runtime provider, and turn the TypeScript managed gateway into a live Streamable HTTP proxy with a real HTTP MCP upstream adapter.

**Scope:** First production slice: read-only `portfolio.read` through one managed HTTP proxy revision. Preserve the existing stdio/local mode, fail-closed behavior, Apex governance/evidence authority, and no-raw-data event policy. Do not implement arbitrary CLI execution or business writes in this plan.

**Primary verification:** Rust workspace tests, MCP gateway typecheck/build/tests, Compose-backed live acceptance, security checks, and `git diff --check`.

## Task 1: Add the durable proxy lifecycle event encoder and sink

**Files:**
- Create `apps/control-plane-api/src/proxy/events.rs`.
- Modify `apps/control-plane-api/src/proxy.rs` to export the production sink.
- Modify `apps/control-plane-api/src/lib.rs` only if the sink must be publicly re-exported for startup/tests.
- Add focused tests beside the new module.

**Steps:**

1. Add a failing unit test that builds a valid `ProxyLifecycleEvent`, emits it to an in-memory `ControlOutboxBackend`, reads the pending `IngestRequest`, decodes the `EventEnvelope`, and asserts `WORKFLOW`, exact scope, fixed SYSTEM producer, deterministic IDs/timestamp, and allowlisted metadata.
2. Add a failing test showing a second `emit` with the same request ID returns success and leaves one durable event.
3. Add a failing test proving secret-like or malformed lifecycle metadata is rejected before enqueue.
4. Implement a `DurableProxyEventSink` holding `Arc<ControlOutboxBackend>` and an encoder that constructs the shared `proto::EventEnvelope`, computes the canonical integrity hash, and calls `IngestRequest::from_validated_transport`.
5. Use UUIDv7-derived stable time and the lifecycle request ID for `event_id`, `run_id`, and `trace_id`, so retries produce the same canonical event.
6. Map the lifecycle fields into a fixed, metadata-only `WORKFLOW` data object. Do not include input/output payloads, config blobs, credential refs, filesystem paths, or arbitrary caller text.
7. Enqueue using `submit_command` (or a small equivalent that preserves duplicate outcomes) and translate durability failures to `ProxyError` without leaking backend details.
8. Keep the sink synchronous, but document and expose a startup/helper boundary that lets callers invoke it from `spawn_blocking` when the backend is Postgres-backed.

**Verification:** `cargo test -p apex-control-plane-api proxy::events` and the focused event tests must pass; inspect the decoded envelope rather than only asserting a successful method call.

## Task 2: Wire runtime provider and event sink into control-plane startup

**Files:**
- Modify `apps/control-plane-api/src/startup/service.rs`.
- Modify `apps/control-plane-api/src/startup/service/storage.rs` or add `apps/control-plane-api/src/startup/service/proxy.rs` for runtime configuration.
- Modify `apps/control-plane-api/src/proxy/provider.rs` only for startup-configurable network/provider validation or readiness details.
- Add startup/configuration tests under `apps/control-plane-api/src/startup/tests/` or the closest existing test module.

**Steps:**

1. Add failing tests for managed-runtime configuration: absent runtime network/provider configuration keeps proxy health unavailable; malformed network configuration is rejected; valid configuration selects the Docker provider with the provider-owned network.
2. Add a startup constructor that receives the already-open `Arc<ControlOutboxBackend>` and proxy store, builds `DurableProxyEventSink`, and optionally builds `DockerProxyProvider` from explicit environment configuration.
3. Reuse the existing `DockerCommandRunner` and `DockerProxyProvider::with_network`; do not add shell parsing, host networking, runtime sockets, or caller-supplied Docker flags.
4. Construct `McpProxyService` with `.with_event_sink(...)` and `.with_runtime_provider(...)` only when the corresponding production boundary is configured and validated.
5. Set the MCP proxy health status to `Serving` only when both dependencies are wired. Preserve `NotServing` otherwise, with a redacted startup diagnostic that identifies the missing boundary.
6. Ensure the production sink and provider are constructed before entering the Tokio runtime, matching the existing Postgres client rule.
7. If the sink is invoked by async proxy operations, move the blocking emission through the established blocking boundary. Preserve the current rule that a failed durable enqueue makes the lifecycle operation fail rather than reporting false success.
8. Add tests around the health decision as a pure helper if direct startup testing is too invasive; test all combinations of sink/provider presence.

**Verification:** Run focused startup/proxy tests, then `cargo test -p apex-control-plane-api`; verify no Postgres client construction occurs from an entered Tokio runtime.

## Task 3: Make the managed executor resolve multiple live upstream sessions

**Files:**
- Modify `apps/mcp-gateway/src/managed/managed-executor.ts`.
- Modify `apps/mcp-gateway/src/managed/managed-executor.test.ts`.
- Modify `apps/mcp-gateway/src/managed/upstream.ts` only where session lookup/closure needs a small explicit API.
- Add a focused managed runtime test if needed.

**Steps:**

1. Add a failing test with two configured upstreams and two exposed aliases; verify each alias calls only its mapped upstream and an unmapped alias is rejected.
2. Add a failing test that a missing/closed session fails safely and cannot fall back to another upstream.
3. Refactor the executor options from one session to a read-only upstream session map, or introduce a narrow resolver that maps `ExposedTool.upstreamId` to one session.
4. Preserve the existing authentication, governance, approval, egress, filtering, and evidence ordering exactly.
5. Add a lifecycle close helper that closes all sessions once and safely aggregates/handles close failures without exposing credentials.

**Verification:** `pnpm --dir apps/mcp-gateway test -- managed/managed-executor` (using the repository’s test runner syntax) and `pnpm --dir apps/mcp-gateway typecheck`.

## Task 4: Implement the real outbound Streamable HTTP MCP transport

**Files:**
- Create `apps/mcp-gateway/src/managed/mcp-http-transport.ts`.
- Modify `apps/mcp-gateway/src/managed/upstream.ts` for transport lifecycle/concurrency hooks if required.
- Create `apps/mcp-gateway/src/managed/mcp-http-transport.test.ts`.
- Extend `apps/mcp-gateway/src/managed/upstream.test.ts` with the concrete transport seam.

**Steps:**

1. Add a failing integration-style test using a local HTTP fixture that implements the MCP SDK Streamable HTTP protocol and records request headers. Assert discovery and tool calls succeed only after a configured outbound credential is resolved.
2. Add a failing test proving inbound `Authorization`, cookies, and arbitrary caller headers are not copied to the upstream.
3. Add a failing test for wrong scheme/host/port/redirect and oversized or malformed upstream responses.
4. Implement `UpstreamTransport` with the official MCP SDK `Client` and `StreamableHTTPClientTransport`.
5. Create one client/transport per configured upstream. Cache only the session within the proxy revision; do not share clients or credential material across revisions.
6. Implement bounded `listTools`, tool name validation, call timeouts, response-size limits, and safe close. Use the existing `validateHttpsDestination` and resolved-address/redirect policy seams; fail closed if a required live DNS/address check cannot be made safely.
7. Resolve the upstream credential through `createOutboundCredentialProvider`; keep the credential in request initialization only and never return it in errors or telemetry.
8. Return MCP SDK results through the existing quarantine and explicit exposure checks; a discovery result must never expand the exposed catalog automatically.
9. Keep stdio upstream transport unsupported in this production slice and return a safe adapter failure if selected at runtime.

**Verification:** `pnpm --dir apps/mcp-gateway test`, `pnpm --dir apps/mcp-gateway typecheck`, and a fixture test that inspects actual outbound headers.

## Task 5: Implement the live Streamable HTTP ingress

**Files:**
- Create `apps/mcp-gateway/src/managed/http-server.ts`.
- Modify `apps/mcp-gateway/src/index.ts`.
- Modify `apps/mcp-gateway/src/server.ts` or add `apps/mcp-gateway/src/managed/managed-server.ts` for dynamic exposed-tool registration.
- Create `apps/mcp-gateway/src/managed/http-server.test.ts`.

**Steps:**

1. Add a failing test that starts a real Node HTTP server with a minimal managed revision, calls it using the MCP SDK Streamable HTTP client, and receives a governed `portfolio.read` response.
2. Add failing tests for missing/invalid bearer auth, wrong host, wrong origin, invalid method/content type, oversized body, unsupported tool alias, and malformed session headers.
3. Implement server lifecycle around Node `http.createServer` and the official `StreamableHTTPServerTransport`. Use a bounded request reader only where the SDK requires parsed input; reject over-limit input before protocol handling.
4. Preserve request headers as a narrow `HeaderValues` map for `ManagedExecutor.execute`; do not pass the full incoming request object or credential values into upstream code.
5. Maintain a revision-scoped session map keyed by the SDK session ID. On initialize, create the MCP server/transport pair; on subsequent requests, route only to the matching transport and revision. Support explicit stateless operation only if the configured transport mode requires it.
6. Register only configured exposed tools. For the first slice, bind `portfolio.read` to the managed session path and make its input/output use the same safe schema/filtering contract as the existing local proof.
7. Return `401` plus `WWW-Authenticate` using the existing protected-resource metadata/challenge helper when authentication fails before MCP request processing. Convert other failures to safe protocol errors.
8. Gracefully close the HTTP listener, MCP transports, and all upstream sessions on SIGTERM/SIGINT or test shutdown; make close idempotent.
9. Keep `index.ts`’s existing stdio mode when no managed revision is supplied. When a managed HTTP revision is supplied, require live-mode dependencies and start only the HTTP path.

**Verification:** Run the real HTTP fixture test, all managed tests, build/typecheck, and verify that stdio startup behavior remains unchanged.

## Task 6: Connect production gateway dependency wiring

**Files:**
- Modify `apps/mcp-gateway/src/wiring.ts`.
- Modify `apps/mcp-gateway/src/live/config.ts` and/or add live auth/secret resolver modules.
- Add tests under `apps/mcp-gateway/src/managed/` and `src/live/`.

**Steps:**

1. Add failing tests showing a managed HTTP revision in live mode refuses startup when governance, events, inbound verifier, or outbound secret resolver configuration is absent.
2. Add an explicit live managed dependency builder that composes the existing mTLS governance/events clients, configured inbound token verifier, and outbound secret resolver.
3. Keep the local static Apex adapter available only under explicit local mode; never silently substitute it for a managed production HTTP revision.
4. Use the existing trusted-secret-base checks for all certificate, key, token, and outbound-secret material. Do not place raw credentials in revision config, logs, or event data.
5. Ensure the managed executor’s caller context is derived from verified inbound claims and server-side scope, not from untrusted request fields.
6. Keep approval behavior explicit: the first read-only slice may use `approvalMode: none`; any other classification must retain the existing fail-closed approval seam.

**Verification:** Focused live wiring tests, full gateway tests, typecheck, and a negative startup test with missing live material.

## Task 7: Add the Compose-backed live acceptance fixture and CI gate

**Files:**
- Inspect and modify the existing Compose/CI files only where needed: `.github/workflows/*`, `deploy/compose/*`, `apps/mcp-gateway/scripts/*`, and live integration tests.
- Modify `apps/control-plane-api/tests/live_mcp_proxy_control.rs` to require the now-live path rather than accepting intentional `NotServing` as success.
- Add a small fixture upstream under the existing test fixture location, keeping each source file below 600 lines.

**Steps:**

1. Add a failing live test that starts the gateway, fixture upstream, control plane, and durable outbox, then checks health, proxy readiness, HTTP MCP initialize/discovery/call, event admission, and durable activity.
2. Remove the old test branch that treats `PROXY_EVENT_SINK_UNAVAILABLE` or `PROXY_RUNTIME_UNAVAILABLE` as an accepted deployment result; those become failures for the configured production profile.
3. Add a negative live check that disables either runtime or sink configuration and verifies health becomes `NotServing` and tool calls are rejected.
4. Keep CI service health/readiness bounded and use cached dependency installs and targeted waits so this gate does not turn into a long unbounded build.
5. Add log assertions that prove no bearer token or secret value appears in gateway/control-plane output.

**Verification:** Run the exact local Compose acceptance command used by CI, then the workflow-equivalent unit/typecheck/build commands. Do not claim the live item is complete until the fresh CI run is green.

## Task 8: Documentation, review, and final verification

**Files:**
- Update `docs/roadmap.md` to mark only this remaining integration item complete after verification.
- Update `docs/security/mcp-proxy-threat-model.md` residual-risk and operational sections.
- Update the focused specification if implementation decisions differ materially.
- Add `docs/operations/mcp-proxy-live-integrations.md` if operational recovery/configuration guidance does not fit existing docs.

**Steps:**

1. Document production environment requirements, health semantics, outbox retry/replay behavior, runtime provider requirements, HTTP session lifecycle, upstream credential isolation, and failure recovery.
2. Run `git diff --check`, line-limit/readability checks, Rust fmt/clippy/tests, gateway build/typecheck/tests, and the live acceptance gate.
3. Review the diff for secrets, raw payload logging, accidental local-adapter selection, Docker-socket exposure, host-networking flags, and cross-revision session sharing.
4. Run the repository’s security and CI-equivalent checks from a clean working tree state, preserving the pre-existing untracked `apps/mcp-gateway/pnpm-workspace.yaml`.
5. Only after fresh verification, prepare the commit. Push only if explicitly requested in the active turn.

## Expected changed-surface summary

- Rust: one production event-sink module, startup construction/health wiring, focused tests, and only minimal provider changes.
- TypeScript: one live HTTP server module, one official SDK upstream transport module, managed executor/session wiring, tests, and live dependency composition.
- CI/docs: one acceptance gate adjustment and operational documentation.

Every new or modified source file must remain under the repository’s 600-line readability limit.
