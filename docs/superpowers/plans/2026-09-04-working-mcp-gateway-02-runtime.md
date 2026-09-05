# Working MCP Gateway: Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn a published revision into an isolated, reachable, healthy gateway whose lifecycle controls affect real traffic.
**Architecture:** A restricted host runtime agent consumes compiled revisions, stages per-proxy material, enforces network grants and reports observations to a durable reconciler. The HTTPS edge routes only the ready active generation.
**Tech Stack:** Rust/tonic/mTLS, Docker/OCI, TypeScript MCP SDK, the existing deployment edge and Postgres.
**Spec:** [Delivery design](../specs/2026-09-04-working-mcp-gateway-design.md); prerequisites in the [execution index](2026-09-04-working-mcp-gateway.md).

## Global constraints

- One logical proxy has at most one routable revision; a replacement candidate may coexist only during bounded validation and drain.
- Inbound credentials are never passed through to upstreams.
- Published revisions are immutable; mutations use lowercase UUIDv7 request IDs and optimistic concurrency.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.

All other spec constraints apply. New helper infrastructure is limited to the MCP runtime boundary; do not modify the existing agent force-stop subsystem.

## Task 6: Build a self-contained gateway image and truthful startup probes

Checkpoint: production packaging and its owned-container harness are committed
(`cc30a1c`, `24e3290`). Explicit development-only standalone/default-managed
selection and removal of unconditional Compose health success are committed
(`b973488`); additive launch/readiness wire contracts are in `a6fc19b`.
Pure launch validation is committed in `0ba80dc`, with Rust health-wire checks
in `79de522`. Image startup (`3679446`) passes eight cases and detects the older fallback.
The bounded readiness monitor is committed in `6dafe00`, with 41 component
tests and fresh full-suite verification. The shared bound report validator is
committed in `09c04fa`, with 25 additional codec/presence tests and independent
review. Its 8KiB boundary preserves exact integer timing and rejects mismatched
identity/check/stage data; it does not authenticate the expected launch.
The complete task remains open: no authenticated health
listener or actual network/admission owners are composed into production yet.

**Files**

- Modify `apps/mcp-gateway/Dockerfile`, `src/live/grpc.ts`, `src/index.ts`, `src/managed/http-server.ts`, `deploy/compose/compose.mcp-proxy.yaml`.
- Create `apps/mcp-gateway/src/managed/readiness.ts`, `readiness.test.ts`, `apps/mcp-gateway/scripts/verify-image.mjs`.
- Modify `.dockerignore` if present; otherwise create a root-context `.dockerignore` excluding secrets, `.git`, targets and host dependency directories.

**Interfaces**

`checkStartup(config, dependencies) -> ReadinessReport` reports `live`, `ready`, `observedAtUnixUs`, generation/config hash and bounded checks. Admin health is a separate internal authenticated listener, not a public unauthenticated dump. `GET /livez` reports process liveness; `GET /readyz` reports dependency readiness without credentials or upstream URLs.

- [ ] Write image-level tests that invoke the image entry point and verify live Protobuf dependencies, configuration version, required secret files, health transitions and graceful exit. Missing governance/event schemas must fail the test.

```powershell
docker build -f apps/mcp-gateway/Dockerfile -t apex-mcp-gateway:working-test .
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-test --suite packaging
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-test --suite startup
```

`verify-image.mjs` must inspect the built image with `--network none --read-only`, import its actual live client module and assert both `existsSync(protoPath("governance.proto"))` and `existsSync(protoPath("event.proto"))`. It then exercises missing-config startup and a configured disposable runtime. It deletes only its own named containers.

The implemented `packaging` suite verifies imports/descriptors, production
output hygiene, confinement and cleanup only, and reports
`readinessVerified: false`. The separate `startup` suite checks eight original
entrypoint/profile outcomes with valid fixture identity and exact owned cleanup,
not MCP negotiation or configured health. Configured-health acceptance remains
required; neither existing suite closes that gate.

- [ ] Run against the current image first; confirm the missing schemas are a real red result.
- [ ] Change the build context to repository root, copy required contracts into a fixed image path and make `protoPath` resolve that packaged path consistently. Keep multi-stage dependency caching/non-root/read-only settings. Add health probes reflecting actual startup; remove `process.exit(0)` health checks. Require live mode for managed runtime and fail startup on missing configuration/trust material.
- [ ] Run image verification, gateway tests/typecheck/build, and Compose config validation. Verify the final image has no source secrets, private keys or runtime socket, and the local stdio regression still works only under its explicit development profile.
- [ ] Commit: `fix: package live gateway dependencies and real readiness checks`.

## Task 7: Restricted runtime agent, image catalog and secret staging

Checkpoint: `b5d0391` adds the workspace library, separately generated runtime
wire types, pure target/configuration relation checks and bounded inspection
comparison (43 tests). It does not yet start a service, authenticate an owner,
verify images, stage secrets or operate containers. The full task remains open;
engine Running is never treated as application readiness.

`d652276` adds a shared fallible manifest implementation with actual Rust-export
parity, plus strict deployment-owned certificate policy and real mTLS role/grant
tests. Policy checks retain integer microseconds and return borrowed point-in-time
identity evidence, not enrollment or a current operation permit. The existing
cached CI job now runs the shared packages and agent tests (`68d8d77`).
Policy loading/revocation delivery, current PostgreSQL operation proof, image
verification, staging and engine effects remain required before this task closes.

**Files**

- Create `apps/proxy-runtime-agent/{Cargo.toml,build.rs}`, `src/{lib.rs,main.rs,service.rs,config.rs,docker.rs,secrets.rs,ownership.rs}`, `tests/runtime_boundary.rs`.
- Add the Rust workspace member and update `Cargo.lock`.
- Create `apps/control-plane-api/src/proxy/runtime_client.rs`; modify `proxy/provider.rs`, `proxy/service.rs`, `startup/service/proxy.rs`.
- Create `deploy/runtime-agent/{install.md,apex-proxy-runtime-agent.service,policy.example.json}`.

**Interfaces**

Implement the task-1 runtime RPCs with generated types. Agent configuration supplies its authenticated control-plane identity allowlist, approved image catalog, secret provider root, dedicated state directory, permitted networks and Docker endpoint. Requests refer only to catalog/reference IDs and generation/fencing values.

`ensure` validates the manifest, resolves a pullable approved `repository@sha256:digest`, verifies its configured signing policy, stages a config plus scoped secrets at mode 0400/read-only for UID 10001, and creates a deterministically named container. Raw credentials are files, not Docker env values. The response contains runtime handle and safe metadata, never staged contents or arbitrary host paths.

- [ ] Add tests for unauthenticated/wrong-role requests, forged ownership labels, stale fencing, arbitrary image/host-path/flag injection, symlink escape, duplicate ensure and a real inspect response. Secret canaries must be absent from command argv, `docker inspect`, RPC results and logs.

```rust
#[test]
fn inspect_reads_the_id_field_not_the_entire_json_document() {
    let body = r#"[{"Id":"sha256:abc","State":{"Status":"running"}}]"#;
    assert_eq!(parse_inspect_id(body).unwrap(), "sha256:abc");
}
```

Implement `parse_inspect_id(&str) -> Result<String, RuntimeError>` in `docker.rs`, with `RuntimeError` a bounded code enum in the same module. Its production parser also validates required ownership labels and exact ID shape; this small test covers parsing separately.

- [ ] Run `cargo test -p apex-proxy-runtime-agent --test runtime_boundary`; for Docker-backed cases, missing Docker is an explicit precondition failure in CI. Capture the current provider's inspect parsing failure before replacing it.
- [ ] Move/reuse the narrow command construction behind the agent, without importing a control-plane application crate. Share generated contracts through an appropriate shared crate if required. Limit command duration/output and redact Docker stderr. Harden the host service and dedicated rootless engine account. Replace control-plane direct `docker` calls with mTLS agent calls; absence/unreachable agent means `NotServing`.
- [ ] Verify real container UID/rootfs/capabilities/PID/memory/CPU/tmpfs/file-descriptor restrictions and config mounts. Verify two proxies get distinct scoped identity/material. Run existing supervisor tests to prove its control boundary was not changed.
- [ ] Commit: `feat: add restricted OCI runtime agent for managed proxies`.

## Task 8: Stable HTTPS routing and enforced per-proxy egress

**Files**

- Create `apps/proxy-runtime-agent/src/network.rs`, `network/{grants.rs,guard.rs}`, `src/routes.rs`, `tests/network_isolation.rs`.
- Create `apps/control-plane-api/src/proxy/routes.rs`, `apps/mcp-gateway/src/managed/network-dialer.ts`, `network-dialer.test.ts`.
- Modify `apps/mcp-gateway/src/managed/network.ts`, `mcp-http-transport.ts`, `http.ts`.
- Create `deploy/compose/mcp-working/{edge.conf,egress-policy.example.json}` and the task-20 profile's routing configuration.

**Interfaces**

`RouteBinding` contains resource URL, proxy/revision/generation, validated private destination, lease and `enabled`. Only the reconciler publishes it. The edge validates the original host/path, preserves MCP request headers, streams responses without buffering and accepts route updates only from the scoped control boundary.

`NetworkGrant` contains exact hostname, TLS server name, port, bounded CIDRs, private-grant approval and credential-binding ID. Resolve, intersect and pin connection IPs; preserve TLS hostname verification. A revision cannot expand its grant after DNS changes.

- [ ] Add real-network tests for an allowed private fixture, undeclared LAN address, metadata/loopback/link-local target, redirect escape, rebinding between validation and connect, cross-proxy access and direct CLI socket bypass. Test that an edge route cannot serve an unready/stale generation.

```text
grant: upstream-a.test:8443 AND 172.30.10.4/32
DNS answer 172.30.10.4 -> connect using that checked address, verify upstream-a.test TLS
DNS answer 172.30.20.4 -> deny, zero upstream requests
CONNECT metadata/host-control address -> deny at both application and egress guard
```

- [ ] Run `cargo test -p apex-proxy-runtime-agent --test network_isolation` and `pnpm --dir apps/mcp-gateway exec tsx --test src/managed/network-dialer.test.ts`; verify the old blanket-private rejection and unpinned fetch are exposed.
- [ ] Implement a provider-owned internal network per proxy, with a bounded egress guard as its only outbound path. The gateway is not dual-homed onto a general bridge. The guard accepts only validated destinations; deny direct network bypass at the provider boundary, including CLI processes. Keep the Docker/host control network unreachable. Use per-proxy resolver/network configuration and fail preflight when the host cannot enforce these controls. Network policy is not merely `HTTP_PROXY` environment advice.
- [ ] Implement the pinned dialer and restrictive redirect policy, exact HTTPS routes and origin semantics. Prove a trusted fixture CA is used without disabling certificate verification. Test SDK POST/GET/DELETE and streaming through the real edge, including cancellation and stale session routing.
- [ ] Commit after both isolation layers pass: `feat: enforce proxy routes and scoped private upstream egress`.

## Task 9: Durable reconciler and real pause/resume/retire

**Files**

- Modify `apps/control-plane-api/src/proxy/reconciler.rs`, `proxy/service/operations/lifecycle.rs`, `inspection.rs`, `startup/service/proxy.rs`, `startup/service/workers.rs`.
- Create `apps/control-plane-api/src/proxy/reconcile/{observe.rs,transitions.rs,recovery.rs}`, `tests/proxy_runtime_lifecycle.rs`.
- Modify gateway `src/managed/readiness.ts`, `http-server.ts`, `managed-executor.ts`; create `src/managed/admission-state.ts`, `admission-state.test.ts`.

**Interfaces**

The operation worker consumes the task-2 journal, compiled config and runtime agent. `reconcile_once(operation_id, fencing_token)` records observations transactionally. State responses distinguish requested/observed status, freshness and safe reason codes; accepted deployment is not immediately ready.

`SetAdmission(false)` disables new calls in the gateway as well as edge routing. Admission is bound to a short-lived generation lease; a paused/stale generation cannot keep serving through an old session or direct internal connection. Drain waits a configurable bounded deadline, then cancels and terminates the process tree.

- [ ] Create a live lifecycle test with a deliberately slow upstream. Pause during an in-flight call, attempt another call with the existing session, wait for drain and confirm the container stops. Repeat with retire and verify the owned container is removed and history remains.

```text
Create -> Publish -> Deploy returns operation(PROVISIONING)
Wait for actual ready probe -> READY and route enabled
Pause accepted -> admission disabled -> route disabled -> drain -> PAUSED
Retire accepted -> admission disabled -> stop/remove -> credential release -> RETIRED
```

- [ ] Run `cargo test -p apex-control-plane-api --features postgres --test proxy_runtime_lifecycle`; before wiring, assert that the old pause only changed the database.
- [ ] Wire startup/periodic reconciliation to the real worker, not the currently unused in-memory reconciler alone. Readiness checks image/config hashes, valid identity/JWKS, MCP initialize/catalog, governance/policy, evidence availability and network enforcement. Record the probe result and timestamp; do not create one audit event per health poll. Catch lost responses with inspection and fencing, not duplicate provisioning.
- [ ] Pass the live sequence, repeated command, restart during provisioning, missing dependency and lease-expiry tests. Verify no unconditional `Ready` on `running`, no paused runtime admission, no retirement provisioning, and no indefinite waits.
- [ ] Commit: `fix: reconcile proxy lifecycle into real runtime and routing state`.

## Task 10: Safe replacement, rotation, rollback and crash recovery

**Files**

- Modify `apps/control-plane-api/src/proxy/service/operations/inspection.rs`, `proxy/reconcile/transitions.rs`, `recovery.rs`, `proxy/store/postgres/lifecycle.rs`.
- Create `apps/control-plane-api/src/proxy/reconcile/replacement.rs`, `apps/control-plane-api/tests/proxy_revision_recovery.rs`.
- Modify `apps/proxy-runtime-agent/src/secrets.rs`, `ownership.rs`, `routes.rs`; add `tests/replacement_isolation.rs`.

**Interfaces**

`ReplacementOperation` references old/new immutable revisions and a new deployment generation. Stage -> probe -> atomic route switch -> drain old -> revoke/release owned material -> complete. Failed candidates never replace the last healthy route. A rollback reuses validated configuration but acquires fresh generation/credentials when prior credentials were revoked.

- [ ] Write a crash matrix for each boundary, including secret rotation before switch, failure after switch/before drain, two controllers, retry with the same request ID, invalid new secret and stale old generation.

```sql
-- Query assertion at every replacement crash point:
SELECT count(*) FROM mcp_proxy_routes
WHERE proxy_id = $1 AND enabled = true;
-- Result is 0 or 1, never 2; successful replacement ends at 1.
```

Create the route projection table in this task if task 8 used only the operation table; migrate atomically and preserve fencing semantics.

- [ ] Run `cargo test -p apex-control-plane-api --features postgres --test proxy_revision_recovery`; verify failures are runtime/ownership failures, not only state-machine unit assertions.
- [ ] Implement resumable replacement phases and atomic routing generation changes. Close old sessions/caches; revoke only proxy-owned issued credentials. For shared external static secret references, release the proxy binding without revoking another proxy's underlying credential. Unknown orphan containers are quarantined and reported for explicit operator action, not broadly deleted.
- [ ] Run real rotation/rollback/retire/restart tests and ensure evidence identifies old/new revision, generation and credential reference without values. Test restoration from a persisted operation snapshot with no in-memory runtime map. Resume a completed operation as a no-op.
- [ ] Commit: `feat: recover proxy replacement rotation and rollback safely`.

## Runtime acceptance checkpoint

- [ ] A dynamically provisioned production image serves the existing read-only path through the allocated HTTPS endpoint.
- [ ] Runtime identity, config and network enforcement are inspected, not assumed from requested flags.
- [ ] Pause, resume, retire, replacement and restart affect actual traffic as documented.
- [ ] Feed results into the G1 browser/call/evidence harness; do not mark the entire product complete here.
