# Live Apex Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the TypeScript gateway's local Apex stubs with live mTLS clients and prove one server-observable governed portfolio read.

**Architecture:** `control-plane-api` serves a dedicated, gateway-authenticated GovernanceGateway for authorization and policy metadata. `event-ingest` remains the sole durable event admission service, reached by a certificate-bound gateway credential. The TypeScript gateway selects local adapters only for local mode and live adapters only when all live configuration is present.

**Tech Stack:** Rust 2024, tonic/prost, existing rustls mTLS and `apex-policy`/`apex-domain` contracts, Node 24 TypeScript, `@grpc/grpc-js`, `@grpc/proto-loader`, MCP stdio, Zod, Docker Compose, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-03-live-vertical-slice-and-hardening-design.md`

## Global Constraints

- The active path is one read-only `portfolio.read`; held roadmap work remains paused.
- Live mode has no local authorization fallback and fails closed when required configuration is incomplete.
- The TypeScript gateway owns no policy storage and no second audit ledger.
- `event-ingest` remains the only event admission authority.
- Private material is bounded to its trusted base, rejects symlinks and unsafe permissions, and is never logged.
- Successful tool results require durable event admission; downstream fanout is asynchronous.
- No file modified by this plan may exceed 600 lines of source or tests.

---

### Task 1: Add the governance wire contract

**Files:**
- Create: `contracts/proto/apex/v1/governance.proto`
- Modify: `apps/control-plane-api/build.rs`
- Modify: `apps/control-plane-api/Cargo.toml`
- Test: `apps/control-plane-api/src/service/governance_tests.rs`

**Interfaces:**
- Produces `apex.v1.GovernanceGateway.Authorize` and `GetPolicy` messages consumed by Rust and the dynamic TypeScript client.
- `Authorize` accepts `GovernanceAuthorizationRequest` with caller, exact scope, tool, action, resource, classification, and trace.
- `Authorize` returns `GovernanceAuthorizationDecision` with `outcome`, `policy_id`, `reason_code`, and `field_restrictions`.
- `GetPolicy` accepts `GovernancePolicyRequest` and returns `GovernancePolicySnapshot` with scope, policy ID, and uint64 revision.

- [ ] **Step 1: Write the failing contract-compilation test**

Add a Rust test that constructs the generated request/response types, checks the service client/server modules exist, and asserts the generated enum names include `ALLOWED`, `DENIED`, and `REQUIRES_APPROVAL`.

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cargo test -p apex-control-plane-api --lib governance_tests --features test-support`

Expected: FAIL because `governance_tests` and the generated governance types do not yet exist.

- [ ] **Step 3: Write the minimal protobuf and build wiring**

Define unique `GovernanceCaller`, `GovernanceScope`, and `GovernanceTrace` messages to avoid package-name collisions with `event.proto`; compile `governance.proto` alongside `control.proto` in `build.rs`; add `apex-policy` to the control-plane dependencies for the implementation tasks.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cargo test -p apex-control-plane-api --lib governance_tests --features test-support`

Expected: PASS with generated client/server types available.

- [ ] **Step 5: Commit**

```powershell
git add contracts/proto/apex/v1/governance.proto apps/control-plane-api/build.rs apps/control-plane-api/Cargo.toml apps/control-plane-api/src/service/governance_tests.rs
git commit -m "feat: define live Apex governance RPC"
```

### Task 2: Implement the dedicated Apex governance authority

**Files:**
- Create: `apps/control-plane-api/src/governance.rs`
- Modify: `apps/control-plane-api/src/lib.rs`
- Modify: `apps/control-plane-api/src/service.rs`
- Modify: `apps/control-plane-api/src/startup/service.rs`
- Modify: `apps/control-plane-api/src/startup/service/resolvers.rs`
- Modify: `apps/control-plane-api/src/startup/env/credentials.rs`
- Modify: `deploy/compose/compose.gateway-ref.yaml`
- Modify: `deploy/compose/live-mtls/generate_pki.py`
- Test: `apps/control-plane-api/src/governance_tests.rs`

**Interfaces:**
- `GatewayTokenAuthenticator::new(token: &str) -> Result<Self, io::Error>` stores only a digest and applies bounded failure throttling.
- `GatewayTokenAuthenticator::authenticate(&MetadataMap) -> Result<(), tonic::Status>` accepts only one ASCII `Bearer` value.
- `GovernanceGatewayService::new(config: GovernanceConfig, auth: GatewayTokenAuthenticator) -> Self`.
- `GovernanceConfig` contains the immutable `HashSet<String>` of allowed portfolio resource references, policy ID, revision, and field restrictions.
- `GovernanceGatewayService` implements the generated `governance_gateway_server::GovernanceGateway` trait.

- [ ] **Step 1: Write failing tests for credential isolation and policy behavior**

Cover: missing token is unauthenticated; operator token is rejected; duplicate authorization headers are rejected; malformed request is invalid; an allowed exact portfolio returns `ALLOWED` with the configured policy identity and restrictions; a disallowed resource returns `DENIED` with no restrictions; `GetPolicy` returns the exact requested scope and revision.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cargo test -p apex-control-plane-api governance --features test-support`

Expected: FAIL because the authenticator, service, and config do not exist.

- [ ] **Step 3: Implement the service and startup wiring**

Use the existing bounded bearer parser shape from `auth.rs`, a separate `APEX_CONTROL_MCP_GATEWAY_TOKEN_FILE` secret, and a separate `mcp-gateway-client` certificate generated by the lab PKI. Add the service beside, not inside, `ControlGatewayService`; add health status `apex.v1.GovernanceGateway`; require the dedicated token at startup for the runnable service; set the compose allowlist to the SHA-256 resource for `northstar-401k`.

- [ ] **Step 4: Run the focused tests and type/build checks**

Run: `cargo test -p apex-control-plane-api governance --features test-support`; `cargo check -p apex-control-plane-api`; `docker compose -f deploy/compose/compose.gateway-ref.yaml config`

Expected: PASS and compose config renders without warnings that omit the gateway credential.

- [ ] **Step 5: Commit**

```powershell
git add apps/control-plane-api contracts deploy/compose/compose.gateway-ref.yaml deploy/compose/live-mtls/generate_pki.py
git commit -m "feat: serve live Apex governance decisions"
```

### Task 3: Implement the TypeScript live gRPC adapters

**Files:**
- Create: `apps/mcp-gateway/src/live/grpc.ts`
- Create: `apps/mcp-gateway/src/live/secrets.ts`
- Create: `apps/mcp-gateway/src/live/governance.ts`
- Create: `apps/mcp-gateway/src/live/events.ts`
- Create: `apps/mcp-gateway/src/live/canonical.ts`
- Create: `apps/mcp-gateway/src/live/uuid.ts`
- Modify: `apps/mcp-gateway/package.json`
- Modify: `apps/mcp-gateway/pnpm-lock.yaml`
- Test: `apps/mcp-gateway/src/live/governance.test.ts`
- Test: `apps/mcp-gateway/src/live/events.test.ts`

**Interfaces:**
- `loadLiveConfig(env: NodeJS.ProcessEnv): LiveConfig` validates complete all-or-none governance and event settings.
- `createLiveGovernanceClient(config: GovernanceClientConfig): ApexGovernance`.
- `createLiveEventsClient(config: EventClientConfig): ApexEvents`.
- `createUuidV7(): string`, `timestampFromUuidV7(id: string): string`.
- `jsonToStruct(value: JsonValue): StructWire`, `structToJson(value: StructWire): JsonValue`.
- `canonicalizeJson(value: JsonValue): string`, `canonicalEventHash(envelopeWithoutEventHash: JsonValue): string`.

- [ ] **Step 1: Write failing adapter tests**

Test all-or-none configuration; path rejection for symlink/oversized/private files; exact protobuf request mapping; enum decoding; deadline mapping to `GatewayError`; Struct round-trip; six-digit timestamp; deterministic hash for a fixed envelope; event receipt mapping and no raw error detail in safe failures.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `pnpm --dir apps/mcp-gateway test -- src/live/governance.test.ts src/live/events.test.ts`

Expected: FAIL because the live modules and dependencies do not exist.

- [ ] **Step 3: Add dependencies and implement the adapters**

Use `@grpc/grpc-js` and `@grpc/proto-loader` with `keepCase: true`, string enums, string longs, and bounded package/proto paths. Use `grpc.credentials.createSsl` for CA and client identity. Every unary call uses a deadline. Encode the metadata-only TOOL event through the existing event proto and compute a Rust-compatible canonical hash over the decoded Struct view.

- [ ] **Step 4: Run gateway tests and static checks**

Run: `pnpm --dir apps/mcp-gateway test`; `pnpm --dir apps/mcp-gateway typecheck`; `pnpm --dir apps/mcp-gateway build`

Expected: PASS with no token or provider diagnostics in test output.

- [ ] **Step 5: Commit**

```powershell
git add apps/mcp-gateway
git commit -m "feat: add live Apex TypeScript clients"
```

### Task 4: Select live mode and prove the operator-visible path

**Files:**
- Modify: `apps/mcp-gateway/src/index.ts`
- Modify: `apps/mcp-gateway/src/execution.ts`
- Modify: `apps/mcp-gateway/.env.example`
- Modify: `apps/mcp-gateway/README.md`
- Create: `deploy/compose/gateway-ref/run_live_mcp.py`
- Modify: `.github/workflows/live-mtls-e2e.yml`
- Test: `apps/mcp-gateway/src/index.test.ts`
- Test: `deploy/compose/gateway-ref/test_run_live_mcp.py`

**Interfaces:**
- `buildGatewayDependencies(env: NodeJS.ProcessEnv): GatewayDependencies` selects `StaticLocalApex` only for local mode and requires live governance/events in live mode.
- The live proof script launches the built gateway with a bounded environment and speaks MCP stdio; it prints only safe IDs, statuses, sizes, and hashes.

- [ ] **Step 1: Write failing mode-selection and proof tests**

Assert live mode rejects incomplete configuration, never instantiates local policy, and maps the seeded portfolio request to live dependencies. Add a script-level test that rejects a response lacking a server-derived event evidence record.

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `pnpm --dir apps/mcp-gateway test -- src/index.test.ts`; `python -m pytest deploy/compose/gateway-ref/test_run_live_mcp.py -q`

Expected: FAIL because live selection and the proof script are not present.

- [ ] **Step 3: Implement selection and the proof**

Build local dependencies only when `APEX_MCP_GOVERNANCE_MODE` is `local`; in live mode create both clients and use the existing local portfolio adapter for this read-only slice. Extend compose secrets/env with the gateway client material and token. The proof must query the existing server-side projection/evidence endpoint or NATS-derived operator verification, and must fail if only the gateway process's local sink saw the event.

- [ ] **Step 4: Run the complete local checks**

Run: `pnpm --dir apps/mcp-gateway test`; `pnpm --dir apps/mcp-gateway typecheck`; `pnpm --dir apps/mcp-gateway build`; `cargo test --workspace --all-targets`; `python -m pytest deploy/compose/gateway-ref/test_run_live_mcp.py -q`; `docker compose -f deploy/compose/compose.gateway-ref.yaml config`

Expected: PASS; the known pnpm `esbuild` approval issue may be bypassed only with the repository's existing direct test/typecheck commands and must be recorded, not silently changed.

- [ ] **Step 5: Commit**

```powershell
git add apps/mcp-gateway deploy/compose/gateway-ref .github/workflows/live-mtls-e2e.yml
git commit -m "test: prove live governed portfolio read"
```

### Task 5: Merge, push, and hand off to the second loop

**Files:**
- Modify: `docs/roadmap.md`
- Modify: `docs/phase-0.5-progress.md`

- [ ] **Step 1: Run the live stack and proof**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/live-mtls/run.ps1`; `powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/gateway-ref/run.ps1`; `python deploy/compose/gateway-ref/run_live_mcp.py`.

Expected: the MCP call is allowed, filtered, durably admitted, and visible through server-derived evidence; the denial case has no adapter call.

- [ ] **Step 2: Inspect GitHub Actions**

Push the branch and inspect both workflows with `gh run list --branch codex/live-vertical-slice` and `gh run view <run-id> --log-failed` until required jobs are terminal. Fix only failures on this active path.

- [ ] **Step 3: Merge and push the verified branch**

```powershell
git checkout master
git pull --ff-only origin master
git merge --no-ff codex/live-vertical-slice -m "merge: complete live Apex vertical slice"
git push origin master
```

- [ ] **Step 4: Update roadmap evidence**

Record the commit and CI run URLs, the exact server-derived evidence check, and the held-work list. Do not mark unrelated roadmap items active.

- [ ] **Step 5: Start the second loop**

Arm one dynamic monitored shell loop with sentinel `AGENT_LOOP_WAKE_REFACTOR` for the prompt: “Continue the approved codebase readability/security/throughput refactor. Split every tracked source/test file over 600 lines without behavior change, run security checks, benchmark throughput before/after, commit and push only verified active-roadmap changes, and keep held work paused.” Do not create a duplicate loop if one is already armed.
