# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Apex is a self-hosted, cloud-agnostic control plane for AI agents (observability, governance, evaluation, security, cost). Scope hierarchy: installation → workspace → namespace → AgentGroup → agent → run.

**Status:** Phase 0 (event contract, Python SDK, hardened ingest admission, Security Alerts, durable outbox/fanout, storage contracts, Compose provider slots) is complete. The out-of-band (OOB) control gateway — originally scoped as Phase 0.5 — is also built and real: cooperative controls (`stop`/`pause`/`resume`/`inject`/`set_budget`/`resolve_hold`), a non-cooperative `force_stop` enacted by a dedicated supervisor process rather than the agent's own, durable per-command delivery tracking, and operator-facing bulk/list/cancel APIs. Phase 1 (operator UI wired to a live backend) has not started — the React UI is still a static preview with illustrative data and calls no backend. Don't assume the UI reflects real control-plane state.

Four components have real, runnable implementations: `apps/event-ingest` (Rust gRPC ingest gateway), `apps/control-plane-api` (Rust gRPC OOB control gateway), `apps/agent-supervisor` (Rust process supervisor that enacts non-cooperative `force_stop`), and `packages/sdk-python` (Python instrumentation SDK, including the reference agent runtime that consumes control-plane-api's control channel). The Rust workspace now owns reusable contract, domain, auth, policy, security, and durability crates; applications depend on those shared boundaries rather than on one another. `apps/operator-ui` is still a static Vite preview with no backend calls.

## Current execution focus

Follow [docs/roadmap.md](docs/roadmap.md) as the execution source of truth. The Rust workspace, shared-crate extraction, durable admission/fanout separation, and Apex governance interfaces are complete. The only active work now is the remaining assessment-directed sequence: build a thin TypeScript MCP gateway, add one read-only RIA portfolio tool, and prove the live operator-visible vertical slice. Treat all other feature and phase roadmaps as paused unless work is required to unblock this sequence or fix a security defect, regression, or data-integrity issue.

## Commands

### Rust gateway (`apps/event-ingest`)

Run all commands from `apps/event-ingest`.

```bash
# Core unit tests (no live infra needed; postgres/valkey/live-mtls tests self-skip)
cargo test --lib --features test-support

# Full integration suite (gateway.rs, e2e_path.rs, nats_local.rs, startup_paths.rs)
cargo test --features test-support

# One test by name
cargo test --features test-support <test_name> -- --nocapture

# Compile-check the optional Postgres/Valkey backends
cargo check --features valkey,postgres

# Clippy -- CI enforces this as a hard gate across every target/feature, not advisory
cargo clippy --locked --all-targets --all-features -- -D warnings

# Dependency/license hygiene (deny.toml)
cargo audit
cargo deny check
```

**Feature flags:** `test-support` (test-only code paths, e.g. loopback sink destinations), `valkey` (optional Redis-protocol rate-limit accelerator), `postgres` (multi-process authoritative outbox/idempotency backend). Production defaults to file-backed outbox/idempotency with no `valkey`/`postgres`.

**To exercise the Postgres- and live-mTLS-backed tests** (`idempotency::postgres_tests`, `outbox::postgres_tests`, `tests/live_mtls.rs`), live infra must be running first — see `deploy/compose/live-mtls/README.md`. Short version:

```powershell
cd deploy/compose/live-mtls
python generate_pki.py
python render_configs.py
docker compose -f compose.yaml up -d
$env:APEX_LIVE_MTLS='1'
$env:APEX_LIVE_MTLS_SECRETS = (Resolve-Path .\secrets-host).Path
$env:APEX_ALLOW_LOOPBACK_SINKS='1'   # required alongside APEX_LIVE_MTLS for the HTTP sink loopback tests
cd ../../../apps/event-ingest
cargo test --features "test-support,valkey" -- --nocapture
```

For Postgres tests specifically, also bring up `deploy/compose/compose.e2e.yaml`'s `postgres` service and set `APEX_POSTGRES_URL` (loopback `sslmode=disable` also requires `APEX_ALLOW_POSTGRES_PLAINTEXT=1`) and run with `--features postgres`. **Wait for the Postgres container's healthcheck to report healthy before running tests** — connecting before that fails with a misleadingly generic `InvalidIdempotencyConfiguration`/`InvalidOutboxConfiguration` error (the transport-classification error code is deliberately generic and doesn't distinguish "bad config" from "transient connect failure").

**Coverage** (`cargo-llvm-cov`, already installed in dev environments that need it):
```bash
cargo llvm-cov --features valkey,postgres,test-support --summary-only
```
Exclude `startup/service.rs` and `main.rs` from any coverage target — they're pure process-wiring code (env parsing → build sinks → start the gRPC server) only exercisable by running the compiled binary, never by a test harness. Several other functions (`startup/env.rs`, `startup/auth.rs`, `startup/secrets.rs`) are thin `env::var(...)` wrappers that structurally can't be unit-tested here: this crate has `unsafe_code = "forbid"` and Rust 2024 requires `unsafe` to call `env::set_var`/`remove_var`, so tests can't set env vars. The working pattern when a value needs to be both env-driven in production and testable is to split it into a pure `_value`-suffixed function taking an `Option<&str>`/bool parameter (see `attempts` / `attempts_value` in `startup/env.rs`, or `plaintext_explicitly_allowed` / `parse_and_classify` in `postgres_transport.rs`) — refactor for testability rather than trying to inject env vars.

### Control gateway (`apps/control-plane-api`)

Run all commands from `apps/control-plane-api`.

```bash
# Full test suite (postgres/valkey/live-* tests self-skip without their env vars)
cargo test --locked --features "test-support,postgres,valkey" -- --nocapture

# Compile-check the optional Postgres feature
cargo check --locked --features postgres

# Clippy -- same hard gate as event-ingest
cargo clippy --locked --all-targets --all-features -- -D warnings
```

**Feature flags:** `test-support` (test-only seams, e.g. injecting a peer identity without a real mTLS handshake), `postgres` (multi-replica-authoritative command inbox/outbox), `valkey` (distributed admission-rate-limit accelerator). Production defaults to file-backed inbox/outbox with no `postgres`/`valkey`.

**Live-infra tests** are gated behind their own env vars and self-skip when unset: `APEX_CONTROL_LIVE_MTLS`, `APEX_CONTROL_LIVE_KEYCLOAK`, `APEX_CONTROL_LIVE_POLL` (spawns a real agent process and drives it through stop/pause/resume/budget/inject over a real poll loop — see `deploy/compose/gateway-ref/agent_under_control.py`), `APEX_CONTROL_LIVE_POSTGRES` (also needs `APEX_CONTROL_POSTGRES_URL` — this crate's own variable, deliberately never the same name as `event-ingest`'s `APEX_POSTGRES_URL`), `APEX_CONTROL_LIVE_VALKEY`.

### Agent supervisor (`apps/agent-supervisor`)

Run all commands from `apps/agent-supervisor`.

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

No feature flags. One instance per supervised agent run: wraps and spawns the agent as this process's real OS child, in its own process group, holds a credential distinct from (and never visible to) the agent process it supervises, polls `control-plane-api` for `force_stop`, and kills the whole process group — not just the top-level process — on receipt.

The real process-group-kill proof (`tests/process_group_kill.rs`) is platform-sensitive: the full multi-process-tree kill only runs `#[cfg(unix)]` (`killpg` has no Windows equivalent), so a green local run on a Windows dev box only exercises the weaker "direct child dies" fallback — it does **not** prove the Unix path works. This bit once: a real bug in that test's own liveness check (conflating a SIGKILLed zombie with a still-running process) only surfaced on real Linux CI. Don't trust this test green until you've seen it pass on CI, not just locally on Windows.

### Python SDK (`packages/sdk-python`)

```bash
python -m pip install --editable ".[dev]"
python -m pytest -q                     # cov-fail-under=95 is already wired into pyproject.toml
python -m pytest tests/test_bundle_signing.py -q --no-cov
```
On Windows, a stale locked `%TEMP%\pytest-of-<user>` directory from a previous run can cause spurious `PermissionError` failures across many tests at once — point `TEMP`/`TMP` at a fresh directory rather than assuming a real regression.

### Operator UI (`apps/operator-ui`)

```bash
pnpm install
pnpm dev        # http://127.0.0.1:4173, illustrative data only
pnpm typecheck
pnpm build
pnpm audit      # not in CI yet; run manually for dependency CVEs
```

### Repo-wide checks

```bash
python3 scripts/check_lab_only_settings.py   # fails if a lab-only escape hatch (e.g. unpinned mTLS client) leaks into a non-lab deploy manifest
python3 deploy/compose/e2e/run_gates.py      # full deploy-time gate suite (Docker required): live mTLS, Postgres, MinIO Object-Lock, optional Azure/GCS
```

CI (`.github/workflows/ci.yml`): `python-sdk`, `rust-ingest` (test + clippy), `rust-control-plane` (test + clippy), `rust-agent-supervisor` (test + clippy), `rust-sast` (cargo audit + cargo deny, matrixed across all three Rust crates — each carries its own `Cargo.lock`/`deny.toml`), `python-sast` (bandit + pip-audit), `lab-only-settings-gate`, `signed-bundles`. `.github/workflows/live-mtls-e2e.yml` runs the live-mTLS + Postgres + MinIO gates on a real Docker daemon (push to main/master or manual dispatch; not required on every PR since runner Docker networking can be flaky).

## Conventions

- **File size:** any hand-written source file over 600 lines should be split into smaller files. Applies to source you'd actually edit (Rust `.rs`, Python `.py`, TS/TSX/JS) — not generated code (protobuf stubs, `_generated/`), vendored dependencies, lock files, or fixture/snapshot data, where line count is meaningless and splitting would just fight the generator.

## Architecture

### Target dataflow

```
Agents/SDKs → Rust event-ingest (gRPC/Protobuf, mTLS) → NATS JetStream (durable backbone)
                                                       → Control Plane API → PostgreSQL (mutable control state)
                                                       → Processors → ClickHouse (trace/analytics)
                                                                    → Archive adapter (WORM/immutable)
Operator UI → Control Plane API ← Self-hosted identity provider
```
Mutable control state (Postgres), analytical trace storage (ClickHouse), and immutable archive storage are deliberately separate systems behind portable provider contracts — never conflate them.

### `apps/event-ingest` internals

Module map (`src/`):

- **`auth/`** — gRPC service (`service.rs`: admission rate-limiting, blocking-task semaphore, replay-worker spawn) and credential verification (`verifier.rs`: `BearerTokenVerifier` with per-identity + distributed failure-rate tracking).
- **`gateway/`** — `IngestGateway`/`AuthenticatedIngestAdapter`: the core admit → validate → idempotency-reserve → fanout → commit/abort pipeline.
- **`validation/`** — envelope/scope/identifier/secrets validation. `contains_secret_like_data` in `validation/secrets.rs` is a best-effort heuristic scanner, not a hard gate; it deliberately never flags keys ending in `hash`/`digest`/`id` even with a sensitive-sounding prefix (see the `hash_and_identifier_fields_are_not_secret_false_positives` test) — don't "fix" that without checking that test first, it encodes an intentional false-positive-avoidance tradeoff.
- **`idempotency/` and `outbox/`** — each has three backends behind a shared trait: `memory` (tests), `file` (production default, single-process), `postgres` (feature-gated, multi-process-authoritative). The outbox pattern is: enqueue → fanout → mark-complete; a crash between fanout success and mark-complete means replay must be idempotent at every sink. `idempotency/postgres.rs` has a `reap_expired` reaper (a crash between `reserve()` and `commit()`/`abort()` otherwise leaves a permanently-stuck `pending` row, since the `reservation_id → token` mapping only lives in that process's memory) — wired into a periodic background task in `startup/service.rs` with its own lazily-established connection so a reaper-connectivity hiccup can never block gateway startup.
- **`sinks/` and `http_sinks/`** — fanout to JetStream/ClickHouse/archive-provider over authenticated HTTPS+mTLS. `http_sinks/config.rs`'s `build_client` does real SSRF hardening: resolves DNS once at build time and pins the client to those addresses (anti-rebinding), rejects loopback/private/link-local/CGNAT (100.64.0.0/10) destinations by default, and only allows private destinations via `APEX_ALLOW_PRIVATE_SINK_DESTINATIONS` + an explicit per-host allowlist. Both HTTP sinks and the NATS client (`nats/client.rs`) implement rate-limited rebuild-after-failure (re-resolve DNS / rebuild the connection) rather than requiring a process restart to recover from IP churn or a broker outage — NATS's rebuild runs on a detached `std::thread::scope`/`spawn` specifically because `Runtime::block_on` panics if called from a thread that already has a tokio runtime entered, which is reachable via `publish()`'s `block_in_place` path.
- **`ephemeral/`** — non-authoritative acceleration (rate limits, fingerprints, deny hints) with `InMemoryEphemeralStore`, optional `ValkeyEphemeralStore` (feature `valkey`), and `FallbackEphemeralStore` that prefers Valkey and falls back to memory only on `Unavailable` (never masks other error kinds). Valkey command errors are treated as poisoning the connection (reconnect before the next call) because a read/write timeout can leave a reply unread on the wire, and reusing that connection risks silently reading the wrong command's reply.
- **`security/`** — append-only Security Alerts/findings store with deterministic detectors, redacted evidence, and scope-checked transitions.
- **`startup/`** — binary-only wiring (`mod` under `main.rs`, not part of the library crate `apex_event_ingest`): env parsing (`env.rs`), secret loading (`secrets.rs`), the file-bearer credential resolver (`auth.rs` — single-agent-staging only, requires explicit `APEX_FILE_BEARER_MODE` ack, fails closed after repeated reload failures or token staleness), and `service.rs` (the actual `run()` entrypoint, 0% unit-test-coverable by design, see Commands above).
- **`postgres_transport.rs`** — fail-closed transport selection: remote Postgres requires TLS + cert verification; loopback plaintext requires *both* `sslmode=disable` on a numeric loopback host *and* an explicit `APEX_ALLOW_POSTGRES_PLAINTEXT=1` (neither alone is enough — this mirrors the same "explicit opt-in, not just a permissive default" pattern used for private sink destinations).
- **`permissions/`** — platform-specific private-key-file permission checks (Unix mode bits vs Windows ACL via `icacls`/PowerShell). Both platforms are real, fail-closed checks; don't assume Windows is a stub.

### `apps/control-plane-api` internals

The OOB (out-of-band) control gateway: delivers cooperative commands to agents and tracks their delivery, independently authenticated from the ingest data path and reachable even when the rest of the platform is degraded (ADR-0006). Module map (`src/`):

- **`service/`** — the `ControlGatewayService` tonic impl, split by RPC group: `submit.rs` (`SubmitCommand`/`SubmitBulkCommand`, the write path — `force_stop` specifically requires two distinct operator approvals via `dual_approval.rs` before anything is recorded), `poll.rs` (`PollCommands`/`AckCommand`, the agent-facing path), `query.rs` (`GetCommandStatus`/`ListCommands`/`CancelCommand`, operator query/management), `proto_mapping.rs` (the internal-type ↔ wire-type mapping every handler group shares).
- **`inbox.rs` + `inbox/`** — durable per-command *delivery-state* tracking, a different question from the outbox's fanout-completion tracking (outbox: "did this reach the queryable trace"; inbox: "did the targeted agent retrieve it"). `inbox/state.rs` is the shared delivery-state machine the in-memory and file backends both build on; `inbox/file.rs` is the file-backed backend plus its append/replay journal; `inbox/backend.rs` is the trait/dispatch layer. `inbox_postgres.rs` (+ `inbox_postgres/`) is the multi-replica-authoritative Postgres backend, feature-gated. Enforces two independent capacity ceilings — one global, one per `(workspace_id, namespace_id)` — so a single tenant filling the inbox can never block delivery, including an emergency `stop`, to every other tenant.
- **`agent_auth.rs` (+ `agent_auth/`)** — agent-workload authentication for `PollCommands`/`AckCommand`: mTLS client certificate pinned to a bearer token, a third credential space distinct from both the ingest workload's and the operator's (see `auth.rs`). `agent_auth/revocation.rs` is a background-refreshed, file-backed revocation list (structurally mirrors `keycloak.rs`'s JWKS-cache pattern) so a compromised agent's credential can be pulled in seconds by editing a file, not by redeploying the process.
- **`auth.rs`** — independent operator authentication (static token table, lab/CI seam). **`keycloak.rs` (+ `keycloak/`)** — the production operator-credential path: verifies short-lived, scope-bound Keycloak-issued JWTs, closing the standard JWT pitfalls explicitly (algorithm confusion, missing issuer/audience checks, ID/access/refresh-token confusion, stale keys) rather than trusting library defaults.
- **`envelope.rs`** — validates operator input and builds the outbox-ready request plus the agent-facing delivery record, reusing the same admission rules `event-ingest` enforces on its own data path. `derive_target_command_id` deterministically derives each bulk-fanout target's own idempotency key from one operator-supplied `bulk_id`, so an operator never has to track one idempotency key per target.
- **`dual_approval.rs`** — the two-distinct-operator approval gate `force_stop`, and only `force_stop`, must pass before `SubmitCommand` ever records it.
- **`outbox.rs` / `replay.rs`** — the durable command outbox and its fanout-to-trace worker; the event-ingest outbox pattern reapplied to commands.
- **`startup/`** — binary-only wiring: `env/` (env parsing, split into `credentials.rs`/`keycloak.rs`/`limits.rs`/`backends.rs`), `service/` (the `run()` entrypoint's setup phases, split into `resolvers.rs`/`storage.rs`/`workers.rs`), plus `secrets.rs`, `fanout.rs`, `valkey.rs`.

The operator and agent-workload credential spaces must never be conflated — an operator credential cannot poll, an agent credential cannot submit. See `contracts/proto/apex/v1/control.proto`'s own module doc.

### `apps/agent-supervisor` internals

A separate binary from `control-plane-api`, one instance per supervised agent run, that exists to close a specific gap: every other control is *cooperative* — it relies on the agent's own process choosing to honor it — which is exactly the trust assumption that breaks once that process is compromised (the incident motivating this whole gateway: an agent-spawned PowerShell child process, not the agent's own top-level process, was the actual threat). `force_stop` is the backstop, and it needs real OS kill authority held by a process the supervised agent never has access to.

- **`process_group.rs`** — spawns the agent as this process's real OS child, in a new process group with itself as leader, and kills the whole group (not just the top process) on `force_stop`. The full guarantee is Unix-only (`killpg`); Windows falls back to killing the direct child alone, documented as an honest gap rather than silently claimed parity.
- **`child_env.rs`** — builds the agent's environment from scratch (`env_clear()` plus an explicit allowlist) instead of inheriting this process's own — the mechanism behind the credential-isolation property: a compromised agent process cannot read the credential that can order its own termination.
- **`credentials.rs`** — loads this process's own agent-workload credential, under a distinct `agent_id` convention from the agent it supervises (see `apps/control-plane-api/src/agent_auth.rs::supervisor_agent_id`).
- **`control_client.rs`** — the mTLS `PollCommands`/`AckCommand` client, built from its own independently generated proto stubs rather than a path-dependency on `control-plane-api`, so the one process holding the system's most sensitive credential doesn't also pull in that crate's Keycloak/Postgres/reqwest dependency tree.

### Repository layout

```
apps/            event-ingest, control-plane-api, agent-supervisor (all real), operator-ui (static preview, no backend calls), reference-providers (Python mTLS stub providers for local/CI)
crates/           apex-contract, apex-domain, apex-auth, apex-security, apex-durability (shared Rust foundations), with later policy/telemetry/cost crates still reserved
packages/         sdk-python
contracts/        proto/apex/v1 (versioned protobuf), jsonschema
config/           profiles, policies, pricebooks
deploy/           compose/ (compose.yaml = production reference, requires operator-supplied digest-pinned images; compose.e2e.yaml + compose.gateway-ref.yaml = CI/dev reference topologies; live-mtls/ = real-TLS local harness), lab/, helm/, kubernetes/
docs/             architecture/, api/, security/, operations/
examples/         reference-agent, evaluation-flow
tests/            contract/, integration/, e2e/, security/ (repo-root level; separate from apps/event-ingest/tests/)
```

### Security conventions worth knowing before touching deploy/compose files

- Production images (`compose.yaml`) are pinned by digest with no default — `${VAR:?message}` — deliberately, so a missing/placeholder value fails loudly instead of silently resolving to something unpinned. Reference/CI overlays (`compose.e2e.yaml`, `compose.gateway-ref.yaml`) pin specific digests too; only `live-mtls/compose.yaml` uses floating tags (it's explicitly local-only, never production).
- `scripts/check_lab_only_settings.py` enforces that lab-only escape hatches (currently: `APEX_PROVIDER_ALLOW_UNPINNED_CLIENT`, world-readable `0644` key permissions) never appear in a deployment manifest outside their reviewed allowlist. When adding a new lab-only flag, add it to that script's `GUARDED_PATTERNS`, not just to the lab compose file.
- MinIO in `compose.e2e.yaml` intentionally runs `chainguard/minio`, not `minio/minio` — MinIO stopped publishing free community Docker images in October 2025, so the upstream image is permanently stuck without security patches. Chainguard rebuilds the same MinIO source daily with current patches. That image runs as non-root (uid 65532) with no shell, so a `minio-data-init` service must `chown -R` the named volume before MinIO starts (a **recursive** chown — a previous run under the old root-owned image leaves nested files that a non-recursive chown won't fix).
