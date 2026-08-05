# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Apex is a self-hosted, cloud-agnostic control plane for AI agents (observability, governance, evaluation, security, cost). Scope hierarchy: installation → workspace → namespace → AgentGroup → agent → run.

**Status:** Phase 0 (event contract, Python SDK, hardened ingest admission, Security Alerts, durable outbox/fanout, storage contracts, Compose provider slots) is complete. Phase 1 (operator UI, live control-plane API) has only started — the React UI is a static preview with illustrative data; it does not call any backend yet. Don't assume control-plane API or authenticated-session code exists.

The only two components with real, runnable implementations today are `apps/event-ingest` (Rust gRPC gateway) and `packages/sdk-python` (Python instrumentation SDK). `crates/*` are currently empty placeholder directories reserved for future extraction from `event-ingest`. `apps/control-plane-api` is empty. `apps/operator-ui` is a static Vite preview with no backend calls.

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

# Clippy (CI only fails on hard errors, not style warnings)
cargo clippy --lib --features test-support -- -W clippy::all

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

CI (`.github/workflows/ci.yml`): `python-sdk`, `rust-ingest` (test + clippy), `rust-sast` (cargo audit + cargo deny), `python-sast` (bandit + pip-audit), `lab-only-settings-gate`, `signed-bundles`. `.github/workflows/live-mtls-e2e.yml` runs the live-mTLS + Postgres + MinIO gates on a real Docker daemon (push to main/master or manual dispatch; not required on every PR since runner Docker networking can be flaky).

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

This is the one component with real depth. Module map (`src/`):

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

### Repository layout

```
apps/            event-ingest (real), control-plane-api (empty), operator-ui (static preview), reference-providers (Python mTLS stub providers for local/CI)
crates/           domain, event-contract, policy-engine, authz, cost-ledger, archive-provider, diagnostics -- all currently EMPTY placeholders
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
