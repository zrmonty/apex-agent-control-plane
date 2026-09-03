# Apex foundation boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Put the existing Apex Rust applications in one workspace and make reusable event, security, authentication, and durability code available through shared crates without changing the externally visible event or control contracts.

**Architecture:** Add a root Cargo workspace, then extract the reusable layers from `apps/event-ingest` in dependency order: contract and domain types, errors and validation, authentication and ephemeral stores, security findings, and durability/outbox code. Rewire `apps/event-ingest` and `apps/control-plane-api` to those crates while preserving compatibility re-exports. The existing durable-enqueue-only admission and background fanout behavior is already present in `apps/event-ingest`; this plan preserves it and adds regression coverage where the baseline reveals a gap.

**Tech Stack:** Rust 2024, Cargo workspace resolver 3, Tokio, tonic 0.14, prost 0.14, NATS JetStream, PostgreSQL, rustls with the ring provider, existing file/memory/Postgres durability backends, and the repository's current Rust test and lint commands.

**Spec:** `docs/superpowers/specs/2026-09-03-apex-mcp-vertical-slice-design.md`

## Global Constraints

- Preserve Protobuf contracts and compatible external behavior.
- Applications may depend on shared crates. Applications must not depend on another application for reusable implementation.
- Admission owns validation, authorization, scope checks, idempotency, canonicalization, and durable outbox commit.
- Fanout owns bounded batch claims, sink isolation, retry deadlines, replay, and delivery state.
- Admission never waits for every downstream destination.
- Preserve idempotency, bounded retries, durable replay, and stricter durability options for genuinely high-impact actions.
- Cache and live UI systems must not become authorities for policy, audit, access, or durable events.
- Do not log raw prompts, full client records, or full tool responses by default.
- Keep strong negative-path, scope-isolation, and failure testing with every active change.
- Only work required for this foundation checkpoint, or required to fix a security defect, regression, or data-integrity issue, is in scope.

---

## Current repository map

The repository has no root `Cargo.toml`. The three Rust applications have independent manifests and lockfiles:

- `apps/event-ingest` contains the reusable event contract, validation, authentication, security, outbox, idempotency, NATS, HTTP sink, and fanout implementation.
- `apps/control-plane-api/Cargo.toml` currently depends on `apps/event-ingest` as `apex-event-ingest`.
- `apps/agent-supervisor` is already independent and generates its own control client stubs.
- `apps/event-ingest/src/outbox/publisher.rs` already implements durable-enqueue-only admission and `spawn_fanout_worker`; do not recreate that behavior.

The extraction order below keeps the dependency graph acyclic and keeps each migration independently testable.

### Task 1: Establish the root Cargo workspace

**Files:**
- Create: `Cargo.toml`
- Modify: `apps/event-ingest/Cargo.toml`
- Modify: `apps/control-plane-api/Cargo.toml`
- Modify: `apps/agent-supervisor/Cargo.toml`
- Test: Cargo metadata and the existing per-application suites

**Interfaces:**
- Consumes: the three existing package manifests and their current package names.
- Produces: one workspace containing all current Rust applications, with the existing package names unchanged.

- [x] **Step 1: Capture the current baseline**

Run these commands before changing manifests:

```powershell
cargo test --manifest-path apps/event-ingest/Cargo.toml --lib --features test-support
cargo test --manifest-path apps/control-plane-api/Cargo.toml --locked --features "test-support,postgres,valkey"
cargo test --manifest-path apps/agent-supervisor/Cargo.toml --locked
```

Record any pre-existing failures separately. A failure introduced after the workspace change must not be classified as baseline noise.

- [x] **Step 2: Write the root workspace manifest**

Create `Cargo.toml` with the current applications as members and resolver 3:

```toml
[workspace]
resolver = "3"
members = [
    "apps/event-ingest",
    "apps/control-plane-api",
    "apps/agent-supervisor",
]

[workspace.package]
edition = "2024"
version = "0.1.0"
```

Do not add future empty crates to `members`; add each crate when its first real implementation moves into it.

- [x] **Step 3: Make workspace metadata resolve without changing package identity**

Keep each existing `[package] name`, `version`, `edition`, `publish`, and binary target unchanged unless Cargo requires a workspace inheritance change. Keep the three `build.rs` files and their generated-proto behavior unchanged in this task.

- [x] **Step 4: Verify the workspace graph**

Run:

```powershell
cargo metadata --workspace --no-deps --format-version 1
cargo check --workspace
```

Expected result: all three existing packages appear exactly once, with no duplicate workspace member errors.

- [x] **Step 5: Commit the workspace shell**

```powershell
git add Cargo.toml apps/event-ingest/Cargo.toml apps/control-plane-api/Cargo.toml apps/agent-supervisor/Cargo.toml
git commit -m "build: add Apex Rust workspace"
```

### Task 2: Extract the shared wire contract

**Files:**
- Create: `crates/apex-contract/Cargo.toml`
- Create: `crates/apex-contract/build.rs`
- Create: `crates/apex-contract/src/lib.rs`
- Create: `crates/apex-contract/src/codec.rs`
- Modify: `Cargo.toml`
- Modify: `apps/event-ingest/build.rs`
- Modify: `apps/event-ingest/src/lib.rs`
- Test: `apps/event-ingest/src/codec.rs` tests, event transport tests, and `cargo test -p apex-contract`

**Interfaces:**
- Consumes: `contracts/proto/apex/v1/event.proto` and the existing redacted codec implementation in `apps/event-ingest/src/codec.rs`.
- Produces: `apex_contract::proto`, `apex_contract::RedactedProstCodec`, `apex_contract::RedactedProstDecoder`, and `apex_contract::RedactedProstEncoder`.

- [x] **Step 1: Add the contract crate manifest and workspace member**

Create `crates/apex-contract/Cargo.toml` with the existing code-generation dependencies and add it to the root workspace:

```toml
[package]
name = "apex-contract"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
prost = "0.14"
prost-types = "0.14"
tonic = { version = "0.14", default-features = false, features = ["codegen", "router", "transport", "tls-ring"] }
tonic-prost = "0.14"

[build-dependencies]
prost-build = "0.14"
protoc-bin-vendored = "3"
tonic-prost-build = { version = "0.14", default-features = false, features = ["transport"] }
```

- [x] **Step 2: Move event code generation and the redacted codec**

Copy the existing `apps/event-ingest/build.rs` code-generation settings to `crates/apex-contract/build.rs`, preserving:

```rust
config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
tonic_prost_build::configure()
    .build_server(true)
    .build_client(true)
    .build_transport(true)
```

Keep the custom codec path as `crate::RedactedProstCodec`. Move the codec implementation without changing its public types or its safe error mapping.

- [x] **Step 3: Expose the generated event module**

Create `crates/apex-contract/src/lib.rs` with the codec declarations before the generated module:

```rust
mod codec;

pub use codec::{RedactedProstCodec, RedactedProstDecoder, RedactedProstEncoder};

pub mod proto {
    tonic::include_proto!("apex.v1");
}
```

- [x] **Step 4: Re-export the contract from event-ingest during migration**

Replace the local generated event module and codec declarations in `apps/event-ingest/src/lib.rs` with:

```rust
pub use apex_contract::{proto, RedactedProstCodec, RedactedProstDecoder, RedactedProstEncoder};
```

Remove the event-proto build step and its now-unused build dependencies from `apps/event-ingest/Cargo.toml` only after `cargo check -p apex-event-ingest` proves the re-export compiles.

- [x] **Step 5: Run contract and event-ingest tests**

```powershell
cargo test -p apex-contract
cargo test -p apex-event-ingest --lib --features test-support
```

Expected result: generated event types, codec behavior, and existing event admission tests remain unchanged.

- [x] **Step 6: Commit the contract extraction**

```powershell
git add Cargo.toml crates/apex-contract apps/event-ingest/Cargo.toml apps/event-ingest/build.rs apps/event-ingest/src/lib.rs
git commit -m "refactor: extract Apex event contract crate"
```

### Task 3: Extract domain, validation, and shared error types

**Files:**
- Create: `crates/apex-domain/Cargo.toml`
- Create: `crates/apex-domain/src/lib.rs`
- Create: `crates/apex-domain/src/validation/`
- Create: `crates/apex-domain/src/errors/`
- Create: `crates/apex-domain/src/permissions/`
- Modify: `Cargo.toml`
- Modify: `apps/event-ingest/src/lib.rs`
- Modify: `apps/control-plane-api/Cargo.toml`
- Modify: `apps/control-plane-api/src/envelope.rs`
- Modify: `apps/control-plane-api/src/errors.rs`
- Modify: `apps/control-plane-api/src/lib.rs`
- Test: the moved validation/error tests and control envelope tests

**Interfaces:**
- Consumes: `apex_contract::proto` and the existing validation/error modules.
- Produces: `apex_domain::{Caller, IngestRequest, canonical_event_hash, GatewayError, GatewayErrorCode, DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope, GatewayDiagnosticReport, RedactionSummary}` plus the existing permission helpers.

- [x] **Step 1: Move validation and error modules with their unit tests**

Move these modules without changing signatures:

```text
apps/event-ingest/src/validation/caller.rs      -> crates/apex-domain/src/validation/caller.rs
apps/event-ingest/src/validation/canonical.rs   -> crates/apex-domain/src/validation/canonical.rs
apps/event-ingest/src/validation/control.rs     -> crates/apex-domain/src/validation/control.rs
apps/event-ingest/src/validation/convert.rs     -> crates/apex-domain/src/validation/convert.rs
apps/event-ingest/src/validation/identifiers.rs -> crates/apex-domain/src/validation/identifiers.rs
apps/event-ingest/src/validation/request.rs     -> crates/apex-domain/src/validation/request.rs
apps/event-ingest/src/validation/secrets.rs     -> crates/apex-domain/src/validation/secrets.rs
apps/event-ingest/src/errors/code.rs            -> crates/apex-domain/src/errors/code.rs
apps/event-ingest/src/errors/diagnostics.rs      -> crates/apex-domain/src/errors/diagnostics.rs
apps/event-ingest/src/errors/gateway.rs          -> crates/apex-domain/src/errors/gateway.rs
```

Move the associated tests with each module. Replace `crate::proto` references with `apex_contract::proto` and replace internal `crate::GatewayError` references with `crate::errors::GatewayError`.

- [x] **Step 2: Add the domain crate manifest and public surface**

Use the dependencies already required by the moved modules (`apex-contract`, `prost`, `prost-types`, `serde_json`, `serde_jcs`, `sha2`, and `uuid` where the existing code uses them). Expose only the existing public types needed by applications:

```rust
pub use errors::{
    DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure, DiagnosticScope,
    GatewayDiagnosticReport, GatewayError, GatewayErrorCode, RedactionSummary,
};
pub use validation::{Caller, IngestRequest, canonical_event_hash};
```

- [x] **Step 3: Move permission helpers into the domain crate**

Move `apps/event-ingest/src/permissions/mod.rs`, `windows.rs`, and `non_windows.rs` into `crates/apex-domain/src/permissions/`. Preserve the existing platform-specific function names and file/path checks. Re-export the module from `apex_domain`.

- [x] **Step 4: Rewire event-ingest and control-plane-api imports**

In `apps/event-ingest/src/lib.rs`, re-export domain types for compatibility:

```rust
pub use apex_domain::{
    Caller, DiagnosticCorrelation, DiagnosticEvidence, DiagnosticFailure,
    DiagnosticScope, GatewayDiagnosticReport, GatewayError, GatewayErrorCode,
    IngestRequest, RedactionSummary, canonical_event_hash,
};
```

In `apps/control-plane-api/Cargo.toml`, add `apex-contract` and `apex-domain` path dependencies. In `src/envelope.rs` and `src/errors.rs`, import domain types directly rather than through `apex_event_ingest`.

- [x] **Step 5: Run the moved unit and dependent integration tests**

```powershell
cargo test -p apex-domain
cargo test -p apex-event-ingest --lib --features test-support
cargo test -p apex-control-plane-api --lib --features test-support
```

Expected result: all validation, canonicalization, diagnostic redaction, and control-envelope tests pass without changing wire data or public error codes.

- [x] **Step 6: Commit the domain extraction**

```powershell
git add Cargo.toml crates/apex-domain apps/event-ingest/src apps/control-plane-api/Cargo.toml apps/control-plane-api/src/envelope.rs apps/control-plane-api/src/errors.rs apps/control-plane-api/src/lib.rs
git commit -m "refactor: extract Apex domain and validation crate"
```

### Task 4: Extract authentication and ephemeral stores

**Files:**
- Create: `crates/apex-auth/Cargo.toml`
- Create: `crates/apex-auth/src/lib.rs`
- Create: `crates/apex-auth/src/verifier.rs`
- Create: `crates/apex-auth/src/verifier/tests.rs`
- Create: `crates/apex-auth/src/ephemeral/`
- Modify: `Cargo.toml`
- Modify: `apps/event-ingest/src/lib.rs`
- Modify: `apps/event-ingest/src/auth/mod.rs`
- Modify: `apps/control-plane-api/Cargo.toml`
- Modify: `apps/control-plane-api/src/auth.rs`
- Modify: `apps/control-plane-api/src/agent_auth.rs`
- Modify: `apps/control-plane-api/src/startup/valkey.rs`
- Test: authentication, ephemeral-store, and control credential tests

**Interfaces:**
- Consumes: `apex_domain::{Caller, GatewayError, GatewayErrorCode}` and the existing auth/ephemeral implementations.
- Produces: the existing `PeerIdentity`, `CallerVerifier`, `BearerTokenResolver`, `BearerTokenVerifier`, `EphemeralStore`, `FallbackEphemeralStore`, `InMemoryEphemeralStore`, `ValkeyConfig`, and `ValkeyEphemeralStore` APIs. `AuthenticatedGrpcService` and `bounded_event_ingest_server` remain application-owned transport adapters.

- [x] **Step 1: Move auth and ephemeral modules with tests**

Move the verifier and ephemeral-store implementations with their tests:

```text
apps/event-ingest/src/auth/verifier.rs       -> crates/apex-auth/src/verifier.rs
apps/event-ingest/src/auth/verifier/tests.rs -> crates/apex-auth/src/verifier/tests.rs
apps/event-ingest/src/ephemeral/              -> crates/apex-auth/src/ephemeral/
```

Leave `apps/event-ingest/src/auth/service.rs` and its `AuthenticatedGrpcService`/`bounded_event_ingest_server` transport adapter in the application. That adapter owns event-ingest startup wiring; only the reusable verifier, identity, resolver, and ephemeral-store APIs move to `apex-auth`.

- [x] **Step 2: Define the crate surface and feature flags**

Keep the `valkey` feature optional and preserve the existing default behavior when it is absent. The public surface must retain the current strict credential, peer certificate, scope, rate-limit, and fallback semantics.

- [x] **Step 3: Rewire both applications**

Replace imports that currently start with `apex_event_ingest::` with `apex_auth::` for moved symbols. Keep compatibility re-exports in `apps/event-ingest/src/lib.rs` until all workspace consumers compile against the shared crate.

- [x] **Step 4: Run authentication and feature-matrix tests**

```powershell
cargo test -p apex-auth
cargo test -p apex-event-ingest --lib --features "test-support,valkey"
cargo test -p apex-control-plane-api --lib --features "test-support,valkey"
cargo check --workspace --all-features
```

Expected result: malformed credentials, peer binding, rate-limit isolation, fallback behavior, and Valkey feature compilation remain unchanged.

- [x] **Step 5: Commit the auth extraction**

```powershell
git add Cargo.toml crates/apex-auth apps/event-ingest/src apps/control-plane-api/Cargo.toml apps/control-plane-api/src
git commit -m "refactor: extract Apex authentication crate"
```

### Task 5: Extract security findings and evidence

**Files:**
- Create: `crates/apex-security/Cargo.toml`
- Create: `crates/apex-security/src/lib.rs`
- Create: `crates/apex-security/src/detect.rs`
- Create: `crates/apex-security/src/error.rs`
- Create: `crates/apex-security/src/ids.rs`
- Create: `crates/apex-security/src/store.rs`
- Create: `crates/apex-security/src/types.rs`
- Create: `crates/apex-security/src/validate.rs`
- Modify: `Cargo.toml`
- Modify: `apps/event-ingest/src/lib.rs`
- Modify: `apps/event-ingest/src/gateway/adapter.rs`
- Test: all security finding and detection tests

**Interfaces:**
- Consumes: `apex_domain::{Caller, GatewayError}` and the existing finding journal/types.
- Produces: the existing `FindingStore`, `SecurityFinding`, `SecuritySignal`, `DetectionInput`, `EvidenceRef`, `FindingError`, `FindingErrorCode`, `detect_and_record`, and related enums.

- [x] **Step 1: Move the security modules and their tests**

Move the seven listed source modules and `apps/event-ingest/src/security/tests.rs` into `crates/apex-security/src/`. Preserve the append-only status transitions, bounded collections, stable fingerprints, scope checks, and redacted evidence references.

- [x] **Step 2: Add the security crate manifest and public exports**

Use path dependencies on `apex-domain` and `apex-contract` only where required by existing types. Keep the public names unchanged. Do not add new detectors or UI behavior.

- [x] **Step 3: Rewire the ingest adapter**

Update `apps/event-ingest/src/gateway/adapter.rs` and `src/gateway/core.rs` to import security types from `apex_security`. Keep rejected-envelope signal recording behavior identical.

- [x] **Step 4: Run security tests**

```powershell
cargo test -p apex-security
cargo test -p apex-event-ingest --lib --features test-support
```

Expected result: scope filtering, deduplication, append-only transitions, redaction, and detector tests pass unchanged.

- [x] **Step 5: Commit the security extraction**

```powershell
git add Cargo.toml crates/apex-security apps/event-ingest/src
git commit -m "refactor: extract Apex security findings crate"
```

### Task 6: Extract durability and preserve the existing fanout split

**Files:**
- Create: `crates/apex-durability/Cargo.toml`
- Create: `crates/apex-durability/src/lib.rs`
- Create: `crates/apex-durability/src/idempotency/`
- Create: `crates/apex-durability/src/outbox/`
- Create: `crates/apex-durability/src/persistence/`
- Create: `crates/apex-durability/src/publisher/`
- Create: `crates/apex-durability/src/nats/`
- Create: `crates/apex-durability/src/http_sinks/`
- Create: `crates/apex-durability/src/sinks/`
- Create: `crates/apex-durability/src/postgres_transport.rs`
- Modify: `Cargo.toml`
- Modify: `apps/event-ingest/src/lib.rs`
- Modify: `apps/event-ingest/src/gateway/core.rs`
- Modify: `apps/event-ingest/src/startup/service.rs`
- Modify: `apps/control-plane-api/Cargo.toml`
- Modify: `apps/control-plane-api/src/outbox.rs`
- Modify: `apps/control-plane-api/src/replay.rs`
- Modify: `apps/control-plane-api/src/inbox_postgres.rs`
- Test: outbox, idempotency, sink, NATS, replay, and control fanout tests

**Interfaces:**
- Consumes: `apex-contract`, `apex-domain`, and the existing durability implementations.
- Produces: the existing `EventOutbox`, `FileOutbox`, `InMemoryOutbox`, `PostgresOutbox`, `OutboxKey`, `EnqueueResult`, `EventPublisher`, `PublishOutcome`, `OutboxedPublisher`, `PendingEventReplayer`, `spawn_fanout_worker`, `IdempotencyStore`, and sink traits.

- [x] **Step 1: Move durability modules without redesigning their behavior**

Move the listed modules as a cohesive unit. Preserve the current `EventOutbox` semantics: `enqueue` durably commits before fanout, `pending_batch` is bounded, `mark_complete` happens only after sink success, and retry/quarantine state is durable where the backend supports it.

- [x] **Step 2: Keep the fanout worker as a separate ownership boundary**

Preserve these existing invariants from `apps/event-ingest/src/outbox/publisher.rs`:

```rust
impl<P, O> EventPublisher for OutboxedPublisher<P, O> {
    fn publish(&mut self, event: &IngestRequest) -> Result<PublishOutcome, GatewayError> {
        // enqueue only; never call the downstream publisher here
    }
}

pub fn spawn_fanout_worker<P, O>(
    worker: OutboxedPublisher<P, O>,
    interval: Duration,
) -> tokio::task::JoinHandle<()>
```

The worker must continue to own its outbox handle and downstream publisher, run on `spawn_blocking`, claim bounded pending work, isolate events, and retry without holding the admission mutex.

- [x] **Step 3: Add a regression test for ACK-before-downstream behavior**

Extend the existing `apps/event-ingest/tests/gateway_durable_fanout.rs` or its moved equivalent with a publisher that blocks or fails downstream while the outbox accepts an event. Assert that the admission call returns `IngestOutcome::Accepted` after durable enqueue, that the event remains pending, and that the worker later settles it after the publisher recovers.

The test must not use sleeps longer than the existing test utilities. Use the repository's in-memory outbox and deterministic publisher seams.

- [x] **Step 4: Rewire event-ingest and control-plane-api**

Change both applications to depend on `apex-durability` directly. In `apps/control-plane-api`, replace the current `apex_event_ingest::{EventOutbox, IngestRequest, OutboxKey, ...}` imports with the shared crate. Preserve the distinct control outbox table/configuration and credential boundary.

- [x] **Step 5: Run durability and live-adjacent tests**

```powershell
cargo test -p apex-durability
cargo test -p apex-event-ingest --features test-support
cargo test -p apex-control-plane-api --features "test-support,postgres,valkey"
cargo check --workspace --all-features
```

Expected result: outbox, idempotency, publisher, sink retry, Postgres, and control replay behavior remains green, including the new ACK-before-downstream regression.

- [x] **Step 6: Commit the durability extraction**

```powershell
git add Cargo.toml crates/apex-durability apps/event-ingest/src apps/control-plane-api/Cargo.toml apps/control-plane-api/src
git commit -m "refactor: extract Apex durability crate"
```

### Task 7: Remove the application-to-application dependency

**Files:**
- Modify: `apps/control-plane-api/Cargo.toml`
- Modify: `apps/control-plane-api/src/**/*.rs`
- Modify: `apps/control-plane-api/tests/**/*.rs`
- Modify: `apps/event-ingest/Cargo.toml`
- Modify: `apps/event-ingest/src/lib.rs`
- Test: all control-plane-api and event-ingest suites

**Interfaces:**
- Consumes: `apex-contract`, `apex-domain`, `apex-auth`, `apex-security`, and `apex-durability` public surfaces.
- Produces: a control-plane API package with no `apex-event-ingest` dependency and an event-ingest package that retains compatibility re-exports for its own consumers.

- [x] **Step 1: Replace every control-plane application import**

Search first:

```powershell
rg -n "apex_event_ingest" apps/control-plane-api
```

Replace each import with the shared crate that now owns the symbol. Do not use a new catch-all compatibility dependency. Keep `crate::proto` references for the control gateway’s own `control.proto` module.

- [x] **Step 2: Remove the path dependency and unused features**

Delete this dependency from `apps/control-plane-api/Cargo.toml`:

```toml
apex-event-ingest = { path = "../event-ingest" }
```

Move any feature forwarding that was only needed to reach event-ingest onto the actual shared crate. Keep `postgres`, `valkey`, and `test-support` behavior explicit and optional.

- [x] **Step 3: Prove dependency direction**

Run:

```powershell
rg -n "apex_event_ingest|path = \"\.\./event-ingest\"" apps/control-plane-api
cargo tree -p apex-control-plane-api --edges normal,build,dev
```

Expected result: the first command has no matches and the dependency tree contains only shared crates, not `apex-event-ingest`.

- [x] **Step 4: Run the complete offline workspace matrix**

```powershell
cargo test --workspace --all-targets --features test-support
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Expected result: all existing application and shared-crate tests pass. Live-infrastructure tests may self-skip under their existing environment gates.

- [x] **Step 5: Commit the dependency-boundary change**

```powershell
git add apps/control-plane-api apps/event-ingest
git commit -m "refactor: remove control-plane dependency on ingest app"
```

### Task 8: Close the foundation checkpoint and document the boundary

**Files:**
- Modify: `docs/roadmap.md`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Test: workspace metadata, diff checks, and the documented commands

**Interfaces:**
- Consumes: the completed workspace and shared-crate dependency graph.
- Produces: an accurate foundation checkpoint and a repository-level command path that future MCP work can build on.

- [x] **Step 1: Update the roadmap checkpoint**

Add a short status entry to `docs/roadmap.md` under the foundation sequence stating that the workspace boundary is complete only after the dependency-direction and fanout regression checks pass. Do not mark later governance, MCP, portfolio, or UI steps complete.

- [x] **Step 2: Update repository command guidance**

Update only commands that became invalid after the root workspace became authoritative. Keep the current feature flags and live-infrastructure gates. Leave `.github/workflows/ci.yml` unchanged in this checkpoint unless a command is proven invalid by the final workspace run. Do not expand the README into a new product roadmap.

- [x] **Step 3: Run final verification**

```powershell
cargo metadata --workspace --no-deps --format-version 1
cargo test --workspace --all-targets --features test-support
cargo check --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
git status --short
```

Expected result: workspace commands pass, `git diff --check` reports no changed-line whitespace errors, and only intended foundation files are modified or newly created.

- [x] **Step 4: Commit the checkpoint documentation**

```powershell
git add docs/roadmap.md README.md CLAUDE.md
git commit -m "docs: record Apex foundation checkpoint"
```

## Completion criteria

This plan is complete only when:

1. The root workspace builds all current Rust applications and shared crates.
2. `apps/control-plane-api` has no dependency on `apps/event-ingest`.
3. Reusable contract, domain, auth, security, and durability code is owned by shared crates.
4. Durable admission ACKs after durable enqueue and does not wait for downstream fanout.
5. Background fanout remains bounded, isolated, retryable, replayable, and idempotent.
6. Existing Protobuf, authentication, scope, error, archive, and control semantics remain compatible.
7. The full offline workspace test, check, and clippy commands pass.
8. No MCP gateway, portfolio tool, broad UI work, business write, approval, extra provider, extra identity provider, evaluation subsystem, forecast, HA cache, workflow engine, or autonomous trading work has started under this plan.

The next plan must be a separate governance-interface/MCP plan and may begin only after this checkpoint is reviewed and accepted.
