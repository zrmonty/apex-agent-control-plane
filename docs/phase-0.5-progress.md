# Phase 0.5 progress

**Status: Complete.** Phase 0.5 delivered the out-of-band (OOB) control command gateway per [ADR-0006](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0006%20OOB%20Control%20Gateway%20Moved%20to%20Phase%200.5.md) and [ADR-0005](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0005%20Cooperative%20V1%20Controls.md). The control/durability/auth logic shipped and was pen-tested first; a second pass then made the gateway an actually-deployed service with its own transport boundary, which is what makes ADR-0006's independence claim operational rather than structural.

## What shipped

A new crate, `apps/control-plane-api` (`apex-control-plane-api`), exposes the five cooperative v1 controls -- `stop`, `pause`, `resume`, `inject`, `set_budget` -- behind a single tonic gRPC RPC, `ControlGateway.SubmitCommand` (`contracts/proto/apex/v1/control.proto`), served over mTLS from its own container.

| Requirement (ADR-0006) | How it is met |
|---|---|
| Durable command outbox | Reuses `apex-event-ingest`'s `EventOutbox` trait and implementations (`InMemoryOutbox`, `FileOutbox`, `PostgresOutbox` under `postgres`) via `apps/control-plane-api/src/outbox.rs`. No forked durability story. |
| Independent authentication from the ingest/data path | `apps/control-plane-api/src/auth.rs`: a distinct `OperatorCaller`/`OperatorCredentialResolver`/`OperatorTokenAuthenticator` stack with its own credential type, its own token table, and its own auth-failure rate-limit buckets -- structurally separate from `event-ingest`'s `Caller`/`BearerTokenVerifier`. An ingest workload token is not accepted here and vice versa. |
| `control` event emission | `apps/control-plane-api/src/envelope.rs` builds a validated `EventType::CONTROL` envelope and hands it to `apex_event_ingest::IngestRequest::from_validated_transport` -- the same admission gate (identifiers, RFC 3339 timestamp, RFC 8785/JCS integrity hash, `control` action schema in `validation/control.rs`) the ingest data path enforces. It is never bypassed. |
| Cooperative-only semantics (ADR-0005) | The gateway only ever durably records a command for the instrumented runtime to observe; it has no code path that terminates, suspends, or otherwise reaches into a process. |
| Reachable when the primary data path is degraded | `submit_command` (`outbox.rs`) never calls a publisher on the accept path -- a command is durable, and the RPC returns success, the moment the outbox commits the row. Fanout to JetStream/ClickHouse is a separate, best-effort, retrying background loop (`replay.rs::spawn_fanout_worker`) that drains pending rows once the primary path is reachable again. `ControlCommandResponse.delivered` reports whether fanout has completed yet without ever blocking acceptance on it. |
| Deployed as its own service | `apps/control-plane-api/Dockerfile` plus `control-plane-api` service blocks in `deploy/compose/compose.yaml` and `deploy/compose/compose.gateway-ref.yaml`. Its own image, its own runtime uid (10002, not the ingest gateway's 10001), its own port, its own TLS material, its own operator credential table, and its own outbox volume. See "Containerization" below. |
| Its own transport boundary | Native mTLS via `tonic::transport::ServerTlsConfig` in `src/startup/service.rs`, client certificate mandatory. See "Transport security" below. |

## Containerization

`apps/control-plane-api/Dockerfile` mirrors `apps/event-ingest/Dockerfile`, including the two failures that Dockerfile's comments record, both of which would have reappeared here verbatim:

- `ARG BUILD_IMAGE` / `ARG RUNTIME_IMAGE` are declared in **global** scope, before the first `FROM`. A stage-scoped `ARG` is invisible to a later `FROM`, which then expands to the empty string and fails with "base name should not be blank".
- The build context is the **repository root**. `build.rs` compiles `contracts/proto/apex/v1/control.proto` from outside the crate directory, and this crate additionally has a path dependency on `apps/event-ingest`. `deploy/postgres` is copied for the same `include_str!` reason it is copied for `event-ingest`: `--features postgres` forwards to `apex-event-ingest/postgres`, which compiles those `.sql` files into the binary.

Two decisions specific to this service:

- **Runtime uid 10002, not 10001.** ADR-0006 requires this service to be independently authenticated from the ingest data path. Sharing the ingest gateway's uid would leave that boundary visible only in application code -- at the OS layer, one container's compromise would already hold the other's file-level identity on any shared mount or volume. `deploy/compose/preflight.sh`/`.ps1` now check secret ownership against the *correct* uid per secret; a file chowned to the other service's uid is exactly as unreadable as one left owned by root.
- **`/var/lib/apex-control` and `/var/lib/apex-control-secrets` are created in the image**, owned by 10002. Docker initialises a fresh named volume from the image content at the mount point; when the path does not exist in the image it creates the volume root `root:root 0755` instead, and a non-root container cannot write to it. That is the exact `EACCES`/`INVALID_OUTBOX_CONFIGURATION` failure that hit `event-ingest` on every fresh deployment before its Dockerfile grew the same `install -d` step.

The Compose service matches `ingest-gateway`'s posture exactly -- `no-new-privileges:true`, `cap_drop: [ALL]`, `read_only: true`, `tmpfs: [/tmp]`, and `${VAR:?...}` fail-closed interpolation on the image and every secret -- and is slightly stricter in the `gateway-ref` profile, where the ingest gateway's block leaves the root filesystem writable and this one does not.

Deliberate differences from `ingest-gateway`:

- **No `depends_on`.** A command is durable the moment its outbox row commits, so this gateway must start and accept commands while JetStream/ClickHouse/the archive are down. A dependency edge would reintroduce exactly the coupling ADR-0006 exists to remove.
- **A separate outbox volume** (`control-outbox`, not `ingest-outbox`), per the code's own constraint: the two services must not share a durability boundary any more than they share auth.
- **The operator credential table is a file secret, never an `environment:` value.** Compose environment is readable through `docker inspect` and `/proc/<pid>/environ`, and these tokens authorize `stop`/`pause`/`inject` against live agents. `APEX_CONTROL_OPERATOR_TOKENS_FILE` was added for this; the inline `APEX_CONTROL_OPERATOR_TOKENS` remains for local/lab and CI. Setting both is a hard startup error rather than a precedence rule, since two configured credential sources means one is being silently ignored.

## Transport security

`src/startup/service.rs` terminates mTLS natively:

```rust
ServerTlsConfig::new()
    .identity(Identity::from_pem(server_cert, server_key))
    .client_ca_root(Certificate::from_pem(client_ca))
    .client_auth_optional(false)
```

**TLS is mandatory, with no plaintext or optional-client-auth mode.** This mirrors `event-ingest`, which has no such fallback either -- all three of its TLS paths are `required()` and its `client_auth_optional(false)` is likewise explicit, so that a tonic upgrade cannot make client certificates optional by changing a default. There is no "lab mode": local and CI use is served by the real PKI under `deploy/compose/live-mtls/`, so adding a plaintext bypass here would have invented a weaker mode that exists nowhere else in this repository. A deployment that still wants a terminating proxy in front of this process gets one; it simply speaks mTLS to the process behind it rather than plaintext.

Cert/key/CA material is read the same disciplined way `event-ingest` reads its own: bounded reads, paths canonicalized and confined under `APEX_CONTROL_TRUSTED_SECRET_BASE`, symlinks refused, and the shared `apex_event_ingest::permissions` private-key permission check applied to the server key and the operator token table.

**The loopback-only bind default and its `APEX_CONTROL_ALLOW_NONLOCAL_BIND` escape hatch were kept, deliberately.** Their original justification (the process served plaintext) is gone, but the replacement is stronger: this is the one surface that can `stop`, `pause`, or `inject` into a running agent, and widening its listener beyond loopback should be something an operator typed rather than a default that survives a copied `.env`. TLS protects bytes on the wire; it does not make "who can reach this socket at all" a non-decision. It also mirrors the acknowledgement the ingest profile has always required (`APEX_ALLOW_NONLOCAL_INGEST_BIND`) for a gateway that was never plaintext, so this is the established pattern here rather than an artefact of the plaintext era. What did change is the remediation text: the old message told operators to put a TLS-terminating proxy in front of the process, which is now actively wrong advice. `APEX_CONTROL_BIND` additionally gets its own preflight acknowledgement (`APEX_ALLOW_NONLOCAL_CONTROL_BIND`) rather than reusing the ingest one -- agreeing that ingest may be reached off-host is not the same decision as agreeing to it for the control channel.

## Reused vs. new

Reused directly from `apps/event-ingest` (no fork):
- `EventOutbox` / `InMemoryOutbox` / `FileOutbox` / `PostgresOutbox` / `OutboxKey` / `EnqueueResult`
- `IngestRequest::from_validated_transport` and `canonical_event_hash` (both widened from `pub(crate)` to `pub` and re-exported from `event-ingest`'s `lib.rs` -- the only visibility changes made to that crate)
- `IngestRequest::event_id/envelope/workspace_id/namespace_id` accessors (the first two were `test-support`-gated; ungated since a production consumer now needs them for outbox-key construction in the fanout worker)
- `GatewayError`/`GatewayErrorCode` (mapped into the control gateway's own `CommandError` taxonomy rather than passed through verbatim, since some ingest codes describe the ingest identity model, which does not apply to an OOB operator command)
- `EventPublisher` trait, as the abstraction `spawn_fanout_worker` drives (a deployment wires in `JetStreamPublisher` or any other `EventPublisher`)

New in `control-plane-api`:
- `contracts/proto/apex/v1/control.proto` -- the `ControlGateway` service contract
- `src/auth.rs` -- independent operator auth boundary (see table above)
- `src/envelope.rs` -- command-to-envelope construction, including a UUIDv7-derived deterministic timestamp (see "Idempotency" below)
- `src/outbox.rs` -- accept-path orchestration decoupled from fanout
- `src/replay.rs` -- best-effort fanout worker
- `src/service.rs` -- the tonic service: auth, per-operator admission rate limiting, command construction, outbox submission
- `src/errors.rs` -- redacted `CommandError` taxonomy and gRPC status mapping
- `src/main.rs` + `src/startup/` -- the runnable binary's process wiring (bind policy, mTLS material, operator credential table, file outbox), split into `env.rs`/`secrets.rs`/`service.rs`/`tests.rs` the same way `event-ingest/src/startup/` is. Bin-only: declared from `main.rs`, not from `lib.rs`.
- `Dockerfile` and the `control-plane-api` service blocks in `deploy/compose/compose.yaml` and `compose.gateway-ref.yaml`
- `tests/live_control_mtls.rs` -- live mTLS tests against the running container
- `control-plane-server`, `control-operator-client`, and `control-operator-tokens` fixtures in `deploy/compose/live-mtls/generate_pki.py`, so the control gateway borrows neither the ingest gateway's server certificate nor the ingest workload's client identity

## Idempotency

A command's `event_id` (`command_id`) is what the outbox keys on. Naively stamping `timestamp: now()` on every submission would make two genuinely-duplicate submissions of the same `command_id` hash to two different canonical envelopes -- turning intended idempotent replay into a spurious `IDEMPOTENCY_CONFLICT`. Instead, the envelope timestamp is derived from the `command_id`'s own embedded UUIDv7 millisecond clock (`envelope.rs::uuidv7_unix_millis`), so retrying the same `command_id` with the same fields always produces a byte-identical canonical envelope and is recognized as a true duplicate. A `command_id` reused with *different* fields still correctly surfaces `IDEMPOTENCY_CONFLICT`.

Determinism alone is not sufficient, because `command_id` is entirely caller-chosen. The derived timestamp is additionally bounded against the gateway's own clock (`envelope.rs::command_millis_within_acceptance_window`: at most 5 minutes ahead, at most 24 hours behind) and the `command_id` must be in the canonical lowercase hyphenated UUIDv7 spelling the ingest boundary accepts. Without those bounds, any holder of a valid operator credential could stamp a `stop`/`inject`/`set_budget` command with an arbitrary audit timestamp.

## Security review findings and fixes

- **Timestamp-based idempotency defeat** (found during edge-case testing, fixed before merge): see "Idempotency" above.
- **Missing per-operator admission rate limit**: `OperatorTokenAuthenticator` only throttled *auth failures*. A valid-but-compromised or malfunctioning operator credential could otherwise flood the durable outbox with accepted commands. Added a separate per-operator-subject admission ceiling in `service.rs` (`MAX_COMMANDS_PER_WINDOW`), independent of the auth-failure bucket.
- **Pre-existing clippy drift in `event-ingest`** (unrelated to this feature, found while running the mandated gate): `clippy::suspicious_open_options` on two lock-file `OpenOptions` calls (`outbox/file.rs`, `idempotency/file.rs`) and `clippy::type_complexity` on `startup/service.rs`'s ephemeral-store return type. Fixed with `.truncate(false)` (documenting that lock-file content is intentionally preserved, not overwritten) and a `SharedEphemeralStore` type alias respectively. Verified these did not change behavior -- both are lint-only fixes.
Found during the containerization/TLS pass:

- **The operator credential table would have travelled as a Compose `environment:` value.** The binary only read `APEX_CONTROL_OPERATOR_TOKENS`, so wiring it into `compose.yaml` the obvious way would have put bearer credentials that authorize `stop`/`pause`/`inject` somewhere `docker inspect` and `/proc/<pid>/environ` expose -- while every other credential in that file is a file secret. Added `APEX_CONTROL_OPERATOR_TOKENS_FILE`, held to the same owner-only permission policy as a private key, and made setting both sources a hard startup error.
- **A bare `docker compose up -d` in CI would have hidden control-side failures under the gateway's name.** `.github/workflows/live-mtls-e2e.yml`'s gateway smoke-start step started every service in the profile. Once this profile also defined `control-plane-api` and its `service_completed_successfully` init container, a control-side init failure would have failed the *gateway* step, printing only the gateway's logs -- the same class of undiagnosable CI failure that step's own comments already record. The `up -d` is now scoped to `ingest-gateway`; Compose still starts everything it depends on.
- Reviewed and verified live, against the running container: the mTLS gate rejects a client presenting no certificate (server sends TLS `CertificateRequired`) and a client presenting a certificate from an untrusted CA (`UnknownCA`), while a *trusted* certificate with no operator token reaches the application and returns gRPC `Unauthenticated` -- which is what makes the first two results meaningful rather than "the server rejects everything". An ingest workload certificate plus ingest bearer token is also refused, confirming ADR-0006's credential separation against the two credentials a deployment actually issues. Container hardening was confirmed by `docker inspect`: uid 10002, `ReadonlyRootfs=true`, `CapDrop=[ALL]`, `no-new-privileges:true`, not privileged; staged secrets 0600 owned by the runtime uid.
- Reviewed for: auth bypass (none found -- every RPC path requires `authenticate` before any outbox interaction), injection via `inject.content` (content flows untouched into the `control` event's `parameters.content` field and is never interpreted, matching ADR-0005's "content is untrusted data" requirement; `validation/control.rs` already enforces `content_classification: "untrusted"` and a 32 KiB ceiling), budget overflow/negative/NaN/infinity/zero (all rejected by the existing `validate_control_data` finite/positive/bounded check, exercised here via `submit_command_rejects_a_negative_budget_limit`), replay/duplicate attacks (idempotency semantics above), secrets in logs (the fanout worker and auth paths only ever log static `GatewayErrorCode`/summary strings, never tokens or payload content), and TOCTOU on outbox claim (`ControlOutboxBackend` serializes every outbox operation, including the fanout worker's `pending`/`mark_complete`, behind a single `Mutex` -- verified under the concurrency test below).

## Edge cases covered (tests)

`apps/control-plane-api/src/{auth,envelope,outbox,replay,service}.rs` unit/integration tests (36, run with `--features test-support`):

- Duplicate command idempotency (`submit_command_is_idempotent_for_a_repeated_command_id`)
- Idempotency conflict on a reused `command_id` with different fields (`submit_command_rejects_a_reused_command_id_with_different_fields`)
- Concurrent commands to the same target with the same `command_id` -- exactly one non-duplicate acceptance across 8 concurrent tasks (`submit_command_handles_concurrent_duplicate_submissions_without_a_torn_write`)
- Malformed `inject` parameters missing `content_classification` (`submit_command_rejects_inject_without_untrusted_classification`)
- Negative `set_budget` limit (`submit_command_rejects_a_negative_budget_limit`)
- Missing/duplicate/malformed authorization headers (`auth::tests::*`)
- Auth-failure rate limiting (`authenticate_rate_limits_repeated_failures_for_the_same_token`)
- Post-auth admission rate limiting (`submit_command_rate_limits_a_single_operator_after_the_per_second_ceiling`)
- Scope enforcement -- an operator cannot act outside its granted workspace/namespace, a global operator can act everywhere (`submit_command_rejects_a_scope_the_operator_does_not_hold`, `global_operator_allows_every_well_formed_scope`)
- Degraded-fanout availability: a `FlakyPublisher` that fails once still leaves the command durable and pending, then succeeds and is marked complete on the next tick (`fanout_worker_retries_after_a_transient_publish_failure`)
- Deterministic UUIDv7-derived timestamps and rejection of non-v7 UUIDs (`envelope::tests::*`)

`apps/control-plane-api/src/startup/tests.rs` startup-policy tests (9):

- Loopback default, and that a non-loopback bind is refused without acknowledgement in both address families
- That the acknowledgement is exact -- `"TRUE"`, `"True"`, `"1"`, `"yes"`, `"on"`, `" true"` must all fail closed rather than be read as consent to expose the control channel
- Bind values that are not socket addresses
- Two configured operator credential sources refused
- Bounded reads (empty, oversized, exactly-at-limit, missing)
- Trusted-base confinement, symlink refusal, and agreement with the platform private-key permission primitive

These cover startup policy rather than `env::var` plumbing because that plumbing is structurally untestable here: the crate has `unsafe_code = "forbid"` and Rust 2024 requires `unsafe` to call `env::set_var`. Each rule is therefore split into a pure `*_value` function taking `Option<&str>`, the same pattern `event-ingest`'s `attempts`/`attempts_value` uses.

`apps/control-plane-api/tests/live_control_mtls.rs` live-container tests (5, opt-in via `APEX_CONTROL_LIVE_MTLS=1`):

- Valid operator certificate + valid token accepted, and the command lands durably in the container's outbox volume
- Valid certificate, **no** token -- reaches the application, returns `Unauthenticated`
- **No** client certificate -- refused at the handshake
- Client certificate from an untrusted CA -- refused at the handshake
- Ingest workload certificate + ingest bearer token -- refused (ADR-0006 credential separation)

The middle case is the load-bearing one: it proves a correctly-certified client *does* reach the application layer, so the two handshake refusals demonstrate that the certificate is what stopped them rather than the server being broken in some way that rejects everything. Nothing else in CI can catch a regressed TLS gate -- every other test drives the service in-process as a library, where `ServerTlsConfig` is never constructed at all.

## Verification gates

```powershell
cd apps/control-plane-api
cargo test --features test-support,postgres
cargo clippy --all-targets --all-features -- -D warnings
```

Both pass clean (36 + 9 + 5 tests), as do `event-ingest`'s own gates (`cargo test --all-features` -- 240 tests, `cargo clippy --all-targets --all-features -- -D warnings`).

`.github/workflows/live-mtls-e2e.yml` additionally builds the real image, starts the real container, and drives real mTLS gRPC at it ("Build and smoke-start the control gateway image", "Live control-gateway mTLS tests"). This exists for the same reason the equivalent gateway step does: `docker compose config` parses YAML, and never catches a Dockerfile that cannot build, a binary that panics before binding, or a container that cannot write its data volume. All three of those reached `master` for `event-ingest` before it had such a gate.

## Open items for a future pass

Closed by the containerization/TLS pass: the container image and Compose wiring, and native mTLS termination. What remains:

1. **The fanout worker is not wired into the binary.** `replay.rs::spawn_fanout_worker` exists, is tested, and is exported -- but `src/startup/service.rs` never calls it, because doing so requires an `EventPublisher` and therefore a whole JetStream client configuration surface this crate does not yet have. Consequence in the deployed container today: every accepted command is durably recorded and stays `pending` in the outbox forever, and `ControlCommandResponse.delivered` is always `false`. **This does not affect the ADR-0006 acceptance guarantee** -- a command is durable and acknowledged the moment the outbox row commits, which is the point -- but nothing currently drains the outbox into the queryable trace, so a `control` event never reaches ClickHouse. This should be the next item picked up, ahead of items 2 and 3: it is the difference between "commands are recorded" and "commands are observable".
2. **`--features postgres` does not select the Postgres outbox backend.** `startup::service::open_outbox` always constructs a `FileOutbox`; the feature currently only forwards the dependency to `apex-event-ingest`. So the deployed container is single-process-authoritative regardless of how it was built. This matters for item 4: a second replica sharing a `control-outbox` volume would have two processes contending on one file outbox. Backend selection needs the same `APEX_POSTGRES_URL`-driven branch `event-ingest`'s `open_durability_stores` already has.
3. **Keycloak token exchange.** `StaticOperatorTokenResolver` is the local/lab and CI seam for `OperatorCredentialResolver`; production wiring is a resolver that verifies a short-lived, scope-bound credential issued via Keycloak OIDC token exchange, per [[Authentication and Identity]]. That exchange service is out of scope for this crate. Note for whoever picks this up: `APEX_CONTROL_OPERATOR_TOKENS_FILE` is now the production credential path and is read through `startup::secrets`, so a Keycloak-backed resolver slots in at `build_operator_resolver` without touching the transport or secret-loading code.
4. **Distributed (cross-replica) admission rate limiting.** The per-operator admission ceiling in `service.rs` is process-local, mirroring `event-ingest`'s own local-ceiling-plus-optional-accelerator pattern (`EphemeralStore`/Valkey). Running more than one replica is possible for the first time now that the service is containerized -- but see item 2 first: shared rate-limit state without a shared outbox backend would only solve half of the multi-replica problem.

Known lab-vs-production difference, not a defect: in `compose.gateway-ref.yaml` the control gateway's client CA is the single shared lab `ca`, so an ingest workload certificate survives the *handshake* there and is stopped by the operator credential check instead (`rejects_an_ingest_workload_credential` asserts exactly that). `compose.yaml` separates them -- `CONTROL_CLIENT_CA_FILE` is distinct from `GATEWAY_CLIENT_CA_FILE` -- so in a real deployment that attempt does not survive the handshake either. Giving the lab harness a second CA would let CI exercise the production topology; it was not done here because `live-mtls/` assumes a single `ca.pem` throughout.
