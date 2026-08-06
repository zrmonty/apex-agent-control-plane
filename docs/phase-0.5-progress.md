# Phase 0.5 progress

**Status: Complete.** Phase 0.5 delivered the out-of-band (OOB) control command gateway per [ADR-0006](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0006%20OOB%20Control%20Gateway%20Moved%20to%20Phase%200.5.md) and [ADR-0005](../../AgentPlaneBrain/Apex%20Agent%20Control%20Plane/06%20Decisions/ADR-0005%20Cooperative%20V1%20Controls.md).

## What shipped

A new crate, `apps/control-plane-api` (`apex-control-plane-api`), exposes the five cooperative v1 controls -- `stop`, `pause`, `resume`, `inject`, `set_budget` -- behind a single tonic gRPC RPC, `ControlGateway.SubmitCommand` (`contracts/proto/apex/v1/control.proto`).

| Requirement (ADR-0006) | How it is met |
|---|---|
| Durable command outbox | Reuses `apex-event-ingest`'s `EventOutbox` trait and implementations (`InMemoryOutbox`, `FileOutbox`, `PostgresOutbox` under `postgres`) via `apps/control-plane-api/src/outbox.rs`. No forked durability story. |
| Independent authentication from the ingest/data path | `apps/control-plane-api/src/auth.rs`: a distinct `OperatorCaller`/`OperatorCredentialResolver`/`OperatorTokenAuthenticator` stack with its own credential type, its own token table, and its own auth-failure rate-limit buckets -- structurally separate from `event-ingest`'s `Caller`/`BearerTokenVerifier`. An ingest workload token is not accepted here and vice versa. |
| `control` event emission | `apps/control-plane-api/src/envelope.rs` builds a validated `EventType::CONTROL` envelope and hands it to `apex_event_ingest::IngestRequest::from_validated_transport` -- the same admission gate (identifiers, RFC 3339 timestamp, RFC 8785/JCS integrity hash, `control` action schema in `validation/control.rs`) the ingest data path enforces. It is never bypassed. |
| Cooperative-only semantics (ADR-0005) | The gateway only ever durably records a command for the instrumented runtime to observe; it has no code path that terminates, suspends, or otherwise reaches into a process. |
| Reachable when the primary data path is degraded | `submit_command` (`outbox.rs`) never calls a publisher on the accept path -- a command is durable, and the RPC returns success, the moment the outbox commits the row. Fanout to JetStream/ClickHouse is a separate, best-effort, retrying background loop (`replay.rs::spawn_fanout_worker`) that drains pending rows once the primary path is reachable again. `ControlCommandResponse.delivered` reports whether fanout has completed yet without ever blocking acceptance on it. |

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
- `src/main.rs` -- a runnable binary (env-configured token table and file outbox; documents that a TLS-terminating proxy or mTLS sidecar is expected in front of it for any non-loopback deployment -- native `ServerTlsConfig` wiring is a follow-up once an operator PKI profile is chosen)

## Idempotency

A command's `event_id` (`command_id`) is what the outbox keys on. Naively stamping `timestamp: now()` on every submission would make two genuinely-duplicate submissions of the same `command_id` hash to two different canonical envelopes -- turning intended idempotent replay into a spurious `IDEMPOTENCY_CONFLICT`. Instead, the envelope timestamp is derived from the `command_id`'s own embedded UUIDv7 millisecond clock (`envelope.rs::uuidv7_unix_millis`), so retrying the same `command_id` with the same fields always produces a byte-identical canonical envelope and is recognized as a true duplicate. A `command_id` reused with *different* fields still correctly surfaces `IDEMPOTENCY_CONFLICT`.

Determinism alone is not sufficient, because `command_id` is entirely caller-chosen. The derived timestamp is additionally bounded against the gateway's own clock (`envelope.rs::command_millis_within_acceptance_window`: at most 5 minutes ahead, at most 24 hours behind) and the `command_id` must be in the canonical lowercase hyphenated UUIDv7 spelling the ingest boundary accepts. Without those bounds, any holder of a valid operator credential could stamp a `stop`/`inject`/`set_budget` command with an arbitrary audit timestamp.

## Security review findings and fixes

- **Timestamp-based idempotency defeat** (found during edge-case testing, fixed before merge): see "Idempotency" above.
- **Missing per-operator admission rate limit**: `OperatorTokenAuthenticator` only throttled *auth failures*. A valid-but-compromised or malfunctioning operator credential could otherwise flood the durable outbox with accepted commands. Added a separate per-operator-subject admission ceiling in `service.rs` (`MAX_COMMANDS_PER_WINDOW`), independent of the auth-failure bucket.
- **Pre-existing clippy drift in `event-ingest`** (unrelated to this feature, found while running the mandated gate): `clippy::suspicious_open_options` on two lock-file `OpenOptions` calls (`outbox/file.rs`, `idempotency/file.rs`) and `clippy::type_complexity` on `startup/service.rs`'s ephemeral-store return type. Fixed with `.truncate(false)` (documenting that lock-file content is intentionally preserved, not overwritten) and a `SharedEphemeralStore` type alias respectively. Verified these did not change behavior -- both are lint-only fixes.
- Reviewed for: auth bypass (none found -- every RPC path requires `authenticate` before any outbox interaction), injection via `inject.content` (content flows untouched into the `control` event's `parameters.content` field and is never interpreted, matching ADR-0005's "content is untrusted data" requirement; `validation/control.rs` already enforces `content_classification: "untrusted"` and a 32 KiB ceiling), budget overflow/negative/NaN/infinity/zero (all rejected by the existing `validate_control_data` finite/positive/bounded check, exercised here via `submit_command_rejects_a_negative_budget_limit`), replay/duplicate attacks (idempotency semantics above), secrets in logs (the fanout worker and auth paths only ever log static `GatewayErrorCode`/summary strings, never tokens or payload content), and TOCTOU on outbox claim (`ControlOutboxBackend` serializes every outbox operation, including the fanout worker's `pending`/`mark_complete`, behind a single `Mutex` -- verified under the concurrency test below).

## Edge cases covered (tests)

`apps/control-plane-api/src/{auth,envelope,outbox,replay,service}.rs` unit/integration tests (22 total, run with `--features test-support`):

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

## Verification gates

```powershell
cd apps/control-plane-api
cargo test --features test-support,postgres
cargo clippy --all-targets --all-features -- -D warnings
```

Both pass clean, as do `event-ingest`'s own gates (`cargo test --all-features`, `cargo clippy --all-targets --all-features -- -D warnings`), including after the two lint-only fixes above.

## Open items for a future pass

1. **Native mTLS/TLS termination in `main.rs`.** The binary currently listens in plaintext and documents that a TLS-terminating proxy or mTLS sidecar is required in front of it for any non-loopback deployment -- matching the trust boundary `event-ingest`'s strict-TLS mode already documents. Wiring `tonic::transport::ServerTlsConfig` directly is a straightforward follow-up once an operator PKI/cert-rotation profile is chosen (see [[Authentication and Identity]] for the intended Keycloak-fronted operator credential model).
2. **Keycloak token exchange.** `StaticOperatorTokenResolver` is the local/lab and CI seam for `OperatorCredentialResolver`; production wiring is a resolver that verifies a short-lived, scope-bound credential issued via Keycloak OIDC token exchange, per [[Authentication and Identity]]. That exchange service is out of scope for this crate.
3. **Distributed (cross-replica) admission rate limiting.** The per-operator admission ceiling in `service.rs` is process-local, mirroring `event-ingest`'s own local-ceiling-plus-optional-accelerator pattern (`EphemeralStore`/Valkey). Wiring the same optional Valkey accelerator here is straightforward but was not required to close the ADR-0006 gates.
