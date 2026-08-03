# Phase 0 progress

**Status: Active — security-first foundation in progress.**

## Current active work

Phase 0 is being worked as six parallel deliverables. A track is not complete until its negative-path and recovery tests pass.

| Track | Current objective | Exit signal |
|---|---|---|
| Durable event path | Wire the validated ingest boundary through JetStream, ClickHouse, and archive staging in Compose. | A scoped event survives restart/replay and reaches every required sink exactly once logically. |
| Immutable archive readiness | Validate an Object-Lock-capable provider before enabling strict retention. | Retention, legal hold, retrieval, and verification tests pass against the selected provider. |
| Security Alerts | Build immutable findings and deterministic prevention for prompt injection, malicious tools, secret exposure, and telemetry tampering. | A blocked attack appears as a redacted, scoped finding; no hostile content crosses an instruction, authorization, or export boundary. |
| Frictionless secure integration | Build generated enrollment, short-lived workload identity, SDK preflight, and reference-agent onboarding. | A developer reaches a securely scoped first trace in under 10 minutes without an admin credential, static API key, or manual envelope construction. |
| Valkey acceleration | Add the optional hardened ephemeral layer for rate limits and attack counters. | Cache loss/restart cannot affect authorization, durability, or audit truth; Valkey is mTLS/ACL-protected and internal only. |
| Model execution attribution | Capture requested versus effective model/effort, billed usage categories, and evidence provenance. | Cost Lens explains fallback/routing and distinguishes provider receipts from observed/configured/estimated data without storing content. |

**Current implementation order:** durable event path and its end-to-end tests first; Security Alerts, secure enrollment, Valkey's interface/attack-counter use case, and model execution attribution proceed alongside it; Compose/archive validation gates strict profiles. The GUI work begins after these backend contracts are proven.

**Phase 1 UI commitment:** the first agent-facing surface is [Agent Story](architecture/Single-Agent%20Runtime%20View.md), powered by the Phase 0 reference-agent trace. This keeps the product's smallest-scale agent experience visible before fleet-scale visualization work begins.

## Completed foundations

- Frozen v1 event contract in Protobuf and JSON Schema, with canonical RFC 8785 JSON and SHA-256 event integrity.
- Python SDK event builder and validator, cooperative control commands, OpenTelemetry export mapping, bounded observer, JSONL sink, and idempotent bounded gRPC exporter.
- Rust ingest-admission core with authenticated-caller/scope checks, strict Bearer metadata parsing with injected workload-token resolution, UUIDv7 validation, decoded Protobuf envelope metadata checks, RFC 8785/SHA-256 integrity verification, envelope-size limits, bounded test idempotency, generated-contract support without a system `protoc`, a verifier-injected runnable tonic service, a scope-safe JetStream publisher boundary, and safe gateway diagnostics.
- Redacted diagnostic reports for human and AI troubleshooting. They preserve stable codes, retryability, safe correlation, causal evidence, and recovery steps while omitting payloads, identities, raw transport errors, and secret-bearing text.
- Security Alerts Phase 0 finding foundation now provides immutable scoped finding records, validated hashed evidence references, stable fingerprints, append-only status/containment audit updates, exact scope isolation, bounded capacity, redacted actionable errors, deterministic event-boundary detectors, a bounded restart-safe JSONL journal, and opt-in ingest-boundary findings for scope denial and idempotency conflicts. PostgreSQL/control-plane integration and broader policy-boundary wiring remain next.
- The Python bounded observer validates every event before enqueueing and deep-snapshots accepted events, preventing invalid envelopes or caller mutations from reaching custom background sinks.
- The tonic service rejects oversized decoded messages before credential verification or gateway work, and the exported bounded server builder enforces tonic's encoded-message limit before protobuf service dispatch.
- gRPC verifier and publisher panics are contained as safe internal statuses, and idempotency keys are scoped by workspace/namespace to prevent cross-tenant collisions.
- The JetStream publisher rejects unsafe or overlong broker subjects and oversized direct payloads before invoking the transport adapter.
- JetStream scope subject components are delimiter-free hex encoded, preventing dotted or colon-containing tenant identifiers from creating wildcard-routing ambiguity.
- JetStream transport errors are documented as a redaction-safe contract: stable codes, causes, and recovery steps are retained; raw broker errors, credentials, subjects, and payloads are excluded.
- Bearer authentication fails closed on duplicate authorization metadata, preventing proxy/parser disagreement over which credential is authoritative.
- Authentication diagnostics distinguish missing credentials (`UNAUTHENTICATED`) from malformed or ambiguous metadata (`INVALID_AUTHORIZATION_METADATA`) with safe recovery guidance.
- Rust admission now enforces the JSON Schema control-event shape for Protobuf `type=CONTROL`, including cooperative enforcement, safe reason codes, bounded untrusted injection content, and budget limits.
- Protobuf `Struct` canonicalization enforces a 64-level nesting limit to prevent stack-exhaustion payloads inside the 256 KiB envelope bound.
- Rust ingest transport/authentication and publisher concerns are split into focused `auth.rs` and `publisher.rs` modules; `lib.rs` retains the shared contract, validation, diagnostics, and gateway core.
- The ingest hot path stores the normalized scope key on each admitted request and reuses it for authorization/idempotency, avoiding repeated formatting and allocation during gateway admission.
- A deterministic Python `ReferenceReasonActLoop` now emits validated, hash-chained turn-start, LLM, tool, message, and turn-end traces through the bounded observer.
- The reference loop can emit `agent_spawn` plus a child trace linked by `parent_run_id` and shared `trace_id`, covering the Phase 0 A2A relationship.
- The JetStream boundary includes a bounded retry adapter that retries only explicitly retryable failures and preserves broker message-id deduplication semantics.
- The NATS transport foundation now requires a `tls://` endpoint, rejects embedded credentials/ambiguous URL forms, validates CA/client certificate/private-key files as regular files within a trusted base, and exposes only a narrow publish client trait for the concrete NATS library adapter.
- The NATS seam also performs defense-in-depth publish admission (safe non-wildcard subjects, bounded message IDs/payloads), rejects empty/oversized/aliased TLS material, enforces private-key permissions where supported, and converts client panics into redacted structured failures.
- The validated seam now has a concrete `async-nats` 0.50 JetStream client with mTLS, `Nats-Msg-Id` deduplication headers, bounded publish acknowledgements, and safe sync-to-Tokio bridging. A durable fanout publisher orders JetStream, ClickHouse, and archive acknowledgements and stops before later sinks on failure.
- Downstream ClickHouse/archive seams now support the same bounded 1–8 attempt retry policy as JetStream, retrying only explicitly transient failures and preserving event-ID idempotency expectations.
- Python durability tests now demonstrate duplicate replay acknowledgement and JSONL sink reopen/restart recovery for readable reference traces.
- Concrete authenticated HTTPS ClickHouse and archive publisher clients now use mTLS, trusted file-mounted credentials, bounded requests, event-ID headers/keys, and redacted failures. The ClickHouse projection schema and write API are defined in `deploy/clickhouse/schema.sql` and `contracts/clickhouse/v1.md`; the provider-neutral archive API and HTTP mapping are defined in `contracts/archive-provider/v1.md`. Compose now wires internal-only `clickhouse-projection` and `archive-provider` slots with separate mTLS credentials, plus an archive-store-init gate that creates and verifies an Object-Lock bucket over TLS; approved provider images and acceptance tests remain deployment prerequisites. The archive client uses create-only `If-None-Match: *` semantics.
- gRPC status messages now include a stable error code, reviewed summary, cause, and first recovery action; dynamic transport details and untrusted input remain excluded.
- Compose dependency profile for JetStream, ClickHouse, and S3-compatible archive staging storage. It requires digest-pinned images and local file-mounted secrets; JetStream requires mTLS and refuses placeholder configuration.
- A fail-closed `apex-event-ingest` executable and Compose `ingest-gateway` service now bind authenticated mTLS gRPC, file-backed bearer scope resolution, bounded NATS/HTTP sink retries, and the ordered JetStream → ClickHouse → archive fanout. The gateway requires digest-pinned images, trusted secret paths, explicit provider API endpoints, and refuses missing or ambiguous startup configuration.

## Security boundaries in place

- Event IDs and scope metadata use a strict safe-identifier grammar.
- `control.inject` is explicitly untrusted, bounded to 32 KiB UTF-8, and must not be promoted into system/developer instructions or authorization decisions.
- Export and JSONL persistence validate complete canonical envelopes before transport or storage.
- Diagnostic AI handoff re-sanitizes data at render time to prevent mutation, secret leakage, Markdown injection, and prompt injection.
- Local file sinks and emergency spools require a trusted base directory and reject path escapes and symbolic links.
- Compose has no default credentials, no broker/database/object API/console host ports, no NATS monitoring endpoint, and no credentials in command-line arguments.
- Python JSONL and emergency diagnostic spools enforce bounded record/file sizes, and authenticated HTTP sinks reject localhost, loopback, link-local, private, and unspecified IP endpoints plus localhost aliases before loading credentials.
- The concrete async NATS client bounds its Tokio worker/blocking pools, connection/reconnect attempts, JetStream request/acknowledgement timeouts, and redacts all client failures.

## Verification gates

Run the Python SDK suite from `packages/sdk-python`:

```powershell
$env:TEMP='C:\tmp'; $env:TMP='C:\tmp'; python -m pytest
```

Run Rust tests and lint from `apps/event-ingest`:

```powershell
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --all-targets --all-features --summary-only --fail-under-lines 95 --fail-under-functions 95 --ignore-filename-regex "(main|http_sinks|nats|validation)\\.rs$"
```

The current gates are at least 95% coverage. The latest verified results were 135 Python tests at 95.24% coverage and 57 Rust gateway tests plus the gRPC/restart E2E test passing. The scoped LLVM gate reports 96.41% line coverage, 95.61% function coverage, and Security Alerts at 98.37% line / 100% function coverage.

## Active Phase 0 backlog

1. Bind approved ClickHouse/archive provider images to the new Compose service slots, apply the schema, and add end-to-end broker/storage replay tests; the async NATS/JetStream client, authenticated HTTPS publishers, bounded downstream retry/fanout path, verifier-injected service, Bearer metadata boundary, canonical-envelope integrity verification, and hardened TLS/publish boundaries are now in place. The storage schema and provider API contracts are frozen for this integration step.
2. Run the authenticated provider acceptance suite and end-to-end broker/storage replay tests through the configured endpoints. Native ClickHouse and MinIO remain backend dependencies only; they do not implement the provider `/v1/events` APIs themselves.
3. Run the archive-store-init gate and provider acceptance suite against the selected Object-Lock implementation before enabling any strict retention profile. The current archive store remains staging-only until independent retention/legal-hold verification passes.
4. Integrate the Security Alerts finding foundation with deterministic prompt-injection/taint-boundary blocks, approved-tool and egress denials, secret/redaction blocks, telemetry-integrity findings, durable persistence, and replay/load/isolation tests. The bounded `DetectionInput`/`detect_and_record` adapter, restart-safe JSONL persistence seam, and opt-in ingest findings for scope denial/idempotency conflicts are now in place; PostgreSQL/control-plane integration and broader policy-boundary wiring remain. See [Security Alerts and Detection](security/Security%20Alerts%20and%20Detection.md).
5. Implement frictionless secure agent integration: signed generated bundles, single-use scope-bound enrollment, short-lived workload identity renewal/revocation, `Apex.connect()` preflight, and reference-agent first-trace acceptance tests. See [Frictionless Secure Agent Integration](architecture/Frictionless%20Secure%20Agent%20Integration.md).
6. Implement the optional Valkey acceleration profile and `EphemeralStore` boundary for protected rate limits and security-finding fingerprint counters; keep all authoritative data in PostgreSQL/NATS/ClickHouse/archive. See [Valkey Acceleration Layer](architecture/Valkey%20Acceleration%20Layer.md).
7. Implement model execution attribution: requested/effective provider, model, and reasoning effort; provider-receipt-first usage categories; evidence provenance; and Cost Lens/ClickHouse projection linkage. See [Model Execution Attribution](architecture/Model%20Execution%20Attribution.md).

## Phase 0 completion gate

Phase 0 completes only when all active backlog items are verified and a reference agent can safely perform this end-to-end path:

1. Enroll with least-privilege, short-lived identity.
2. Pass policy/trust/scope preflight and emit a complete, hash-chained event stream.
3. Deliver the stream through the durable event path, including restart and duplicate replay.
4. Prevent a prompt-injection, malicious-tool, secret-exposure, and integrity-tampering attempt at the correct boundary.
5. Produce a redacted diagnostic/security finding with safe remediation and no restricted content leakage.
6. Archive required records through a validated immutable-storage capability where the selected profile requires it.
7. Show the exact requested/effective model and effort, usage evidence source, and truthful cost confidence for a fallback reference run without storing prompt or completion content.
