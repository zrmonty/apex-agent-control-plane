# Phase 0 progress

**Status: Complete.** Phase 0 delivered the security-first foundations.

Phase 0 sets the secure local foundation and the admission core for Apex.

Provider image acceptance with live Object-Lock proof is an environment gate. It is not an open SDK backlog item. Complete that gate before regulated production profiles.

## Track outcomes

| Track | Outcome |
|---|---|
| Durable event path | Runnable ingest gateway with outbox, JetStream, ClickHouse, and archive fanout seams. Restart, replay, and conflict tests exist in `e2e_path` and gateway suites. |
| Immutable archive readiness | Provider-neutral archive contract. Create-only semantics. Compose `archive-store-init` gate. Strict retention still needs live Object-Lock acceptance in the target environment. |
| Security Alerts | Immutable findings, detectors, journal persistence, and ingest-boundary signals for scope, idempotency, secret exposure, and auth abuse. |
| Secure integration | Gold-standard template catalog. Integration bundle validation. Ed25519 signed bundles (verify before SPIFFE). `Apex.connect()` preflight. Reference-agent first trace without manual envelopes. |
| Valkey acceleration | `EphemeralStore` with in-memory fallback and feature-gated `ValkeyEphemeralStore` (mTLS and ACL). Compose overlay `compose.valkey.yaml`. Rate limits with fail-closed local ceiling. |
| Model execution attribution | Optional `execution` object on `llm` events (schema, SDK builder and validator, reference runtime emission). |

## Completed foundations

- Frozen v1 event contract (Protobuf and JSON Schema). RFC 8785 and SHA-256 integrity. Optional LLM `execution` attribution.
- Python SDK: event builder and validator, controls, OTEL mapping, bounded observer and JSONL sink, idempotent gRPC exporter, gold-standard template, integration bundles, `Apex.connect()` preflight, reference reason-act loop with attribution.
- Rust ingest-admission core: mTLS-ready tonic service, bearer verification, scope, idempotency, outbox, JetStream and HTTPS sink fanout, Security Alerts, restart-safe journals, `EphemeralStore` interface.
- Compose profile for JetStream, ClickHouse projection, archive provider slots, preflight scripts, and digest-pinned image requirements.
- Safe diagnostics, secret admission, control inject taint rules, and redacted security findings on the hot path.

## Getting started

Day-one paths (local demo → lab install → Docker → Compose): **[Getting started](getting-started.md)**.

Writing style for docs: [ASD-STE100](writing-style-ste100.md).

## Lab install (Windows, Linux, macOS)

Lab install creates the bundle signing authority, agent trust pack, live-mTLS PKI, and a demo signed agent.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/lab/install.ps1
```

```bash
./deploy/lab/install.sh
```

See [deploy/lab/README.md](../deploy/lab/README.md).

## Live mTLS provider handshake

Local Docker harness for Valkey, NATS JetStream, and ClickHouse/archive contract stubs:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/live-mtls/run.ps1
```

See [deploy/compose/live-mtls/README.md](../deploy/compose/live-mtls/README.md).

## Verification gates

Python SDK (`packages/sdk-python`):

```powershell
$env:TEMP='C:\tmp'; $env:TMP='C:\tmp'; python -m pytest --cov=apex_sdk --cov-fail-under=95
```

Rust admission core (`apps/event-ingest`):

```powershell
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --lib --test gateway --test e2e_path --test startup_paths --all-features --summary-only --fail-under-lines 95 --fail-under-functions 70 --ignore-filename-regex "(main\\.rs|startup[/\\\\]|http_sinks[/\\\\]|nats[/\\\\]|auth[/\\\\]service\\.rs)"
```

Local first-trace (no Docker):

```powershell
$env:PYTHONPATH = "packages/sdk-python/src"
python examples/reference-agent/run_demo.py
```

## Phase 0 completion checklist

| # | Gate | Status |
|---|---|---|
| 1 | Enroll and preflight with least-privilege local identity and gold-standard template | Met (`Apex.connect`, template assessment, local bundle) |
| 2 | Hash-chained event stream from reference agent | Met |
| 3 | Durable path seams and restart/replay tests | Met (code, unit/integration, live mTLS harness) |
| 4 | Prompt-injection taint, tool/egress allowlists, secret exposure, integrity findings | Met at SDK and ingest boundaries |
| 5 | Redacted diagnostics and security findings | Met |
| 6 | Archive contract, create-only client, store-init gate | Met as staging contract; Object-Lock proof is deploy-time |
| 7 | Requested/effective model attribution without content | Met (`execution` object) |

## Deferred after Phase 0

These items are product or deployment work. They are not open Phase 0 foundation gaps.

1. ~~Reference ClickHouse/archive providers~~ — Delivered (`apps/reference-providers`, live-mTLS and compose.e2e). Production still pins approved digests.
2. ~~Object-Lock / multi-cloud archive acceptance~~ — Delivered (MinIO, Azure Blob, GCS adapters and acceptance scripts).
3. Full SPIFFE/SPIRE enrollment UX and control-plane API/UI. Bundle crypto verify is in the Python SDK. Operator distribution UX remains later.
4. ~~Production Valkey Compose profile and remote adapter~~ — Delivered (`--features valkey`, `compose.valkey.yaml`). HA Sentinel/cluster remains Phase 2.
5. Operator UI (Phase 1 starts with Agent Story).
6. ~~PostgreSQL multi-process outbox/idempotency~~ — Delivered (`PostgresOutbox` / `PostgresIdempotencyStore`, feature `postgres`). Pool sizing and HA topology remain ops work.

### E2E orchestration

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/e2e/run.ps1
```

This script runs live mTLS client tests, optional Postgres smoke tests, and Object-Lock acceptance.

## Phase 1 entry

Phase 1 starts from this baseline:

1. Agent Story UI over the reference-agent trace.
2. Control-plane API session surfaces for findings, enrollment, and policy.
3. ~~CI for e2e and live-mTLS~~ — Delivered (`.github/workflows/live-mtls-e2e.yml`, `ci.yml`). Production still pins digest-pinned bases.
4. SPIFFE enrollment UX and operator bundle distribution service (SDK sign/verify already landed).
5. Valkey HA (Sentinel/cluster) only when measured load requires it.
