# Ingest Gateway Troubleshooting

Run the complete gateway suite with its test-only security fixtures enabled:

```powershell
cargo test --all-features
cargo llvm-cov --all-targets --all-features --summary-only --fail-under-lines 95 --fail-under-functions 95 --ignore-filename-regex "(main|http_sinks|nats|validation)\\.rs$"
```

The LLVM gate measures deterministic policy, error, gateway, publisher, sink,
and Security Alerts logic. `main.rs`, validation's transport-heavy paths, and
the HTTP/NATS adapters are
deployment and transport boundaries with provider/file/socket branches; they
remain covered by the complete unit/integration suite above and are excluded
from this unit-coverage denominator so the threshold is not distorted by
unavailable external services. Security Alerts is included in the gate and is
currently above 98% line coverage and 100% function coverage.

Run the full-path gRPC/restart/idempotency harness independently:

```powershell
cargo test --all-features --test e2e_path
```

The Security Alerts unit suite also exercises the bounded JSONL journal:
finding/status replay after restart, duplicate replay, malformed-record
diagnostics, and trusted-base path isolation. The journal is a local test and
development seam; production persistence must use the authoritative
control-plane store once that integration is available.

This test drives the real tonic gRPC server and generated client through the
JetStream, ClickHouse, and archive publisher seams. Its durable test doubles
model provider-side event-ID idempotency, so it proves replay and conflict
behavior without requiring credentials or network services. The Compose E2E
gate additionally requires approved `CLICKHOUSE_API_IMAGE` and
`ARCHIVE_API_IMAGE` values plus certificates; native ClickHouse and MinIO are
not substitutes for those provider APIs.

When handing a gateway failure to a coding agent, include:

1. The failing test name and full test output.
2. The output of `GatewayError::diagnostic_report(...).to_ai_markdown()`.
3. The command used, Rust/Cargo versions, and whether `test-support` was enabled.

The Markdown bundle is deliberately safe to share with an authorized coding agent: it includes the stable error code, summary, cause, scope, validated correlation IDs, component/stage evidence, retryability, and next steps. It omits raw event payloads, caller identity, and raw transport errors. Do not add those omitted values to an AI handoff unless a separate approved restricted-diagnostics workflow authorizes it.
