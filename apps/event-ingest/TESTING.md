# Ingest Gateway Troubleshooting

Run the complete gateway suite with its test-only security fixtures enabled:

```powershell
cargo test --all-features
cargo llvm-cov --all-targets --all-features --summary-only --fail-under-lines 95 --fail-under-functions 95 --ignore-filename-regex "(main|http_sinks|nats)\\.rs$"
```

The LLVM gate measures deterministic policy, error, gateway, publisher, sink, validation, and Security Alerts logic. `main.rs` and the HTTP/NATS adapters are deployment and transport boundaries with provider, file, and socket branches. The complete unit and integration suite covers them. They are excluded from this unit-coverage denominator so unavailable external services do not distort the threshold. `validation.rs` is included on purpose. It contains the highest-value admission and integrity policy. Security Alerts is included in the gate. It is currently above 98% line coverage and 100% function coverage.

Run the full-path gRPC, restart, and idempotency harness independently:

```powershell
cargo test --all-features --test e2e_path
```

The Security Alerts unit suite also exercises the bounded JSONL journal: finding and status replay after restart, duplicate replay, malformed-record diagnostics, and trusted-base path isolation. The journal is a local test and development seam. Production persistence must use the authoritative control-plane store once that integration is available.

The runnable gateway enables a bounded in-memory Security Alerts store by default. Scope denials, idempotency conflicts, secret exposure, and authentication-abuse signals are emitted in staging. To use the restart-safe journal path, set both `APEX_SECURITY_FINDINGS_FILE` and `APEX_SECURITY_FINDINGS_BASE` to an absolute writable location inside the approved persistence boundary. The journal remains single-writer local persistence until the PostgreSQL adapter is deployed.

On native Windows, production startup also validates private-key ACLs through a fail-closed PowerShell SDDL probe. Unit fixtures skip that probe on purpose. Changing ACLs on a developer profile is unsafe. Deployment tests must exercise the built executable with the real certificate directory.

Set `APEX_BEARER_SUBJECT` to a stable workload identity (for example a SPIFFE URI) when you use the staging file-bearer resolver. The resolver preserves that subject on the authenticated caller. Production deployments should replace the single-token resolver with a rotating per-workload `BearerTokenResolver`. `APEX_BEARER_AGENT_ID` is required for the runnable file-bearer gateway. The credential is bound to one event `agent_id` and AGENT actor. Startup fails closed when it is missing. Bound callers are rejected when either identity does not match. Delegated USER, SYSTEM, or SCHEDULE actors require a separate workload identity resolver rather than the shared file token. `APEX_BEARER_CERT_SHA256` is also required by the runnable gateway. It must be the 64-character SHA-256 fingerprint of the authorized gRPC client certificate. The token is rejected when presented with another certificate trusted by the gateway CA. The mounted token is revalidated and refreshed periodically with trusted-path and ACL checks. Replacement revokes or rotates the staging credential without a process restart.

This test drives the real tonic gRPC server and generated client through the JetStream, ClickHouse, and archive publisher seams. Its durable test doubles model provider-side event-ID idempotency. It proves replay and conflict behavior without credentials or network services. The Compose E2E gate also requires approved `CLICKHOUSE_API_IMAGE` and `ARCHIVE_API_IMAGE` values plus certificates. Native ClickHouse and MinIO are not substitutes for those provider APIs.

When you hand a gateway failure to a coding agent, include:

1. The failing test name and full test output.
2. The output of `GatewayError::diagnostic_report(...).to_ai_markdown()`.
3. The command used, Rust/Cargo versions, and whether `test-support` was enabled.

The Markdown bundle is safe to share with an authorized coding agent. It includes the stable error code, summary, cause, scope, validated correlation IDs, component and stage evidence, retryability, and next steps. It omits raw event payloads, caller identity, and raw transport errors. Do not add those omitted values to an AI handoff unless a separate approved restricted-diagnostics workflow authorizes it.


---

Writing style: [ASD-STE100 Simplified Technical English](../../docs/writing-style-ste100.md).
