# Codebase Hardening Baseline

## Readability gate

The repository readability gate applies to tracked files whose names end in
`.rs`, `.ts`, `.tsx`, `.js`, `.mjs`, `.py`, `.go`, `.java`, or `.cs`. Files
under `.git`, `target`, `node_modules`, `dist`, `build`, or a virtual
environment directory are excluded. A file is an offender when it contains
more than 600 lines, counted with Python `str.splitlines()`.

The authoritative check is:

```text
python scripts/check_source_line_limits.py
```

This inventory started from commit `2e3245f` on 2026-09-03. The initial table
below records the pre-split offenders. After the responsibility-based splits,
the authoritative checker reports no tracked source/test offenders; the
checker remains the source of truth in CI:

| Lines | File |
| ---: | --- |
| 1031 | `apps/event-ingest/src/auth/service.rs` |
| 732 | `crates/apex-policy/src/types.rs` |
| 710 | `apps/event-ingest/src/startup/service.rs` |
| 692 | `deploy/compose/loadtest/loadtest.py` |
| 658 | `crates/apex-durability/src/outbox/tests_cases.rs` |
| 634 | `apps/control-plane-api/src/inbox_postgres.rs` |
| 611 | `apps/control-plane-api/src/startup/tests.rs` |
| 606 | `crates/apex-security/src/tests.rs` |
| 605 | `apps/control-plane-api/src/service/tests/poll.rs` |
| 605 | `deploy/compose/live-mtls/generate_pki.py` |
| 604 | `apps/control-plane-api/src/envelope.rs` |

## Responsibility-based split order

Splits should preserve the existing module paths and public exports. Each
step is independently tested before the next one begins.

1. `apps/event-ingest/src/auth/service.rs`: separate credential and caller
   authentication, admission/backlog state, and server construction; move
   focused auth and admission tests alongside those responsibilities.
2. `crates/apex-policy/src/types.rs`: separate identifiers and scope,
   authorization and approval decisions, and execution/event metadata and
   receipts.
3. `apps/event-ingest/src/startup/service.rs`: separate configuration and
   store construction, fanout publisher setup, and feature-specific reaper
   workers.
4. `deploy/compose/loadtest/loadtest.py`: separate transport and credential
   loading, scheduling/submission, result reporting, and CLI orchestration.
5. `crates/apex-durability/src/outbox/tests_cases.rs`: group tests by file
   outbox persistence, replay/quarantine behavior, and drain/recovery
   signaling.
6. `apps/control-plane-api/src/inbox_postgres.rs`: separate inbox command
   operations, recovery behavior, and configuration/error helpers.
7. `apps/control-plane-api/src/startup/tests.rs`: group credential/config
   parsing, network/TLS boundary, and store/fanout startup tests.
8. `crates/apex-security/src/tests.rs`: group finding lifecycle and scoping,
   validation/capacity, and detector/identifier tests.
9. `apps/control-plane-api/src/service/tests/poll.rs`: group polling and
    acknowledgement, credential/rate-limit boundaries, and submission or
    idempotency behavior.
10. `deploy/compose/live-mtls/generate_pki.py`: separate key/certificate
    generation, runtime secret-table writers, and CLI/output orchestration.
11. `apps/control-plane-api/src/envelope.rs`: separate command input and
    request mapping, event data/hash construction, and UUID timestamp helpers.

The order prioritizes the largest active-runtime modules, then their dense
test surfaces and operational scripts. No application behavior changes are
part of the split work; security and throughput changes are documented in the
companion review and performance baseline.

## Completed result

```text
python scripts/check_source_line_limits.py
No tracked source files exceed 600 lines.
```

Responsibility-based splits were applied to the eleven initial offenders and
to the gateway admission test surface. The split modules preserve their
existing public paths and test behavior; the final verification matrix is
recorded in the SDD ledger at
`.superpowers/sdd/2026-09-03-codebase-readability-security-throughput/progress.md`.
