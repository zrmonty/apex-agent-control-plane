# Managed runtime integration checkpoint

Date: 2026-09-06. This is an implementation checkpoint, not a production release.

## Status and publication boundary

The [parent plan](../superpowers/plans/2026-09-04-working-mcp-gateway.md) has 22
tasks: 1–5 are complete; 6–22 are not fully closed. The five runtime tasks, six
enforcement/tracing tasks and six operator/release tasks total **17 open parent
tasks**. Component completion does not imply full task acceptance.

The separate runtime continuation has completed Tasks 1–3 and two open tasks,
4–5. Its nine unchecked acceptance items are not nine additional parent tasks.

Integration baseline: `fe8ce35618474880914b15bab42c71c7e1970188`, the previous
CI authority-observation fix merge. Task 4U's reviewed guard data producer is
committed in `71dc905`; this documentation records its integration checkpoint.
GitHub CI status must be checked for the exact release SHA; no remote CI success
or production release is asserted by this document.

Fresh pre-commit checks on 2026-09-06 passed 287 agent tests (34 explicit ignores),
one actual Rust producer export, 118 unchanged TypeScript consumer tests and ten
native empty-network/dormant tests. All 13 Rust source files matched the approved
snapshot and retained Linux image exactly. Scoped formatting and five registry
component tests passed. Independent documentation/source-integrity review found
no actionable issues. The native runner removed only its new fixture resources;
the original complete network inventory was unchanged. These checks do not close
the integrated Serving or tracing release gates.

## Included boundaries

- Published-revision launch binding and protected material selection; authenticated
  production agent reconciliation with bounded, durable stopped-container effects.
- PostgreSQL-backed managed deployment selection and call reservations, enrolled
  workload credentials, and canonical metadata-only durable event admission.
- Protected Linux stage readers, credential-role separation, inbound verification,
  guarded TLS/HTTP/upstream clients, and a compiled read-only executor.
- Strict guard configuration, actual ingress/egress relay process ownership, and
  stage-bound governance/evidence HTTP/2 transports with separate credentials.
- Durable network reservations and strict empty-network create/inspect/recovery.
  Concurrent valid topology publication must not falsely poison history; real
  corruption remains quarantined, including after bytes are restored.

See the focused `managed-*` operations documents and the
[continuation plan](../superpowers/plans/2026-09-05-runtime-execution-continuation.md)
for contracts and limitations. Native fixtures establish their named boundaries,
not an integrated deployment of the entire product.

## Resume order

After the pushed checkpoint, Task4U implemented and independently reviewed the
[key-free guard data producer](managed-guard-stage-producer.md). Its 17 focused
Rust tests, actual Rust-to-TypeScript handoff and native dormant-path regression
passed. This does not close any stage-write or execution boundary below.

1. Connect protected staging and verified gateway/guard container provisioning,
   inspect actual networking, and implement start/recovery without weakening
   current-operation checks or uncertain-effect quarantine.
2. Compose the actual gateway HTTPS/session root with live authority, upstream and
   evidence owners; establish non-admitting readiness, route selection and renewal,
   then safe pause/retire/replacement drain and physical resource cleanup.
3. Project admitted call evidence to scope-authorized activity/trace queries and the
   operator UI. Preserve integer microseconds, monotonic durations, clock metadata,
   missing spans and admission/completion links; never infer admission from a hash.
4. Run the complete two-proxy operator journey, outage/restart/restore and release
   gates. A running container, successful handshake or local unit suite is not a
   Serving claim.

`apps/mcp-gateway/src/index.ts` delegates managed activation to
`src/live/managed-runtime.ts`, which still throws `GOVERNANCE_UNAVAILABLE`.
The execution agent's network path also remains explicitly non-serving. All
unrelated roadmap work remains on hold.

## Recorded checkpoint verification

These are results from the named implementation checkpoints, not tests rerun by
the documentation pass. Preserve their fixture, platform and scope limitations.

The 2026-09-06 local checkpoint passed contracts (108 tests), gateway (1,917
passed, two explicitly skipped), operator UI (305 tests), their builds/typechecks,
and workspace all-target/all-feature Rust Clippy. Windows Rust coverage passed
the control-plane library (760), binary (94, including actual browser journeys),
all integration targets and doc-tests, and the remaining workspace test command.
Infrastructure-gated tests that return without their fixture are not native proof.

A fresh Linux image matched 968 recorded source inputs. Its control-plane library
passed 761 tests with three explicit Linux cases subsequently run and passed;
its non-browser root passed 82 tests. Separate Linux ingest and protected evidence
checks passed, including actual typed TypeScript-to-Rust mTLS admission and
reopened durable journal preservation of integer 1, 7 and 999 microseconds.
These are bounded component/integration proofs, not complete trace-query/UI or
production Serving acceptance. GitHub Actions results are a separate remote gate.
