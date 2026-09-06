# Managed runtime integration checkpoint

Date: 2026-09-06. This is an implementation checkpoint, not a production release.

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

1. Produce key-free guard configuration and sealed-stage metadata from genuinely
   held current publication/catalog inputs and validated durable topology. Preserve
   exact identity joins and bounded integer-microsecond expiry. Preparation is data,
   not permission to stage, sign, create or start anything.
2. Connect protected staging and verified gateway/guard container provisioning,
   inspect actual networking, and implement start/recovery without weakening
   current-operation checks or uncertain-effect quarantine.
3. Compose the actual gateway HTTPS/session root with live authority, upstream and
   evidence owners; establish non-admitting readiness, route selection and renewal,
   then safe pause/retire/replacement drain and physical resource cleanup.
4. Project admitted call evidence to scope-authorized activity/trace queries and the
   operator UI. Preserve integer microseconds, monotonic durations, clock metadata,
   missing spans and admission/completion links; never infer admission from a hash.
5. Run the complete two-proxy operator journey, outage/restart/restore and release
   gates. A running container, successful handshake or local unit suite is not a
   Serving claim.

`apps/mcp-gateway/src/index.ts` still refuses managed production activation.
The execution agent's network path also remains explicitly non-serving. All
unrelated roadmap work remains on hold.

## Checkpoint verification

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
