# Managed runtime integration checkpoint

Date: 2026-09-08. This is an implementation checkpoint, not a production release.

## Status and publication boundary

The [parent plan](../superpowers/plans/2026-09-04-working-mcp-gateway.md) has 22
tasks: 1–5 are complete; 6–22 are not fully closed. The five runtime tasks, six
enforcement/tracing tasks and six operator/release tasks total **17 open parent
tasks**. Component completion does not imply full task acceptance.

The separate runtime continuation has completed Tasks 1–3 and two open tasks,
4–5. Its nine unchecked acceptance items are not nine additional parent tasks.

Published integration baseline: `003fd45ac940661f73320cfac95059558576e4eb`.
Task4U's guard producer was committed in `71dc905`; Task4W's reviewed protected
guard-staging continuation and Node24 HTTP/2 regression fix are committed in `cdbcd1f`.
Task4X's paired staging is committed in `4ca8cb1` and included in this baseline.
Both [CI](https://github.com/zrmonty/apex-agent-control-plane/actions/runs/34122122484)
and [Live mTLS + E2E](https://github.com/zrmonty/apex-agent-control-plane/actions/runs/34122122459)
completed successfully for that exact merge SHA. This is not a production release
or acceptance of the still-open Serving and tracing gates.

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

Task4W's [protected guard staging](managed-guard-staging.md) implementation
passed scoped verification and independent review. It freezes guard data and signing
identity before exclusive storage effects, verifies exact sealed recovery, and
keeps missing/partial/changed state quarantined. Recovery evidence is limited to
service-process restart with the original mounts retained; it is not host reboot,
agent-container recreation, positive signed Apex deployment, or Serving acceptance.

Task4W verification: Linux303 passed/36 explicit ignores, Windows170 passed/5
explicit ignores, plus separately executed native network/signature refusal11 and
same-inode bind-mount refusal1. Strict Clippy on both platforms and scoped formatting
passed. Exact Linux image matched all25 Rust sources; largest owned Rust file539
lines. Original11-network inventory and94 unrelated dirty-file hashes were unchanged.

Task4X [paired gateway staging](managed-gateway-staging.md) is committed in `4ca8cb1`
and included in the published baseline; scoped implementation and final integration review passed. Its durable intent
binds the complete schema3 gateway inventory and original source/file identities
to the guard seal, installed revision and current image-signing selection. Recovery
never regenerates a proof or repairs an incomplete stage. Both stages remain
NotServing; positive production signed-fixture composition remains unproven.

Task4X corrected-source verification: Linux318 passed/39 explicit ignores and Windows170 passed/5
explicit ignores; separately executed bind-mount tests3 and native
network/signature-refusal regressions11 passed. All25 changed Rust files matched
the tested image, largest541lines. Strict Clippy and scoped formatting passed.
Native regression is not a positive signed paired-deployment proof. Original11
Docker networks and94 unrelated dirty-file hashes were unchanged.
Review identified two descriptor-identity races; both were reproduced and corrected
test-first, along with independent metadata-mutation cases. Scoped re-review passed.
An unchanged Windows ingress-capacity test failed twice under default parallelism
during worker verification; the controller's fresh default-parallel full suite
passed. That intermittent test concern is retained, not claimed fixed here.

The repo-wide source-line gate still fails on four unrelated, pre-existing dirty
test files: control-plane `proxy/tests.rs` (603 lines), ingest
`adversarial_integrity.rs` (603), `adversarial_malformed_payloads.rs` (702) and
`torn_write.rs` (676). Their hashes match the preserved pre-task baseline; this
stage did not modify them. Every Task4X Rust file remains below 600 lines.

Publication checks on 2026-09-07: fresh Windows agent tests passed170 with5 explicit
ignores, strict Clippy and scoped formatting passed, and all31 reviewed-file hashes
and94 preserved unrelated-file hashes matched their snapshots before committing.
The clean integration baseline passes the repo-wide source-line gate; the four
violations above belong only to excluded local edits. Docker Desktop failed startup
on its `dockerInference` socket, so no fresh local Linux rerun is claimed for this
publication pass. The exact-source Linux/native evidence above remains from
2026-09-06. Both remote workflows subsequently passed for the exact integration SHA
listed above. After the user restarted Docker on 2026-09-07, fresh retained-image
baseline checks passed318 Linux tests/39 explicit ignores and11 native network
tests/0 ignores; the original complete11-network inventory was unchanged. These
are pre-Task4Y baseline checks; final paired-container verification is recorded below.

Task4Y [verified stopped container pairs](managed-paired-containers.md) is
implemented and scoped-reviewed locally, not committed. It connects the sealed stages to
typed gateway/guard create, independent inspection and durable recovery. The
guard alone receives the outer attachment. Ambiguous effects and substituted
resources remain quarantined; paired pause/retire explicitly refuse unsupported
legacy cleanup. At that historical Task4Y boundary, containers remained never-started, with no registration, readiness,
route or Serving claim.

Independent final Task4Y verification on the exact33-source Linux image passed331
tests/45 explicit ignores; the six separately executed native paired cases passed
in110.21seconds; all11 existing native network regressions passed in46.11seconds
on the same image. Windows passed170/5 explicit ignores with default parallelism;
strict Clippy and scoped formatting passed. Largest changed Rust file551lines.
The original11-network objects and94 unrelated edits remain unchanged. Unsigned
stopped-component fixtures do not prove a signed Apex production deployment.
Review and independent verification exposed two defects. A held-real-RPC regression
reproduced shutdown authorizing a dispatch; the shared post-RPC shutdown check
now refuses it. A full Linux run then failed on journal reopen with
`RUNTIME_JOURNAL_BUSY`. A synchronized inherited-descriptor reproduction and
permanent kernel regression established the lock-lifetime mechanism; journal
destruction now explicitly unlocks while preserving live-owner exclusion. The
original untraced child identity remains unknown. Test failure cleanup was also
bounded. Both fix rounds passed scoped re-review; no findings remain open.

Task4Z [paired process start and recovery](managed-paired-start.md) is implemented
and scoped-reviewed locally, not committed. It adds
durable guard-first start intent and exact running recovery without treating
process state as readiness. Independent verification passed all seven native start
tests (228.50seconds), six stopped-pair tests (112.73seconds), and11 legacy network
tests (59.72seconds), plus the full Linux suite and170 Windows tests with5 explicit
ignores. Strict Windows Clippy and scoped formatting passed. All41 changed source
files matched the tested candidate image; three subsequent module-header comments
were corrected, with their executable source bodies independently verified
unchanged. The largest owned source file is551 lines. All94 unrelated file hashes
and the original11 complete Docker network objects remain unchanged.

Native validation exposed a Docker running-state representation difference and
two fixture collector errors; regressions and fixture corrections are retained
alongside their failed runs. All Docker test containers must be serialized with
native inventory checks, even network-none runners: disappearance between list
and inspection intentionally refuses. Tests use unsigned process fixtures, not a
signed Apex release. The integrated Task4Z production branch can perform guarded
paired start before returning NotServing with RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE;
that refusal does not prove no process started. Startup does not establish HTTPS,
registration, readiness, admission or safe paired retirement. Combined integration
review and documentation-only re-review passed with no open findings on2026-09-08.
Changes remain uncommitted. No parent task is closed by this component checkpoint.

1. Compose the actual gateway HTTPS/session root with live authority, upstream and
   evidence owners; establish non-admitting readiness, route selection and renewal,
   then safe pause/retire/replacement drain and physical resource cleanup.
2. Project admitted call evidence to scope-authorized activity/trace queries and the
   operator UI. Preserve integer microseconds, monotonic durations, clock metadata,
   missing spans and admission/completion links; never infer admission from a hash.
3. Run the complete two-proxy operator journey, outage/restart/restore and release
   gates. A running container, successful handshake or local unit suite is not a
   Serving claim.

### Subsequent local executable checkpoint

The managed executable now enters the fixed protected application root through
`src/managed/process.ts`, not the legacy `src/live/managed-runtime.ts` refusal
adapter. It requires sealed-stage-v2 metadata, verifies the actual immutable
stage and credential ownership, composes guarded authority/evidence/upstream
clients, and binds fixed health and HTTPS listeners. Nine concrete readiness
checks establish non-admitting PREPARE; admission additionally requires a fresh
selected SERVE grant. Readiness refresh does not extend the original grant.

Shutdown stops admission before joining physical owners and the exact completion
handoff. A signal arriving after automatic runtime loss cannot relabel failure
as graceful shutdown. Uncertain cleanup remains fatal; neither expiration nor
a cancellation request is physical closure evidence. These component changes
and the first-stop-cause correction passed independent scoped review.

Fresh unsigned Linux fixtures passed the public-root governed MCP call and
three actual-index scenarios: selected SERVE followed by SIGTERM, remote
transport loss, and invalid stage hash. The public-root call also proves required
evidence precedes output and an outstanding completion receipt survives shutdown.
These fixtures use synthetic remote authority/durability and are not joint
production control-plane/agent/event-ingest or signed-image acceptance.

The corrected locally built image
`sha256:ac0641a4eba03f6af15717aaaa8dbbbfd12a7288d16c5f15ad1b1c3ebf935d85`
passed packaging and all eight original-entrypoint negative/development startup
checks. Those checks explicitly do not establish managed readiness. The positive
Linux actual-index fixture executes a source bundle, not that packaged image.
No artifact was signed or published by this continuation.

### Fixed health observation executable

The image now also contains the separate
`/app/apps/mcp-gateway/dist/managed/health-process.js` executable. With no arguments,
it verifies the actual sealed-stage-v2 installation, uses the dedicated health
credential against fixed loopback `/readyz`, and emits one bounded canonical
ProtoJSON health-sample line only after socket and protected-material cleanup.
Its original seven-second deadline includes output handling; malformed input,
signals, unavailable health, and output failures remain nonzero static refusals.
No business credential factory, call reservation, evidence event or route decision
is invoked by this observer. Report identity is metadata, not authentication or
proof of current deployment authority.

Independent scoped review approved the observation, output-ownership and build
changes. Fresh gateway verification passed 2,150 tests with 11 environment-gated
skips, plus typecheck/build. Four explicit Linux cases passed for both the source
executable and the compiled executable in unsigned local image
`sha256:918e251c0f3d9d01868c2d70ec9c60d1d25c3a19b3676afb6b77ce67b427ee0b`:
ready PREPARE, wrong stage hash, absent health listener and unexpected argument.
Wrong-hash/argument cases first prove a working observer against the same ready
runtime. Packaging found zero test artifacts/private-key files; all eight existing
negative/development startup checks passed. Other native fixture helpers remain
source bundles with synthetic authority; this does not establish a fully packaged
managed deployment, real agent/controller collection, or signed release acceptance.

The subsequent health-freshness change is locally implemented and scoped-reviewed.
The real health server now supplies the original cached remaining validity as
`X-Apex-Readiness-Valid-For-Ns`; the observer anchors that duration before its
request and rejects expiry during decoding, socket closure or protected-stage
cleanup. Reading health never refreshes timestamps or leases. Missing, zero,
noncanonical or excessive validity is refused. The report remains metadata only:
an authenticated agent/controller handoff must carry conservative remaining
validity rather than assigning a new lease on receipt.

Verification for the freshness and concurrent cold-start work passed 2,187 gateway
tests with 11 explicit skips, typecheck and build. The freshness-specific checks
passed 52 tests. Fresh unsigned image
`sha256:257ad73be7c99907473774195adf0fd36540a9b8383c289bba1938675209d66e`
passed packaging (zero test artifacts/private keys), eight startup cases and four
compiled-health Linux cases. Four source-health cases also passed. These are
historical image checks; later changes and their verification follow below.

Cold-start convergence and its terminal-error correction passed scoped review.
Only explicitly classified ordinary dependency unavailability can retry before
first readiness, within the existing startup budget and physical cleanup ownership.
Binding, nonce, malformed-proof and credential failures remain terminal, as do all
post-first-ready failures. The corrected gateway suite passed 2,243 tests with
11 explicit skips; its covering cold-start/transport run passed 192 tests, followed
by typecheck/build. This is not paired production startup acceptance.

The fixed process now emits `RuntimeHealthSample` version 1, containing the
unchanged `ReadinessReport` and positive remaining `validForNs`. The original
expiry is checked through stdout completion. The envelope is bounded to 16,385
bytes including its single LF; the nested report retains an independent 8,192-byte
limit. Rust validates original bytes and full launch binding without converting
integer timings through floating point. Review caught the missing nested byte
limit; its test-first correction passed 18 report tests and explicit TypeScript-
to-Rust parity, and passed scoped re-review. Successful decoding grants no
freshness or serving authority. Actual daemon execution ownership and authenticated
forwarding must still subtract elapsed time from a pre-dispatch anchor.

Unsigned image
`sha256:ec7a60d0fe60f039d502273ef2c3f81993c0f4bf91b7d7c70bd2438f932a858c`
includes the new fixed process and passed all four compiled-health Linux cases;
the parent fixture measures from before child spawn through physical reap.
The focused TypeScript process/owner suite passed 32 tests. Other fixture services
still use synthetic authority, and forced guard cleanup is not graceful drain proof.

The controller NETWORK relay now preserves only recognized authenticated runtime
contention as a static resource-exhausted response, after credential, original
budget and PostgreSQL eligibility rechecks. Permission, validation and unknown
errors remain terminal. Five real mTLS transport checks and the extended Linux
two-hop mTLS/PostgreSQL test passed; strict Clippy passed on Windows and Linux.
Scoped relay review passed. The agent reply in this test is synthetic, and
this check does not prove that a signed paired deployment becomes Serving.

The Rust health-report consumer also passed scoped review and Windows/Linux
cross-language checks, including exact integer stage timing and optional uncertainty.
It validates original stdout and installed identity; decoding does not establish
currentness, freshness, selection or admission authority.

The agent now has a local, uncommitted `RuntimeHealthObservation.Observe` path:
Controller mTLS, exact installed binding and nonce, fixed Docker exec, a separate
protected exec journal, and monotonic sample lifetime preserved through handoff.
Health reservations permit concurrent NETWORK inspection but exclude reconciliation;
only two health workers may occupy the eight-worker pool. Ambiguous started execs
retain physical ownership until exact daemon completion, or remain recorded across
agent shutdown. This collector is **not yet accepted**: positive Controller-TLS
collection through the installed journal/worker, interrupted-start/restart coverage,
and independent integrated review remain open. The fresh control-plane client and
selection path are not wired yet.

The fixed Engine transport has now passed an actual Docker daemon test against the
packaged health executable in the unsigned managed application fixture: create,
never-started inspection, attached start, separately observed terminal exit 0, and
strict bound sample decoding with nine checks and remaining nanosecond validity.
This exposed and corrected Docker's nullable pre-exit `ExitCode`: explicit null is
preserved as absence, missing/malformed fields still refuse, and cleanup requires
an actual integer exit code. The gateway closed gracefully without business
admission; fixture guard teardown was forced and is not graceful guard evidence.
This proves the packaged probe boundary, not the entire authenticated collector,
published revision/signature acceptance, route permission, or production deployment.

Current component checks: Linux library 240 passed/88 explicit ignores; separately
selected health TLS3, network TLS3, fixed-engine Unix HTTP10, nullable-exit2 and
physical cleanup/recovery14 passed. The latter reproduced and fixed shutdown during
terminal or never-started inspection, and retain unknown/null-exit history across
shutdown/restart. Their external daemon responses are Unix HTTP fixtures, not a
positive full authenticated collector deployment. Windows
library81 passed/13 explicit ignores plus TLS6; strict agent Clippy passed on both
platforms. The Linux journal32 and physical pool cancellation checks passed.
Earlier broad Linux runners used incompatible capabilities or omitted required
fixture inputs; corrected runners passed. These are unsigned local checks, not
production deployment or complete physical lifecycle evidence. Engine-only, actual-
daemon interoperability and physical cleanup/recovery scoped reviews passed; they
do not approve the complete collector's authenticated journal/caller integration.

This supersedes the first resume item's gateway-composition prerequisite only.
Controller-authenticated readiness observation, route publication after applied
SERVE, replacement ordering, and paired pause/retire/drain remain unfinished.
The production agent network path therefore remains explicitly non-serving.
Full trace projection/query/UI and operator/release acceptance are still open;
no parent task or aggregate Task4/Task5 checkbox is closed. All unrelated roadmap
work remains on hold.

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
