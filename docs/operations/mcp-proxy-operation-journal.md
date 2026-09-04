# MCP proxy operation journal

Task 2 supplies PostgreSQL operation storage, controller lease/fencing primitives,
and durable evidence intents with a startup-wired relay into the existing Apex
outbox. These are storage and recovery capabilities. The full runtime lifecycle
controller remains unwired; runtime reconciliation and real pause/resume/retire
behavior remain Task 9 work. An accepted operation or successful journal test is
not evidence of a ready runtime or a usable MCP gateway.

## Storage profile and migration

`APEX_CONTROL_PROXY_PROFILE` accepts exactly `production` or `development`.
Omitting it selects the production requirements. Default/production startup
requires `APEX_CONTROL_POSTGRES_URL` and a binary built with the `postgres`
feature. Missing configuration, connection failure, or schema failure prevents
startup; production does not fall back to memory. Memory is permitted only with
explicit `development` and no PostgreSQL URL. Development with a configured URL
still uses PostgreSQL and fails if that backend cannot open.

The test-only `APEX_PROXY_JOURNAL_TEST_DATABASE_URL` does not configure service
startup. Supply production connection details through the deployment's secret
configuration. Use the existing verified TLS transport policy for production;
the plaintext flag and sample credentials below are exclusively for local/CI
labs. Keep the control database/schema separate from the ingest database/schema,
since their outboxes share table names.

`PostgresProxyStore::connect` applies
[`mcp_proxies.sql`](../../deploy/postgres/mcp_proxies.sql), then
[`mcp_proxy_operations.sql`](../../deploy/postgres/mcp_proxy_operations.sql),
under the store's migration advisory lock. The additive operation migration runs
as one batch, also takes a transaction advisory lock, and records schema version
1 in `mcp_proxy_operation_schema`. Before journal DDL, a version guard accepts
only a fresh schema or the complete supported version. Unknown, mixed, empty,
unversioned or incomplete journal schemas are rejected without replacing their
journal objects or functions. Repeat application preserves the existing
immutability triggers. Let the store apply the migration; do not run isolated
DDL fragments against a live database.

## Atomic operations and immutable evidence

The public store methods are defined in
[`store/postgres/operations.rs`](../../apps/control-plane-api/src/proxy/store/postgres/operations.rs),
with transaction logic in
[`operation_journal.rs`](../../apps/control-plane-api/src/proxy/store/postgres/operation_journal.rs).
Callers supply an authorized exact workspace/namespace/proxy scope and a
server-built, validated EventEnvelope v1. The journal does not perform caller
authentication or runtime deployment.

- `submit_proxy_operation` locks the scoped proxy, checks the expected active
  revision and deployment generation, and requires a published target revision.
  It commits the desired state (`serving`, `paused`, or `retired`), next
  generation, operation/idempotency result, and acceptance evidence intent in one
  transaction. Failure rolls back all of those changes together.
- `mcp_proxy_operations` retains the immutable operation/request identity,
  semantic request hash, generation, and original accepted result. Repeating a
  request with the same semantic body returns that original acceptance; changing
  the body conflicts. A retry does not create another operation or replace the
  original evidence. `get_proxy_operation` returns the current result for the
  exact scope/proxy/operation, which may have advanced since acceptance.
- `lease_proxy_operation` uses database time and a persistent per-proxy fencing
  counter. A claim after expiry or for a newer generation increases the token.
  Leases are bounded to 300 seconds. `observe_proxy_operation` requires the live
  worker/token, operation, revision, and current generation, then commits the
  observation/result and its evidence intent together. Stale/expired observers
  are refused, including retries. Never delete/recreate lease rows to release a
  claim: their counter must survive handoff and generation changes.
- Leasing and observation also compare the live desired state and revision,
  so a legacy lifecycle update cannot leave an obsolete operation actionable.
  Completed operations cannot be reopened by a new observation; exact replay
  retains the frozen result without appending another transition.
- Every transition has its own lowercase UUIDv7 event ID. The UUIDv7 request ID
  correlates events through `run_id`; it is not reused as their event ID. An
  observation retry reuses its original event identity and payload and returns
  the frozen transition result while its fence remains valid.
- `mcp_proxy_evidence_intents` freezes the event ID, timestamp, original validated
  protobuf envelope bytes (`canonical_payload`), canonical Apex v1 `payload_hash`,
  and transition result. The hash is the established canonical event hash, not a
  hash of protobuf serialization bytes. The frozen EventEnvelope v1 hash contract
  remains unchanged. SQL triggers reject edits/deletes of evidence and immutable
  operation identity; the enqueue marker can only be set once.

## Relay and recovery boundaries

With PostgreSQL storage, service startup calls `spawn_proxy_evidence_worker`,
which starts the
[`evidence relay`](../../apps/control-plane-api/src/proxy/operation_worker.rs).
It discovers committed pending intents without a client retry, including after
restart. Each page contains at most 8 proxy targets and relays at most 16 events
per target. Exactly one blocking job owns the synchronous resources for the
worker's lifetime, with a 250-ms pause between pages. Inventory failures back off
up to four seconds. Idle cancellation is checked within 50 ms, and cancellation
is also checked between proxies and events. No replacement job overlaps old work.
Keyset pagination advances past failed targets so a poison proxy cannot starve
later pages; its pending intents are retried on the next sweep.

The startup wrapper exposes the named health service
`apex.v1.McpProxyService.EvidenceRelay`, initially `NotServing`, and refreshes it
every second. Relay health becomes healthy only after a complete clean sweep;
a successful later page cannot hide an earlier failure. Failure clears health,
and recovery requires a subsequent complete clean sweep. Shutdown or worker exit
reports `NotServing`. Shutdown waits for the relay and releases its store/outbox
ownership on a blocking thread, including when it holds the last reference.
Aborting its async supervisor requests cooperative cancellation; the blocking
worker retains ownership until exit, avoiding PostgreSQL destruction on Tokio.
This health signal describes evidence relay progress, not runtime readiness.

`relay_proxy_evidence` reads pending intents for an exact scope/proxy in bounded
batches of 1–256, validates the stored envelope against its identity/hash, and
submits it through `ControlOutboxBackend` using the existing
outbox enqueue/identity path. The relay tries available connection mutexes instead
of waiting behind busy requests or fanout. It marks `enqueued_at_micros` only after outbox
acceptance. Synchronous database work belongs on a bounded blocking worker,
outside Tokio runtime worker threads.

The store reconnects a closed PostgreSQL connection before the next operation,
using the same verified transport configuration, and reapplies a five-second
statement timeout and two-second lock timeout. It never automatically replays
a transaction whose commit result is uncertain. The background relay retries
from immutable intents, while mutation callers reuse their original request ID.
The control outbox applies the same policy, including on replacement connections.
The worker adapter uses a private current-thread asynchronous driver behind its
synchronous SQL interface. One five-second connect deadline covers trust-material
loading, resolution, socket connection and protocol/TLS startup; each SQL call has a five-second
client deadline in addition to the server-side statement/lock limits. A client
deadline aborts and joins the socket driver, closes the connection, and refuses
reuse. Transaction/savepoint cleanup is bounded by the same policy. There is no
automatic replay of an uncertain mutation. Construct, use and drop these clients
outside Tokio worker threads.

OS hostname lookup cannot be forcibly cancelled. A single process-owned resolver
thread with a bounded 16-request queue contains that resource use; callers still
time out and never wait for it during runtime teardown. Expired requests cannot
open a database connection. Explicit addresses bypass resolution, and resolved
addresses retain the original hostname for TLS verification. A stuck OS lookup
can make further hostname-based connections unavailable until it returns; it
does not create unbounded replacement threads. Socket user timeout and keepalive
settings remain supplementary, not substitutes for client deadlines.

Host attempts preserve configured ordering or random host selection, and resolve
only the host being attempted. A healthy primary does not depend on unused backup
DNS. CA path lookup, metadata/read, parsing and TLS configuration run on a separate
single process-owned trust worker with a 16-job queue, inside the same deadline.
A stuck filesystem operation can make new TLS connections unavailable until it
returns; retries neither accumulate threads nor dispatch expired work. Existing
CA and certificate-name verification remain authoritative.

The startup-abort, backup-DNS, stalled-loader and real TLS regressions now pass,
including serial execution. Independent review approved this Task 2 checkpoint
after the fault-path fixes and fresh aggregate verification. This does not approve
the deferred runtime controller, full service lifecycle or a release gate.

The operation transaction and outbox enqueue are separate commits. A crash after
operation commit leaves a pending durable intent. A crash after outbox acceptance
but before marking leaves that same intent eligible for replay; retry preserves
its event ID, timestamp, payload, and hash so outbox deduplication can resolve the
uncertain enqueue. Enqueue failure leaves the intent pending. Operators should
preserve pending rows and investigate the relay/outbox failure, rather than
manually marking or regenerating events.

The relay does not publish downstream directly. Existing outbox workers own
downstream delivery. An enqueue marker proves outbox acceptance, not downstream
delivery or runtime readiness. The startup evidence relay is wired; the Task 9
runtime controller is not. Validate that controller's integration separately
before making lifecycle or usable-gateway claims.

## CI and temporary local PostgreSQL verification

The [`rust-control-plane` CI job](../../.github/workflows/ci.yml) starts a real
PostgreSQL service pinned to the same image digest used by the existing lab
Compose topology. A `pg_isready` health check gates the job. The control-plane
test step supplies `APEX_PROXY_JOURNAL_TEST_DATABASE_URL` at literal loopback
`127.0.0.1:15432` with `sslmode=disable` and
`APEX_ALLOW_POSTGRES_PLAINTEXT=1`, and keeps `RUST_TEST_THREADS=1`.
An explicit second test step exercises `apex-durability` worker unit tests with
real loopback sockets and TLS fixtures. Cargo does not run dependency unit tests
as part of the application test command. These fixtures require no database and
do not alter production trust configuration.

The `postgres`-feature journal tests and
[`proxy_operation_recovery`](../../apps/control-plane-api/tests/proxy_operation_recovery.rs)
require this dedicated database: missing/unreachable configuration fails the
tests instead of skipping them. Fixtures create isolated schemas, so the lab
role needs schema/DDL permissions. Unit fixtures roll back their schemas;
recovery fixtures remove their generated schemas on normal cleanup. A killed
test runner can leave fixtures behind, which is why the database must be
disposable. Never point these tests at production or a shared developer database.

For a temporary local run, use PowerShell from the repository root with Docker's
Linux-container engine running, the Rust test toolchain installed, and port
15432 free. The following commands intentionally use lab-only credentials and a
uniquely named, disposable container with no host data mount. They run the same
feature set as CI, including the journal, recovery, and profile tests. Stopping
this `--rm` container removes its temporary database and anonymous volumes.

```powershell
$journalContainer = 'apex-proxy-journal-' + [guid]::NewGuid().ToString('N')
$journalImage = 'postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'
$journalPreviousUrl = [Environment]::GetEnvironmentVariable('APEX_PROXY_JOURNAL_TEST_DATABASE_URL', 'Process')
$journalPreviousPlaintext = [Environment]::GetEnvironmentVariable('APEX_ALLOW_POSTGRES_PLAINTEXT', 'Process')
$journalPreviousThreads = [Environment]::GetEnvironmentVariable('RUST_TEST_THREADS', 'Process')

docker run --detach --rm --name $journalContainer `
  --publish 127.0.0.1:15432:5432 `
  --env POSTGRES_USER=apex_journal_ci `
  --env POSTGRES_PASSWORD=apex_journal_lab_only `
  --env POSTGRES_DB=apex_proxy_journal `
  --health-cmd 'pg_isready -h 127.0.0.1 -U apex_journal_ci -d apex_proxy_journal' `
  --health-interval 5s --health-timeout 5s --health-retries 12 $journalImage
if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable journal database.' }

try {
  $journalReady = $false
  for ($attempt = 0; $attempt -lt 30; $attempt++) {
    $journalHealth = docker inspect --format '{{.State.Health.Status}}' $journalContainer
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the journal database.' }
    if ($journalHealth -eq 'healthy') { $journalReady = $true; break }
    if ($journalHealth -eq 'unhealthy') { break }
    Start-Sleep -Seconds 2
  }
  if (-not $journalReady) {
    docker logs --tail 40 $journalContainer
    throw 'Journal database did not become healthy.'
  }
  $env:APEX_PROXY_JOURNAL_TEST_DATABASE_URL = 'postgres://apex_journal_ci:apex_journal_lab_only@127.0.0.1:15432/apex_proxy_journal?sslmode=disable'
  $env:APEX_ALLOW_POSTGRES_PLAINTEXT = '1'
  $env:RUST_TEST_THREADS = '1'
  cargo test --manifest-path apps/control-plane-api/Cargo.toml --locked `
    --features 'test-support,postgres,valkey' -- --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'Control-plane tests failed.' }
  cargo test -p apex-durability --locked --all-features --lib `
    postgres_transport::worker -- --nocapture
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL worker boundary tests failed.' }
} finally {
  docker stop $journalContainer
  [Environment]::SetEnvironmentVariable('APEX_PROXY_JOURNAL_TEST_DATABASE_URL', $journalPreviousUrl, 'Process')
  [Environment]::SetEnvironmentVariable('APEX_ALLOW_POSTGRES_PLAINTEXT', $journalPreviousPlaintext, 'Process')
  [Environment]::SetEnvironmentVariable('RUST_TEST_THREADS', $journalPreviousThreads, 'Process')
}
```

For a focused journal run, replace the Cargo invocation inside that block with
these two commands, checking each exit code before continuing:

```powershell
cargo test --manifest-path apps/control-plane-api/Cargo.toml --locked --features postgres --lib operation_journal -- --nocapture
if ($LASTEXITCODE -ne 0) { throw 'Journal unit tests failed.' }
cargo test --manifest-path apps/control-plane-api/Cargo.toml --locked --features postgres --test proxy_operation_recovery -- --nocapture
if ($LASTEXITCODE -ne 0) { throw 'Journal recovery tests failed.' }
```

These commands are a verification recipe, not a recorded successful run. Record
actual command output and revision in the
[release evidence ledger](mcp-gateway-release-evidence.md). YAML parsing checks
the CI document's syntax; it does not demonstrate service startup, passing Rust
tests, successful recovery, or completion of Task 9.
