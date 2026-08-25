# Data Plane Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the durable event and command data plane bounded, reclaimable, fail-visible, and contract-faithful under retries, restarts, provider faults, and concurrent writers.

**Architecture:** Keep the existing backend abstractions, but make lifecycle operations explicit. Event replay will use the fallible bounded batch API end-to-end; durable idempotency stores will share the outbox retention window and compact file state. The command inbox will persist cancellation timestamps and expose fallible diagnostics. HTTP/provider boundaries will acknowledge only the statuses and integrity evidence promised by the contracts.

**Tech Stack:** Rust 2024, Tokio, serde JSONL journals, PostgreSQL, prost/HTTP, Python reference providers, cargo test, cargo fmt, clippy.

**Spec:** `contracts/clickhouse/v1.md`, `contracts/archive-provider/v1.md`, `contracts/postgres-idempotency.md`, `contracts/postgres-outbox.md`, and the 2026-08-25 data-layer audit findings.

## Global Constraints

- Preserve the existing `master` checkout and implement only in the isolated `codex/data-plane-hardening` worktree.
- Keep file journals backward-compatible: legacy records without lifecycle timestamps remain retained rather than being silently deleted.
- Every production behavior change gets a regression test that fails against the baseline before the implementation is written.
- Replay reads and provider request bodies remain bounded by existing batch and payload ceilings.
- Do not claim cloud-provider acceptance without running the provider-specific acceptance environment; local tests must prove the boundary behavior only.

---

### Task 1: Make event replay bounded, deadline-aware, and fallible

**Files:**
- Modify: `apps/event-ingest/src/outbox/publisher.rs`
- Modify: `apps/event-ingest/src/outbox/tests_cases.rs`
- Modify: `apps/event-ingest/src/outbox/file_ops.rs` only if ordering/deadline coverage needs a focused helper
- Test: `apps/event-ingest/src/outbox/tests_cases.rs`

**Interfaces:**
- Consume `EventOutbox::pending_batch(limit) -> Result<Vec<IngestRequest>, GatewayError>`.
- Keep `PendingEventReplayer::replay_pending` as the fallible one-cycle API.
- Preserve durable backend-specific claiming and retry scheduling.

- [x] **Step 1: Change the regression expectation first**

  Update the existing file replay test that currently documents rapid retry after `reschedule`. Assert that the first failed cycle schedules the row in the future and the immediately following cycle does not publish it again. Add an assertion that a later cycle after the deadline publishes it.

- [x] **Step 2: Run the focused test and verify the baseline failure**

  Run:

  ```bash
  cargo test --locked --features test-support outbox::tests::a_permanently_failing_event_is_quarantined_after_the_replay_ceiling_instead_of_retried_forever -- --exact
  ```

  Expected: fail because `replay_pending_inner` currently reads `pending()` and ignores `next_attempt_at_millis`.

- [x] **Step 3: Use the bounded API in the worker**

  Replace the bare `self.outbox.pending()` call with `self.outbox.pending_batch(FANOUT_BATCH_SIZE)?` (or the crate’s existing batch constant), preserving per-event publish isolation and returning storage read failures to the worker. Ensure the worker never clones the whole durable backlog.

- [x] **Step 4: Run the focused test and the outbox module**

  Run the exact test again, then:

  ```bash
  cargo test --locked --features test-support outbox::tests --lib
  ```

  Expected: both pass with no warnings caused by the change.

- [x] **Step 5: Commit the replay hardening slice**

  ```bash
  git add apps/event-ingest/src/outbox/publisher.rs apps/event-ingest/src/outbox/tests_cases.rs apps/event-ingest/src/outbox/file_ops.rs
  git commit -m "fix: bound event replay reads and honor retry deadlines"
  ```

### Task 2: Give durable idempotency state a retention lifecycle

**Files:**
- Modify: `apps/event-ingest/src/idempotency/types.rs`
- Modify: `apps/event-ingest/src/idempotency/file.rs`
- Modify: `apps/event-ingest/src/idempotency/postgres.rs`
- Modify: `apps/event-ingest/src/idempotency/memory.rs`
- Modify: `apps/event-ingest/src/idempotency/tests.rs`
- Modify: `apps/event-ingest/src/idempotency/postgres_tests.rs`
- Modify: `apps/event-ingest/src/startup/service.rs`
- Modify: `apps/event-ingest/src/auth/service.rs`
- Modify: `apps/event-ingest/src/startup/env.rs`
- Modify: `deploy/postgres/idempotency.sql`

**Interfaces:**
- Add a default `IdempotencyStore::maintain(now_millis, retention_millis)` method so test-only/custom stores remain source-compatible.
- File store records new committed timestamps and compacts expired committed records atomically; legacy records without timestamps remain retained.
- PostgreSQL maintenance deletes only committed rows older than the configured retention and continues to reap crashed pending reservations separately.
- The production retention worker invokes both outbox and idempotency maintenance on the same interval and retention window.

- [x] **Step 1: Add a failing file-store capacity-reuse test**

  Fill a small `FileIdempotencyStore`, commit the records, assert a new key is rejected at capacity, call `maintain` with a cutoff beyond the committed timestamps, then assert a new key can be reserved and committed and survives reopen.

- [x] **Step 2: Run the new test against the baseline**

  Run:

  ```bash
  cargo test --locked --features test-support idempotency::tests::file_idempotency_reclaims_expired_committed_capacity --lib
  ```

  Expected: fail because the trait has no maintenance operation and committed records are never removed.

- [x] **Step 3: Add the lifecycle API and file implementation**

  Add timestamped committed records, load them backward-compatibly, remove only timestamped records at or before `now - retention`, and rewrite the remaining journal using the existing file-journal atomic-compaction pattern. Restore in-memory maps if compaction fails.

- [x] **Step 4: Add PostgreSQL maintenance and schema/index support**

  Keep `pending` crash reaping intact, add a committed-retention delete keyed by `committed_at`, and add a partial index for committed retention scans. Add an opt-in PostgreSQL test that commits an event, runs maintenance with a zero retention window, and proves a new reservation is admitted.

- [x] **Step 5: Wire maintenance into startup**

  Reuse the validated `APEX_OUTBOX_RETENTION_SECS` and interval settings so event idempotency and outbox history have one operational lifecycle. Make the maintenance worker iterate the configured admission stores, log/metric failures, and keep request serving alive during a transient maintenance failure.

- [x] **Step 6: Run the focused idempotency suite and startup tests**

  ```bash
  cargo test --locked --features test-support idempotency --lib
  cargo test --locked --features test-support startup --lib
  ```

- [x] **Step 7: Commit the lifecycle slice**

  ```bash
  git add apps/event-ingest/src/idempotency apps/event-ingest/src/startup apps/event-ingest/src/auth/service.rs deploy/postgres/idempotency.sql
  git commit -m "fix: reclaim durable idempotency state on retention"
  ```

### Task 3: Make cancelled command records retire and make inbox diagnostics fail-visible

**Files:**
- Modify: `apps/control-plane-api/src/inbox/state.rs`
- Modify: `apps/control-plane-api/src/inbox/file.rs`
- Modify: `apps/control-plane-api/src/inbox.rs`
- Modify: `apps/control-plane-api/src/inbox/backend.rs`
- Modify: `apps/control-plane-api/src/inbox_postgres.rs`
- Modify: `apps/control-plane-api/src/inbox/tests/file.rs`
- Modify: `apps/control-plane-api/src/inbox/tests/state.rs`
- Modify: `apps/control-plane-api/src/inbox_postgres/tests.rs`
- Modify: `deploy/postgres/control_inbox.sql` only if a supporting index is required
- Modify: `apps/control-plane-api/src/startup/service/workers.rs`

**Interfaces:**
- Persist `cancelled_at_millis` in the in-memory/file state and use it as the settlement timestamp.
- Include cancelled rows in retention retirement while preserving their status during the configured idempotency window.
- Add fallible diagnostic count methods with compatibility defaults; PostgreSQL overrides them to propagate query errors instead of converting an outage to zero.

- [x] **Step 1: Add failing cancellation-retirement and diagnostic tests**

  Add a file test that records and cancels a never-delivered command, calls `maintain` after retention, reopens the journal, and proves the scope quota is reusable. Add a state test proving cancelled commands are not counted as undelivered. Add a PostgreSQL test that exercises the same retirement path when `APEX_CONTROL_POSTGRES_URL` is configured.

- [x] **Step 2: Run the focused tests against the baseline**

  ```bash
  cargo test --locked --features test-support inbox::tests::file::cancelled_command_reclaims_scope_capacity --lib
  cargo test --locked --features test-support inbox::tests::state::cancelled_commands_are_not_undelivered --lib
  ```

  Expected: the new retirement test fails because cancellation currently has no timestamp and `maintain` requires a delivery timestamp.

- [x] **Step 3: Persist cancellation time and retire cancelled rows**

  Thread `now_millis` through `InboxState::cancel`, journal the supplied cancellation time, restore it on replay, and add `cancelled_at_millis <= cutoff` to both file and PostgreSQL maintenance predicates. Keep acknowledged and exhausted-row behavior unchanged.

- [x] **Step 4: Make diagnostic counts fallible**

  Add `try_pending_count` and `try_undelivered_count` defaults to `CommandInbox`, route `ControlInboxBackend` through them, implement real `Result`-returning PostgreSQL queries, exclude cancelled rows from the undelivered query, and let the status worker mark storage unhealthy when either query fails.

- [x] **Step 5: Run the focused inbox and worker suites**

  ```bash
  cargo test --locked --features test-support inbox --lib
  cargo test --locked --features test-support startup::tests --lib
  ```

- [x] **Step 6: Commit the command-inbox slice**

  ```bash
  git add apps/control-plane-api/src/inbox apps/control-plane-api/src/inbox.rs apps/control-plane-api/src/inbox_postgres.rs apps/control-plane-api/src/startup/service/workers.rs deploy/postgres/control_inbox.sql
  git commit -m "fix: retire cancelled commands and expose inbox read failures"
  ```

### Task 4: Enforce exact acknowledgement and provider-boundary integrity

**Files:**
- Modify: `apps/event-ingest/src/http_sinks/publishers.rs`
- Modify: `apps/event-ingest/src/http_sinks/tests.rs`
- Modify: `apps/reference-providers/apex_reference_providers/clickhouse_projection.py`
- Modify: `apps/reference-providers/apex_reference_providers/archive_provider.py`
- Add: `apps/reference-providers/apex_reference_providers/event_validation.py`
- Modify: `apps/reference-providers/apex_reference_providers/backends/base.py`
- Modify: `apps/reference-providers/apex_reference_providers/backends/s3.py`
- Modify: `apps/reference-providers/apex_reference_providers/backends/gcs.py`
- Modify: `apps/reference-providers/apex_reference_providers/backends/azure_blob.py`
- Add: `apps/reference-providers/requirements.txt`
- Add: `apps/reference-providers/tests/test_provider_boundaries.py`
- Modify: `apps/reference-providers/Dockerfile` and `README.md`
- Modify: `contracts/clickhouse/v1.md` only when clarifying an implemented wire invariant
- Test: `apps/event-ingest/src/http_sinks/tests.rs` and provider-local Python tests if present

**Interfaces:**
- Rust ClickHouse publishing accepts only contract-approved success statuses and required acknowledgement headers.
- ClickHouse reference projection validates the protobuf envelope, scope/event identity, recomputed event hash, and scoped idempotency key before insertion.
- Archive replay verification runs on same-hash replays before returning success; provider capabilities are truthful about actual readback/retention support.
- Terminal archive-verification failures use a status/classification that the Rust client does not retry indefinitely.

- [x] **Step 1: Change the Rust HTTP test first**

  Replace the existing test that treats HTTP 200 from ClickHouse as success with a test asserting 200 is rejected and 201/204 with the required acknowledgement is accepted.

- [x] **Step 2: Run the focused HTTP tests and confirm the baseline failure**

  ```bash
  cargo test --locked --features test-support http_sinks::tests::publishers_use_local_http_server_for_success_and_failure_paths --lib
  ```

- [x] **Step 3: Enforce the exact Rust status/ack contract**

  Separate ClickHouse status handling from generic `2xx` handling; require the matching hash acknowledgement where the contract requires it; preserve bounded error mapping and terminal/retryable semantics.

- [x] **Step 4: Add provider-boundary tests before changing Python providers**

  Test malformed protobuf, mismatched header identity, wrong recomputed hash, and same `event_id` in two scopes. Test an archive same-hash replay whose retention/readback verification fails and assert it is not acknowledged as a successful replay.

- [x] **Step 5: Implement validation and truthful capability/readback behavior**

  Decode and validate the event envelope at the ClickHouse boundary, scope the idempotency key, and make archive `put` re-verify content/retention on replay. Downgrade or reject capabilities that the backend cannot prove rather than advertising unsupported guarantees.

- [x] **Step 6: Run Rust tests plus Python syntax/unit checks**

  ```bash
  cargo test --locked --features test-support http_sinks --lib
  python -m compileall -q apps/reference-providers/apex_reference_providers
  ```

- [x] **Step 7: Commit the contract slice**

  ```bash
  git add apps/event-ingest/src/http_sinks apps/reference-providers/apex_reference_providers contracts/clickhouse/v1.md
  git commit -m "fix: enforce data-plane provider acknowledgement contracts"
  ```

### Task 5: Full verification and handoff

**Files:**
- Modify: plan checklist only as tasks complete

- [ ] **Step 1: Run both complete Rust test commands**

  ```bash
  cargo test --locked --features test-support
  ```

  Run from each of `apps/event-ingest` and `apps/control-plane-api` and record exit codes and test counts.

- [ ] **Step 2: Run formatting and lint verification**

  ```bash
  cargo fmt --all -- --check
  cargo clippy --locked --features test-support --all-targets -- -D warnings
  ```

- [ ] **Step 3: Inspect the final isolated diff**

  ```bash
  git status --short
  git diff --check HEAD~4..HEAD
  git log --oneline --decorate -5
  ```

  Confirm no files in the original dirty `master` checkout were changed, no secrets or generated artifacts were added, and every audit finding either has a fix plus test or is explicitly reported as externally blocked.

- [ ] **Step 4: Report verified results and remaining external gates**

  Report the branch, commits, test/lint evidence, the original-checkout preservation result, and any cloud acceptance tests not run because their services/credentials were unavailable.
