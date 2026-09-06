# Private managed-call reservation store

This PostgreSQL seam stores business-call admission and physical-capacity metadata. It does **not** authenticate a workload, evaluate Apex policy, validate a caller's tool/arguments, enable an RPC, publish a route, or enable serving. Main's bounded authenticated service and actual runtime owners supply those boundaries. PREPARE and a selected-but-unacknowledged SERVE are not call permission.

## Inputs and transaction boundary

`read_admittable_deployment_checked(binding, check)` returns registered deployment metadata without quota consumption. Under the exact existing proxy row lock it requires immutable binding equality, selected nonterminated SERVE, an actual retained current-epoch applied SERVE decision, `admitting=true`, unexpired DB validity and current publication eligibility. It retains the applied-decision deadline through transaction finish. The returned data is a point-in-time snapshot, not a transferable permit.

`reserve_managed_call_checked(input, check)` repeats that guard under the lock. Input contains the exact immutable binding, canonical UUIDv7 call identity, a 32-byte semantic SHA256 digest, policy ID and nonzero uint64 policy revision. Main must first authenticate the exact registered workload/proof and evaluate its actual Apex policy, resolve alias/upstream/tool/action/classification from immutable configuration, and validate caller/argument semantics. The hash must bind all those canonical call semantics; neither a supplied hash nor policy ID proves authorization. The store checks the policy ID against the stored immutable configuration and obtains all published limits from that configuration, never caller-supplied caps.

Output contains admission UUIDv7, call UUID, epoch, policy revision, informational DB Unix-microsecond expiry, and positive `valid_for_us <= 10,000,000`. A permit is bounded by both its original interval and the current applied SERVE decision. Policy revision is canonical decimal TEXT in PostgreSQL, preserving all positive uint64 values, including `18446744073709551615` without float conversion. Epoch remains the registry's positive signed-SQL-range integer.

Main must retain the original monotonic request/job start across every awaited preparation, queue, SQL and retry stage. Consumers expire relative to that original start plus `valid_for_us`, never response receipt or subtraction of remote wall clocks. They must recheck serving/admission immediately before starting actual upstream work. No synchronous SQL belongs on a Tokio executor thread: main's physically bounded worker owns this synchronous store call and cleanup. The same check callback runs at lock/SQL/commit checkpoints without creating a replacement elapsed budget.

## Accounting and retry semantics

All revisions and replicas of one logical proxy share a single counter row under the proxy lock. A newly permitted call reserves exactly one rate unit, one daily unit and one physical concurrency slot. No refunds occur after cancellation, denial later in execution, completion or termination.

- Rate: fixed UTC calendar-minute buckets computed as DB epoch microseconds divided by `60,000,000`; this is not a rolling sixty-second window.
- Budget: fixed UTC calendar-day buckets divided by `86,400,000,000`; one reservation is one budget unit, not a monetary estimate.
- Concurrency: unreleased reservations, regardless of grant or reservation expiry, revision, process replacement or operation completion.
- Period rollover resets only its corresponding usage count. A backward DB bucket relative to recorded accounting refuses instead of resetting counters.
- A hard physical ceiling of 1,024 unreleased calls per proxy can be narrower than the published concurrency limit. A lifetime ceiling of 1,000,000 reservation tombstones per proxy bounds retained identity history. Published limits can be smaller and remain authoritative. Exhaustion refuses; there is no automatic recycling, archival deletion, or identity reset path in this seam.

The global call UUID key is permanent. Exact same binding/call/semantic/policy retry, while still active and eligible in the original epoch, returns the original admission identity and expiry with conservative remaining validity and consumes no additional quota. Changed semantics conflict. Released or expired calls, or retries after an epoch change, never mint replacement authority. A new call requires a new canonical identity after main's actual evaluation, not a retry masquerading as new work.

Rows and queries are bounded by immutable identifiers and indexed outstanding-instance lookups; there is no full-history quota scan or pruning of uncertain physical work. Tombstones are never deleted. Lifetime exhaustion is an explicit availability limit requiring a separately reviewed retention/identity design, not permission to delete rows or reset a proxy's identity.

## Physical completion and termination

`complete_managed_call_checked(binding, admission_id, call_id, check)` is exact and idempotent. Main authenticates the registered credential/proof and asserts actual physical cleanup completion. It remains usable after CLOSED, withdrawal, expiry and revision replacement; it cannot admit new work or refund rate/day units. Wrong binding, admission or call refuses. Duplicate completion cannot release a different/new call's slot.

`release_terminated_admissions_checked(binding, check)` accepts no caller termination boolean. It releases outstanding reservations only when the existing registry already durably records termination of that exact immutable instance. Main must independently verify termination before establishing that registry fact. Loss of credentials, completion responses or network contact is uncertainty, not release evidence.

Before-commit cancellation rolls back owned reservation/counter/completion mutations together. An error after commit is an uncertain response, not undo: exact retry recovers the durable original reservation, and completion remains idempotent. Expiry alone never releases capacity.

## Schema and verification boundary

`deploy/postgres/mcp_proxy_admissions.sql` is applied after the serving registry under the existing proxy-schema advisory lock. Version 1 supports fresh/repeated initialization and refuses empty, newer, partial or unversioned metadata. Database triggers preserve immutable call identities, issued intervals, terminal released tombstones, monotonic lifetime counters and nondecreasing same-period usage. No global PostgreSQL settings or host clock changes are required.

The component tests use real disposable PostgreSQL schemas and trusted metadata fixtures, not real authenticated RPCs or physical upstream cleanup. Real mTLS policy/service, runtime enforcement, network isolation, root shutdown and serving acceptance remain separate main-owned gates. This store does not enable serving.
