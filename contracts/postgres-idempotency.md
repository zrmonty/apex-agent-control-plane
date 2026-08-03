# Ingest idempotency store contract

The in-memory backend is staging-only. Production gateways must use an
authoritative transactional store implementing the `IdempotencyStore` seam in
`apps/event-ingest/src/idempotency.rs`.

## Required behavior

- The key is `(workspace_id, namespace_id, event_id)`.
- The payload hash is exactly 32 bytes and is never replaced after commit.
- A matching committed hash returns `Duplicate` without republishing.
- A different hash returns `Conflict` and must not publish.
- A new key creates a pending reservation atomically.
- A successful durable fanout commits the reservation.
- Any publish failure aborts/deletes the pending reservation so a retry can run.
- Pending reservations may be reaped only with an explicit lease timeout; committed records are immutable and are not evicted.

The reference PostgreSQL table and transaction requirements are in
`deploy/postgres/idempotency.sql`. The SQL adapter is intentionally not
pretended to exist until its connection pooling, transaction, timeout, and
startup credential validation are implemented and acceptance-tested.
