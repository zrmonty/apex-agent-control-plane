# Durable event outbox contract

`DurableFanoutPublisher` preserves ordering but cannot make three independent
providers transactional. The outbox closes that gap: a canonical event is
durably recorded before JetStream, ClickHouse, or archive dispatch begins.

If any sink fails—or the gateway process exits—the outbox row remains pending
and a worker retries the complete idempotent fanout. The row becomes complete
only after all sinks acknowledge. Each provider must continue to use the event
ID and payload hash for idempotency and conflict detection.

The reference PostgreSQL table is in `deploy/postgres/outbox.sql`. The local
`InMemoryOutbox` is test/staging-only and must not be used as a production
durability guarantee.
