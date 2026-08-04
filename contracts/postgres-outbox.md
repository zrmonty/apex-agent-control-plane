# Durable event outbox contract

`DurableFanoutPublisher` preserves ordering. It cannot make three independent providers transactional. The outbox closes that gap. A canonical event is durably recorded before JetStream, ClickHouse, or archive dispatch begins.

If any sink fails—or the gateway process exits—the outbox row remains pending. A worker retries the complete idempotent fanout. The row becomes complete only after all sinks acknowledge. Each provider must continue to use the event ID and payload hash for idempotency and conflict detection.

The reference PostgreSQL table is in `deploy/postgres/outbox.sql`. The Rust adapter is `PostgresOutbox` (Cargo feature `postgres`). Set `APEX_POSTGRES_URL` to enable it at gateway startup. The local `InMemoryOutbox` remains test and staging only. Do not use it as a production durability guarantee.


---

Writing style: [ASD-STE100 Simplified Technical English](../../docs/writing-style-ste100.md).
