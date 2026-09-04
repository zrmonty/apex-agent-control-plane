# Event Ingest Fanout Throughput

Admission acknowledges after the event is durably recorded in the outbox.
Background fanout workers then deliver each record to JetStream, ClickHouse,
and the archive.

## Throughput controls

`APEX_FANOUT_WORKERS` controls the number of independent outbox claimers for
the Postgres backend. It is bounded to `1..=32`, defaults to `4`, and should be
tuned with the downstream connection and object-store limits. File and memory
backends remain capped to one worker.

Each production fanout worker uses `DurableFanoutPublisher::with_parallel_sinks`.
The three independent sink calls overlap for one event, but the outbox row is
only marked complete after all required sink calls succeed. A failure leaves
the row retryable; every sink must remain idempotent on `event_id` because a
peer sink may have completed before the failure was observed.

## Validation

Use the managed event load test with a Postgres DSN and capture:

- admission success/rejection rate and latency;
- pending depth and oldest pending age;
- JetStream, ClickHouse, and archive request latency/error counts;
- worker CPU, memory, and database connection utilization.

Increase worker count only when the backlog drains after the burst and the
downstream error rate remains within the deployment's SLO. Parallel sink
execution is not a substitute for capacity planning: it can expose a slow or
rate-limited downstream more quickly.
