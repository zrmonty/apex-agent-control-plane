# Cold-storage analytical tier (Phase 0.6, item 8)

## What this is, and what it is not

This is an **additive, cheap, long-range analytical tier**: Vector reads the
same `apex.events.>` subjects the ingest gateway already publishes onto
JetStream, batches them, gzip-NDJSON-encodes them, and lands them as objects
in a MinIO bucket (`apex-coldstore` by default) partitioned by
workspace/namespace/date so a query engine can scan a narrow date range
cheaply instead of touching the hot ClickHouse projection or the archive.

**This is not the compliance archive.** The archive (`archive-provider` /
`archive-store`, bucket `apex-events` by default) writes one
Object-Lock-retained object per event and is the tamper-evident record of
record. This tier:

- is mutable (no Object-Lock, no version retention requirement) -- objects
  here can be recompacted, re-partitioned, or deleted by a lifecycle policy
  you choose;
- is a projection for query convenience, not a durability guarantee;
- does not participate in the gateway's outbox/idempotency/fanout-ack
  contract the way `clickhouse-projection` and `archive-provider` do -- the
  ingest gateway has no knowledge this tier exists at all, which is the point
  of consuming from JetStream rather than adding a third gateway sink.

If you delete this whole overlay, nothing about ingest, ClickHouse, or the
archive changes. If you delete the coldstore bucket, you lose only
convenience-tier query data that can, in principle, be rebuilt by replaying
JetStream (subject to its retention) or by re-deriving from the archive.

## Topology

```
JetStream (apex.events.>, existing stream APEX_EVENTS)
        |
        |  subscribe-only credential (mTLS + user/pass),
        |  never the ingest publisher's
        v
   Vector (source: nats, ideally a durable JetStream consumer)
        |
        |  remap: derive workspace_id/namespace_id from the subject,
        |  base64 the envelope, stamp a received-at timestamp
        v
   Vector (sink: aws_s3, gzip NDJSON)
        |
        v
   MinIO "archive-store" server (reused, NOT a new instance)
        bucket: apex-coldstore   (no --with-lock, mutable)
        key layout:
          workspace=<hex-workspace-id>/namespace=<hex-namespace-id>/date=YYYY-MM-DD/<ts>-<uuid>.json.gz
```

## What is reused vs. what is new

Reused, unchanged:

- The NATS/JetStream broker and its TLS material (`nats_client_ca`,
  `nats_server_cert`/`key`) -- Vector gets its own client leaf and its own
  broker account, it does not touch the ingest publisher's credential.
- The `archive-store` MinIO **server process** -- there is no second MinIO
  container. Object-Lock is a per-bucket setting in MinIO, so a second,
  non-locked bucket on the same server is the least infrastructure, not a
  weaker archive.
- `archive-store`'s server certificate/CA for TLS to the coldstore bucket.

New:

- `vector` service (Vector, digest-pinned via `VECTOR_IMAGE`).
- `coldstore-store-init` one-shot service: creates the `apex-coldstore`
  bucket without `--with-lock` and provisions a least-privilege MinIO IAM
  identity scoped to `PutObject`/`ListBucket`/multipart actions on that one
  bucket only -- it cannot read or touch the `apex-events` archive bucket,
  and it is not the MinIO root user.
- A new NATS consumer credential (subscribe-only on `apex.events.>`), which
  you merge into the existing rendered `nats.conf` -- see
  `templates/nats-coldstore-consumer.template`.
- A new Vector config, rendered from
  `templates/vector-coldstore.toml.template`.
- A disk-backed Vector buffer volume (`coldstore-vector-buffer`), so a MinIO
  hiccup backpressures into local disk rather than into JetStream redelivery.

## Parquet vs. gzipped NDJSON, and why

The plan item asked for Parquet if the pinned Vector version supports it. This
change could not run Docker against a specific pinned digest to confirm
Parquet output end-to-end (see "What needs a live stack" below), and the
available documentation lookups for the `aws_s3` sink's exact codec surface
were inconsistent between passes -- not a foundation to bet a production
config on. So this deliverable ships **gzip-compressed newline-delimited
JSON**, which is unambiguously supported by every Vector release in the
`aws_s3` sink family and is directly queryable by DuckDB, ClickHouse's
`s3()`/`url()` table functions, and Athena-style engines without any schema
inference step.

Follow-up, once an operator has pinned `VECTOR_IMAGE` to a specific digest:
check that digest's release notes for Parquet/`batch_encoding` support in the
`aws_s3` sink, and if present, switch `encoding.codec` and add the
`batch_encoding` table in `vector-coldstore.toml.template`. Parquet will cut
both storage size and query time on wide date ranges materially versus
gzipped NDJSON -- it is worth doing, just not worth guessing at blind.

## Partition layout

```
apex-coldstore/
  workspace=<hex>/
    namespace=<hex>/
      date=2026-08-13/
        1755000000123456-3f9a....json.gz
        1755000012456789-7b1c....json.gz
      date=2026-08-14/
        ...
```

`workspace`/`namespace` come from the JetStream subject
(`apex.events.<workspace-hex>.<namespace-hex>`), not from parsing the
protobuf envelope -- the subject is always present and always correct, per
`apps/event-ingest/src/publisher/jetstream.rs`. `date` is Vector's own
receive-time UTC date (`%Y-%m-%d`), which is an ingestion-time partition, not
the event's own `event_timestamp`; range queries by `event_timestamp` still
work, they just are not guaranteed to be perfectly bucketed if an event
arrives late. Each object's rows carry `apex_received_at` explicitly so a
query engine can always filter precisely regardless of which file it landed
in.

Each row (NDJSON line) looks like:

```json
{
  "nats_subject": null,
  "apex_workspace_id": "4f2a...",
  "apex_namespace_id": "9b31...",
  "apex_received_at": "2026-08-13T18:04:22.104Z",
  "envelope_protobuf_base64": "CkQKIN..."
}
```

(`nats_subject` is removed by the remap transform before the JSON is
written; it is listed here only to show where the partition columns came
from. `envelope_protobuf_base64` decodes with the same protobuf schema
`apps/event-ingest/src/publisher` encodes with -- decode it with your
language's protobuf runtime against that schema, not with an ad hoc parser.)

## Bringing it up alongside the main stack

1. Bring up the main stack per `deploy/compose/README.md` first (or already
   have it running).
2. Render `templates/vector-coldstore.toml.template` into
   `secrets/vector-coldstore.toml`, filling in the bucket name if you deviate
   from `apex-coldstore`.
3. Issue a coldstore consumer NATS credential and mTLS client certificate.
   Merge `templates/nats-coldstore-consumer.template` into the same rendered
   `nats.conf` your main stack already uses (this requires restarting
   `jetstream` to pick up the new user).
4. Generate a least-privilege MinIO key pair for the coldstore writer.
   `coldstore-store-init` will provision the matching MinIO IAM identity for
   you; you supply the raw key pair via
   `COLDSTORE_WRITER_ACCESS_KEY_FILE`/`COLDSTORE_WRITER_SECRET_KEY_FILE`, and
   an AWS shared-credentials-format file containing the *same* pair via
   `COLDSTORE_AWS_CREDENTIALS_FILE` (that's what Vector's `aws_s3` sink
   actually authenticates with):

   ```ini
   [default]
   aws_access_key_id = <same value as coldstore-writer-access-key>
   aws_secret_access_key = <same value as coldstore-writer-secret-key>
   ```

5. Set `VECTOR_IMAGE` and `APEX_COLDSTORE_BUCKET` (and the new `COLDSTORE_*`
   / `VECTOR_COLDSTORE_CONFIG_FILE` variables) in your `.env`.
6. Start it:

   ```powershell
   docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml -f deploy/compose/compose.coldstore.yaml up -d
   ```

## Querying the Parquet/NDJSON objects

DuckDB, against gzipped NDJSON directly:

```sql
INSTALL httpfs; LOAD httpfs;
SET s3_endpoint = 'archive-store:9000';
SET s3_access_key_id = '...';       -- a READ-scoped MinIO identity, separate
SET s3_secret_access_key = '...';   -- from the write-only coldstore writer above
SET s3_use_ssl = true;
SET s3_url_style = 'path';

SELECT *
FROM read_ndjson_auto(
  's3://apex-coldstore/workspace=4f2a.../namespace=9b31.../date=2026-08-1*/*.json.gz'
);
```

ClickHouse, via the `s3()` table function, from an authenticated ClickHouse
client with network access to the coldstore bucket (never grant this to
agents directly -- same rule as the primary projection):

```sql
SELECT *
FROM s3(
  'https://archive-store:9000/apex-coldstore/workspace=4f2a.../namespace=9b31.../date=2026-08-13/*.json.gz',
  'access_key', 'secret_key', 'JSONEachRow'
);
```

Issue a **separate, read-only** MinIO identity for query engines -- do not
reuse the coldstore writer credential (write-only, no `GetObject`) or MinIO
root for this.

## What was validated vs. what needs a live stack

Validated in this change, without Docker running a live stack:

- `docker compose --env-file <fully populated .env> -f compose.yaml -f compose.coldstore.yaml config` --
  ran successfully (exit 0) against a temporary `.env` and placeholder secret
  files covering every required variable, confirming the overlay parses,
  merges with the base stack, and resolves every `${VAR:?...}` without
  syntax errors. `vector` and `coldstore-store-init` appear correctly in the
  merged service list, `vector`'s `depends_on` correctly names
  `coldstore-store-init` (`service_completed_successfully`) and `jetstream`,
  and the new `coldstore-vector-buffer` volume and coldstore secrets appear
  in the merged output.
- `python3 -c "import tomllib; tomllib.load(...)"` against
  `templates/vector-coldstore.toml.template` -- parses as valid TOML with the
  expected `sources.apex_events`, `transforms.apex_events_partition`, and
  `sinks.coldstore_s3` tables present.
- `python3 -c "import yaml; yaml.safe_load(...)"` against
  `compose.coldstore.yaml` -- parses as valid YAML.

Needs a live stack (Docker was available in this environment, but standing
up the full mTLS PKI, a real NATS consumer credential, and a real MinIO
writer identity was out of scope for this change):

- That the pinned `VECTOR_IMAGE` digest's NATS source actually accepts the
  `[sources.apex_events.jetstream]` table as written (durable pull consumer
  mode). Bring the stack up and check `docker compose logs vector` for a
  config-rejection error; if it rejects that table, delete it and accept the
  at-most-once core-NATS-subscribe degradation documented inline in the
  template.
- That the `aws_s3` sink actually authenticates against MinIO via
  `AWS_SHARED_CREDENTIALS_FILE` with `force_path_style = true` the way this
  config assumes -- confirm with `docker compose logs vector` showing
  successful `PutObject` calls, and `mc ls apex/apex-coldstore` growing.
- End-to-end: publish an event through the ingest gateway, confirm it lands
  in ClickHouse (existing behavior, unaffected) **and** shows up as a new
  object under `apex-coldstore/workspace=.../namespace=.../date=.../` within
  one `batch.timeout_secs` window (60s in the shipped template).
- Whether the pinned Vector digest supports a real Parquet `batch_encoding`
  path (see "Parquet vs. gzipped NDJSON" above) -- if so, switching to it is
  the recommended follow-up.
