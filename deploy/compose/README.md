# Phase 0 local durable services

For a zero-setup home demonstration, use the [reference-agent quickstart](../../README.md#home-test-in-five-minutes) first. This Compose profile is the hardened durable-dependency path and intentionally requires explicit images, certificates, and local secret files.

This profile starts the Phase 0 ingest gateway and its durable dependencies: NATS JetStream, ClickHouse, and an S3-compatible **archive staging store**. It deliberately exposes no broker, database, object-storage API, console, or NATS monitoring ports to the host; only the gateway port is optionally bound (localhost by default). MinIO's browser interface is disabled. JetStream requires mutually authenticated TLS for every client connection.

There are no public Apex provider images in this repository yet. The
`CLICKHOUSE_API_IMAGE` and `ARCHIVE_API_IMAGE` values are deployment-owned
images that implement the frozen provider contracts. “Approved, digest-pinned”
means an operator builds or obtains an image, scans/tests/signs it, and records
the immutable `@sha256:...` digest in `.env`; do not replace the placeholders
with a floating tag. If you only want to try the SDK locally, use the JSONL
quickstart and skip this Compose profile entirely.

Before starting it, copy `deploy/compose/.env.example` to `deploy/compose/.env`, replace every image placeholder with an approved immutable digest, and generate the referenced secret files. Do not commit `.env` or the `secrets/` directory. Start from `deploy/compose/templates/nats.conf.template`, `deploy/compose/templates/clickhouse-users.xml.template`, and `deploy/compose/templates/clickhouse-tls.xml.template`; the user template removes ClickHouse's default user and does not grant access-management privileges. The TLS template disables ClickHouse plaintext ports and requires a client certificate issued by the configured CA. The NATS template is an ingest-publisher credential restricted to `apex.events.>`; provision separate least-privilege credentials for consumers and control services. Supply a JetStream server certificate, private key, and client-CA certificate. Supply MinIO's server certificate and private key; the profile starts MinIO only with TLS enabled. The NATS and ClickHouse containers refuse to start while `REPLACE_WITH` placeholders remain. MinIO reads root credentials from files.

Run the non-secret preflight before starting Docker services:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/preflight.ps1
```

Linux and macOS use the equivalent Bash preflight:

```bash
./deploy/compose/preflight.sh
```

On macOS, `./deploy/compose/preflight-macos.sh` is also available and refuses
to run on a non-Darwin host. Make the scripts executable after checkout with
`chmod 700 deploy/compose/preflight.sh deploy/compose/preflight-macos.sh`.

It verifies digest pinning, every certificate/key/credential path, explicit
Object-Lock mode, bucket naming, the Docker daemon, and rendered Compose
configuration without printing secret values. It also rejects a non-loopback
`APEX_INGEST_BIND` unless `APEX_ALLOW_NONLOCAL_INGEST_BIND=true` is explicitly
set; binding `0.0.0.0` requires an approved firewall and mTLS network policy.

```powershell
docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml up -d
```

The `ingest-gateway` service now runs the authenticated gRPC boundary and the
JetStream → ClickHouse → archive durable fanout. Build and publish it from
`apps/event-ingest/Dockerfile` using approved immutable build/runtime image
digests, then set `APEX_INGEST_IMAGE` to that digest. The gateway fails closed
when endpoint, certificate, bearer-token, scope, or NATS credential settings are
missing. It binds to localhost by default; expose it to an agent network only
after issuing client certificates and applying an explicit network policy.

The current gateway idempotency index is bounded in memory. Compose requires
the explicit `APEX_ALLOW_IN_MEMORY_IDEMPOTENCY=true` staging acknowledgment and
the gateway refuses to start without it. Do not use this mode for production or
regulated retention: a restart can lose the in-memory index. Replace it with a
durable idempotency store before onboarding production agents.

Compose now includes internal-only `clickhouse-projection` and
`archive-provider` service slots. Set `CLICKHOUSE_API_IMAGE` and
`ARCHIVE_API_IMAGE` to approved digest-pinned images implementing the frozen
contracts in [`contracts/clickhouse/v1.md`](../../contracts/clickhouse/v1.md)
and [`contracts/archive-provider/v1.md`](../../contracts/archive-provider/v1.md).
The slots terminate mTLS for the gateway and use separate writer credentials
to reach native ClickHouse and the archive backend. Native ClickHouse and
MinIO do not implement `/v1/events`; never point the gateway at those native
URLs. Provider images must fail closed when certificates, client CAs, backend,
size limits, or strict Object-Lock settings are invalid.

`APEX_ARCHIVE_REQUIRE_OBJECT_LOCK` is intentionally mandatory in the deployment
environment. `false` is an explicit staging acknowledgement; `true` requires
the provider image to verify immutable retention, legal holds, version IDs,
read-after-write, and content verification before accepting writes. Provider
images must also fail closed when backend credentials are missing or when their
backend readiness check cannot be established; Compose startup ordering is not
a readiness guarantee.

The archive-provider receives separate file-mounted backend access and secret
keys. These must belong to a least-privilege MinIO user restricted to the
configured bucket; never reuse the MinIO root credentials used by the
one-shot bucket bootstrap.

The defaults are `https://clickhouse-projection:8443/v1/events` and
`https://archive-provider:8443/v1/events`. Override them only with an HTTPS
endpoint preserving the same authentication, bounded-body, idempotency,
conflict, hash-echo, and redacted-error semantics.

The archive store is not an Object-Lock/WORM archive yet. A future archive forwarder must create an Object-Lock-enabled bucket, apply retention/legal-hold policy, and verify those capabilities before any strict retention profile is enabled.

The `archive-store-init` one-shot service now performs that staging bootstrap:
it connects to MinIO over TLS using the mounted CA, creates
`APEX_ARCHIVE_BUCKET` with `--with-lock`, and runs `mc retention info` before
the archive-provider is allowed to start. Its credential-format check rejects
ambiguous shell/JSON characters rather than exposing credentials in command-line
arguments. This proves bucket lock capability only; strict production retention
still requires the archive-provider acceptance suite and an independently
verified Object-Lock policy.

The ClickHouse projection definition is [../clickhouse/schema.sql](../clickhouse/schema.sql). Apply it only through an authenticated local ClickHouse client after the service is healthy; the Compose profile intentionally publishes no ClickHouse port to the host. The archive-provider API and its staging HTTP mapping are defined in [../../contracts/archive-provider/v1.md](../../contracts/archive-provider/v1.md).
