# Phase 0 local durable services

For a zero-setup home demonstration, use the [reference-agent quickstart](../../docs/getting-started.md#a--local-first-trace) first.

This Compose profile is the hardened durable-dependency path. It needs explicit images, certificates, and local secret files.

Day-one guide: [Getting started](../../docs/getting-started.md).  
Lab install: [deploy/lab/README.md](../lab/README.md).

## Optional overlays (Valkey, Azure, GCS, gateway-ref)

Overlays use the same rules as production Compose. Secrets are files. The gateway process does not hold cloud credentials.

### Valkey acceleration

Valkey is **not** required for a functional install.

When you want cross-process rate limits and abuse fingerprint counters:

1. Build the gateway with `cargo build --features valkey` (or bake the feature into `APEX_INGEST_IMAGE`).
2. Render `templates/valkey.conf.template` and `templates/valkey.acl.template` into `secrets/`.
3. Create Valkey server and client mTLS material and the ingest ACL password file.
4. Set `VALKEY_IMAGE` to an approved digest-pinned Valkey image.
5. Start with both Compose files:

```powershell
docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml -f deploy/compose/compose.valkey.yaml up -d
```

Valkey is internal only (no host port). It uses TLS with client certificates. It must never hold authoritative auth, audit, cost, or durable event data. If Valkey is unavailable, the gateway falls back to process-local limits and continues durable fanout.

### Azure Blob archive

Use `compose.azure.yaml`. Set `APEX_ARCHIVE_BACKEND=azure`. Set `AZURE_CONNECTION_STRING_FILE` (preferred) and/or `AZURE_ACCOUNT_KEY_FILE` with `APEX_ARCHIVE_AZURE_ACCOUNT_URL`. See `.env.example`.

```powershell
docker compose --env-file .env -f compose.yaml -f compose.azure.yaml up -d
```

### GCS archive

Use `compose.gcs.yaml`. Set `APEX_ARCHIVE_GCS_BUCKET` and `GCS_CREDENTIALS_FILE`.

```powershell
docker compose --env-file .env -f compose.yaml -f compose.gcs.yaml up -d
```

### Gateway and reference providers

Use `compose.gateway-ref.yaml`. This local/CI stack builds ingest-gateway. It runs reference ClickHouse projection and local archive against live-mTLS PKI. Proprietary provider images are not required.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/gateway-ref/run.ps1
```

### Live mTLS and E2E

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/e2e/run.ps1
```

### Ingest load baseline

`loadtest/run_load_baseline.py` measures real throughput and per-stage latency against the built gateway image. It starts `compose.gateway-ref.yaml` under its own Compose project (`apex-gateway-loadtest`, host port 18455), drives real gRPC over mTLS at the container, and tears the stack down again.

```bash
python deploy/compose/loadtest/run_load_baseline.py
```

Add `--quick` for a smoke run, `--skip-build` to reuse the current image, `--keep-up` to leave the stack running. The `loadtest-stage-probe` service (Compose profile `loadtest`, so a normal `up` never starts it) times each downstream dependency from a peer container. Results and method: [docs/phase-0.6-load-baseline.md](../../docs/phase-0.6-load-baseline.md).

## What this profile starts

This profile starts the Phase 0 ingest gateway and durable dependencies: NATS JetStream, ClickHouse, and an S3-compatible archive staging store.

It does not expose broker, database, object-storage API, console, or NATS monitoring ports to the host. Only the gateway port is optionally bound (localhost by default). MinIO browser is disabled. JetStream requires mutual TLS for every client connection.

## Provider images

This repository does not ship public Apex provider images yet.

Set `CLICKHOUSE_API_IMAGE` and `ARCHIVE_API_IMAGE` to deployment-owned images that implement the frozen provider contracts.

**Approved, digest-pinned** means:

1. An operator builds or obtains an image.
2. The operator scans, tests, and signs it.
3. The operator records the immutable `@sha256:...` digest in `.env`.

Do not replace placeholders with a floating tag.

If you only want the SDK locally, use the JSONL quickstart. Skip this Compose profile.

## Before you start

1. Copy `deploy/compose/.env.example` to `deploy/compose/.env`.
2. Replace every image placeholder with an approved immutable digest.
3. Generate the referenced secret files.
4. Do not commit `.env` or the `secrets/` directory.
5. Start from the templates under `deploy/compose/templates/`.

Notes on templates:

- ClickHouse user template removes the default user. It does not grant access-management privileges.
- ClickHouse TLS template disables plaintext ports. It requires a client certificate from the configured CA.
- NATS template is an ingest-publisher credential restricted to `apex.events.>`. Create separate least-privilege credentials for consumers and control services.
- Supply JetStream server certificate, private key, and client-CA certificate.
- Supply MinIO server certificate and private key. The profile starts MinIO only with TLS enabled.
- NATS and ClickHouse containers refuse to start while `REPLACE_WITH` placeholders remain.
- MinIO reads root credentials from files.

## Preflight

Run non-secret preflight before Docker services:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/preflight.ps1
```

Linux and macOS:

```bash
./deploy/compose/preflight.sh
```

On macOS, `./deploy/compose/preflight-macos.sh` is also available. It refuses a non-Darwin host.

Make scripts executable after checkout:

```bash
chmod 700 deploy/compose/preflight.sh deploy/compose/preflight-macos.sh
```

Preflight checks:

- Digest pinning
- Certificate, key, and credential paths
- Explicit Object-Lock mode
- Bucket naming
- Docker daemon
- Rendered Compose configuration

Preflight does not print secret values. It rejects a non-loopback `APEX_INGEST_BIND` unless `APEX_ALLOW_NONLOCAL_INGEST_BIND=true` is set. Binding `0.0.0.0` needs an approved firewall and mTLS network policy.

## Start services

```powershell
docker compose --env-file deploy/compose/.env -f deploy/compose/compose.yaml up -d
```

## Ingest gateway behavior

`ingest-gateway` runs the authenticated gRPC boundary and the JetStream → ClickHouse → archive durable fanout.

1. Build and publish from `apps/event-ingest/Dockerfile` with approved immutable digests.
2. Set `APEX_INGEST_IMAGE` to that digest.
3. The gateway fails closed when endpoint, certificate, bearer-token, scope, or NATS credential settings are missing.
4. It binds to localhost by default. Expose it to an agent network only after you issue client certificates and apply network policy.
5. File-bearer credential binds to `APEX_BEARER_AGENT_ID`. The gateway rejects missing bindings and non-matching agent or AGENT-actor identities.
6. Set `APEX_BEARER_CERT_SHA256` to the SHA-256 fingerprint of the one client certificate authorized for that bearer. For PEM material, compute it over DER bytes with `openssl x509 -in client.pem -outform DER | sha256sum` and use the first 64 hexadecimal characters.
7. The token file is revalidated on a short interval. Replace or revoke the mounted token without process restart.
8. This is a single-agent staging resolver. Multi-agent deployments should use SPIFFE/JWT workload identity, not one shared file token.

## Outbox and idempotency

The gateway needs a persistent append-only outbox at `/var/lib/apex`.

- It fsyncs the canonical event before fanout.
- It marks the row complete only after JetStream, ClickHouse, and archive acknowledge.
- It replays pending rows before it accepts traffic after restart.
- Idempotency uses a bounded fsync-backed journal at `/var/lib/apex/idempotency.jsonl` with per-scope quotas.
- Use PostgreSQL adapters for multi-process or regulated production workloads.

## Provider slots

Compose includes internal-only `clickhouse-projection` and `archive-provider` slots.

Set `CLICKHOUSE_API_IMAGE` and `ARCHIVE_API_IMAGE` to approved digest-pinned images for:

- [`contracts/clickhouse/v1.md`](../../contracts/clickhouse/v1.md)
- [`contracts/archive-provider/v1.md`](../../contracts/archive-provider/v1.md)

Slots terminate mTLS for the gateway. They use separate writer credentials to reach native ClickHouse and the archive backend.

Native ClickHouse and MinIO do not implement `/v1/events`. Never point the gateway at those native URLs.

Provider images must fail closed when certificates, client CAs, backend, size limits, or strict Object-Lock settings are invalid.

## Object-Lock setting

`APEX_ARCHIVE_REQUIRE_OBJECT_LOCK` is mandatory in the deployment environment.

- `false` is an explicit staging acknowledgement.
- `true` requires the provider image to verify immutable retention, legal holds, version IDs, read-after-write, and content verification before writes.

Provider images must fail closed when backend credentials are missing or when backend readiness fails. Compose start order is not a readiness guarantee.

Archive-provider receives separate file-mounted backend access and secret keys. These must belong to a least-privilege MinIO user for the configured bucket. Never reuse MinIO root credentials used by one-shot bucket bootstrap.

Defaults:

- `https://clickhouse-projection:8443/v1/events`
- `https://archive-provider:8443/v1/events`

Override only with an HTTPS endpoint that keeps the same authentication, body limits, idempotency, conflict, hash-echo, and redacted-error rules.

## Archive store init

`archive-store-init` connects to MinIO over TLS with the mounted CA. It creates `APEX_ARCHIVE_BUCKET` with `--with-lock`. It runs `mc retention info` before archive-provider starts.

This proves bucket lock capability only. Strict production retention still needs the archive-provider acceptance suite and an independently verified Object-Lock policy.

## Schema and contracts

ClickHouse projection definition: [../clickhouse/schema.sql](../clickhouse/schema.sql).

Apply schema only through an authenticated local ClickHouse client after the service is healthy. The Compose profile publishes no ClickHouse port to the host.

Archive-provider API: [../../contracts/archive-provider/v1.md](../../contracts/archive-provider/v1.md).

Writing style: [ASD-STE100](../../docs/writing-style-ste100.md).
