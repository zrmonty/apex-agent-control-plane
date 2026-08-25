# Apex reference providers (Phase 0)

These are reference implementations of the frozen ClickHouse projection and archive-provider HTTP APIs.

Use them for local Compose, live mTLS harnesses, and CI. They are not a claim of production multi-tenant scale.

| Service | Contract | Default mode |
|---|---|---|
| `clickhouse_projection` | [`contracts/clickhouse/v1.md`](../../contracts/clickhouse/v1.md) | Durable on-disk store under `/var/lib/apex/ch` |
| `archive_provider` | [`contracts/archive-provider/v1.md`](../../contracts/archive-provider/v1.md) | Pluggable backend: `local`, `s3`, `azure`, or `gcs` |

Both services need **mTLS** (server cert, server key, and client CA). Client certificates must chain to the configured CA.

## Cloud-agnostic archive backends

```text
APEX_ARCHIVE_BACKEND=local|s3|azure|gcs
```

| Backend | Required environment |
|---|---|
| `local` | `--data-dir` only |
| `s3` | `APEX_ARCHIVE_S3_ENDPOINT`, `APEX_ARCHIVE_S3_ACCESS_KEY`, `APEX_ARCHIVE_S3_SECRET_KEY`, `APEX_ARCHIVE_S3_BUCKET` |
| `azure` | `APEX_ARCHIVE_AZURE_CONNECTION_STRING` **or** account URL + key; `APEX_ARCHIVE_AZURE_CONTAINER` |
| `gcs` | `APEX_ARCHIVE_GCS_BUCKET`; ADC or `APEX_ARCHIVE_GCS_CREDENTIALS_FILE` |

Install the provider runtime and optional cloud SDKs only in the adapter image:

```powershell
pip install -r apps/reference-providers/requirements.txt
pip install -r apps/reference-providers/requirements-cloud.txt
```

See [Multi-Cloud Archive Adapters](../../docs/architecture/Multi-Cloud%20Archive%20Adapters.md).

## Run locally

```powershell
python -m apps.reference_providers.clickhouse_projection `
  --cert cert.pem --key key.pem --client-ca ca.pem --data-dir .local/ch

python -m apps.reference_providers.archive_provider `
  --cert cert.pem --key key.pem --client-ca ca.pem --data-dir .local/archive
```

## Docker

```powershell
docker build -f apps/reference-providers/Dockerfile `
  -t apex-reference-providers:local apps/reference-providers
```

Run the provider boundary tests with the runtime requirements installed:

```powershell
$env:PYTHONPATH = "apps/reference-providers"
python -m unittest discover -s apps/reference-providers/tests -p "test_*.py"
```

Set `APEX_SERVICE=clickhouse_projection` or `archive_provider`.

Writing style: [ASD-STE100](../../docs/writing-style-ste100.md).
