# Multi-Cloud Archive Adapters

**Status:** Accepted — cloud-agnostic archive boundary  
**Date:** 2026-08-03

## Decision

Apex stays **cloud-agnostic** for immutable archive.

The ingest gateway must not import AWS, Azure, or GCP SDKs. All cloud storage uses the **archive-provider HTTP API** in [`contracts/archive-provider/v1.md`](../../contracts/archive-provider/v1.md).

```text
event-ingest (Rust)
    │  mTLS HTTPS PUT /v1/events/{id}.pb
    ▼
archive-provider adapter process
    │
    ├── backend=local   SQLite (dev/CI)
    ├── backend=s3      AWS S3 / MinIO (Object Lock)
    ├── backend=azure   Azure Blob (immutability / legal hold)
    └── backend=gcs     Google Cloud Storage (retention / temporary hold)
```

## Reference implementation

| Backend | Module | Credentials |
|---|---|---|
| `local` | `backends/local.py` | none |
| `s3` | `backends/s3.py` | `APEX_ARCHIVE_S3_*` |
| `azure` | `backends/azure_blob.py` | `APEX_ARCHIVE_AZURE_*` |
| `gcs` | `backends/gcs.py` | ADC or `APEX_ARCHIVE_GCS_CREDENTIALS_FILE` |

Select the backend with `APEX_ARCHIVE_BACKEND` or `--backend` on the reference provider.

Optional SDKs stay in the adapter image only:

```text
apps/reference-providers/requirements-cloud.txt
```

## Capability matrix (target)

| Capability | S3/MinIO | Azure Blob | GCS |
|---|---|---|---|
| Create-only write | `If-None-Match: *` | `overwrite=False` | `if_generation_match=0` |
| Content hash metadata | object metadata | blob metadata | blob metadata |
| Version identifier | `VersionId` | `version_id` / ETag | `generation` |
| Immutable retention | Object Lock | immutability policy | bucket retention |
| Legal or temporary hold | Object Lock legal hold | blob legal hold | temporary hold |
| Read-after-write verify | GET + SHA-256 | download + SHA-256 | download + SHA-256 |

Operators must pre-create containers or buckets with the correct immutability features for the deployment profile. The adapter fails closed when credentials or buckets are missing. It must not fall back to a weaker cloud in silence.

## Acceptance harnesses

| Cloud | Script |
|---|---|
| MinIO / S3-compatible | `deploy/compose/object_lock_acceptance.py` |
| Azure Blob | `deploy/compose/object_lock_acceptance_azure.py` |
| GCS | `deploy/compose/object_lock_acceptance_gcs.py` |

Set `APEX_CLOUD_ACCEPTANCE_OPTIONAL=1` to skip when credentials are absent (local CI).

## Compose overlays

Use the same overlay style as Valkey:

- `deploy/compose/compose.azure.yaml`
- `deploy/compose/compose.gcs.yaml`
- Env samples in `deploy/compose/.env.example`

## Rules

1. Keep cloud SDKs out of `apps/event-ingest`.
2. Keep credentials in secret files. Do not put secrets in process env on production hosts when a file mount is available.
3. Prove immutability with the acceptance suite for the target backend before you enable strict retention.

Writing style: [ASD-STE100](../writing-style-ste100.md).
