# Environment gates (deploy-time proof)

**Status:** Runnable on this host with the gate suite.  
**Style:** [ASD-STE100](writing-style-ste100.md).

Phase 0 foundations are complete in code. These gates prove the stack on a **real machine** with Docker.

## What this suite proves

| Gate | Meaning |
|------|---------|
| Docker daemon | Container runtime is available. |
| Live-mTLS PKI | Local CA and service certificates generate. |
| Compose e2e stack | Postgres, MinIO, NATS, reference providers start. |
| Live-mTLS stack | Valkey, NATS, reference HTTPS providers start. |
| Rust live_mtls tests | Real mTLS clients reach Valkey, NATS, ClickHouse, archive. |
| Postgres durability | Outbox and idempotency adapters work against Postgres. |
| MinIO Object-Lock | Retention, read-after-write, and version identity succeed. |
| Azure / GCS acceptance | Runs when credentials exist. Skips cleanly when optional. |
| Compose overlays | gateway-ref, Azure, and GCS Compose files validate. |

## Run the suite

### Any OS (recommended)

```bash
python3 deploy/compose/e2e/run_gates.py
```

### Windows (PowerShell wrapper)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\compose\e2e\run.ps1
```

### Report output

- JSON: `.local/apex-lab/gate-report.json`
- Markdown: `.local/apex-lab/gate-report.md`

Set `APEX_GATE_REPORT` to change the report path.

## Latest run on this workspace

Run `python deploy/compose/e2e/run_gates.py` again after major changes. The last report on disk is under `.local/apex-lab/`.

Expected overall when Docker and cargo are present: **PASS**.

## Residual operator duties (not automated here)

These remain **your** environment or production duties:

1. **Azure Blob** — set `APEX_ARCHIVE_AZURE_CONNECTION_STRING` (or URL + key) and re-run `object_lock_acceptance_azure.py` without optional skip.
2. **GCS** — set `APEX_ARCHIVE_GCS_BUCKET` and credentials; re-run `object_lock_acceptance_gcs.py`.
3. **Production digests** — fill `deploy/compose/.env` with approved `@sha256:` image digests. Do not use floating tags.
4. **Production preflight** — after secrets and digests exist, run `preflight.ps1` or `preflight.sh`.
5. **Regulated Object-Lock** — confirm legal hold and retention policy match your compliance profile on the real bucket.

The gate suite proves the **reference path** and **local Object-Lock**. It does not replace production image approval.

## Related paths

| Path | Role |
|------|------|
| `deploy/compose/e2e/run_gates.py` | Cross-platform gate runner |
| `deploy/compose/e2e/run.ps1` | Windows-oriented e2e script |
| `deploy/compose/object_lock_acceptance*.py` | Archive immutability checks |
| `deploy/compose/live-mtls/` | mTLS harness |
| [Getting started](getting-started.md) | Day-one tracks |
