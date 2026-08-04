# Live mTLS handshake stack (local only)

This stack tests **real** TLS handshakes against local services.

| Service | Port (loopback) | What the test proves |
|---|---|---|
| Valkey 8 | `127.0.0.1:16379` | mTLS and ACL user `apex-ingest`; rate-limit and fingerprint ops |
| NATS JetStream | `127.0.0.1:14222` | mTLS and user/password; stream create; publish ack |
| ClickHouse projection stub | `127.0.0.1:18443` | mTLS client auth; `POST /v1/events` |
| Archive provider stub | `127.0.0.1:18444` | mTLS client auth; create-only `PUT` and hash echo |

These are **local development fixtures**. Certificates last 30 days. Do not use them in production.

Generated material under `secrets/` is gitignored. Do not commit it. Scripts, Compose, stubs, and this README are safe to track.

## Prerequisites

- Docker Desktop or Docker Engine is running.
- Python 3.11 or higher can install `cryptography`.
- Rust toolchain is available for `apps/event-ingest` tests.

## One-shot run

From the repository root (PowerShell):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy/compose/live-mtls/run.ps1
```

## Step-by-step run

```powershell
cd deploy/compose/live-mtls
python -m pip install --user cryptography
python generate_pki.py
python render_configs.py
docker compose -f compose.yaml up -d
$env:APEX_LIVE_MTLS='1'
$env:APEX_LIVE_MTLS_SECRETS=(Resolve-Path .\secrets).Path
cd ../../../apps/event-ingest
cargo test --test live_mtls --features "test-support,valkey" -- --nocapture
```

## Tear down

```powershell
cd deploy/compose/live-mtls
docker compose -f compose.yaml down
```

## Notes

- ClickHouse and archive services here are **contract stubs**. They implement frozen `/v1/events` HTTP APIs so gateway clients can complete mTLS without proprietary provider images.
- Official `valkey/valkey` and `nats` images are used for broker and accelerator handshakes.
- Unit CI does not set `APEX_LIVE_MTLS`. Those tests skip when the flag is absent.

You can also create PKI with the [lab installer](../../lab/README.md).

Writing style: [ASD-STE100](../../../docs/writing-style-ste100.md).
