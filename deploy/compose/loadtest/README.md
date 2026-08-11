# event-ingest load-test harness (Phase 0.6, item 1)

A repeatable load-test harness for `apex-event-ingest`'s real mTLS gRPC
interface. It drives load through `apex_sdk.GrpcEventIngestTransport` — the
SDK's production ingest transport, the same one
`deploy/compose/gateway-ref/agent_submits_events.py` uses for its live proof —
at a configurable rate and concurrency, and reports throughput, per-stage
latency percentiles, and a PASS/FAIL verdict.

Two jobs:

1. **Baseline mode** (`--baseline`): ramps the rate until the gateway starts
   answering `RESOURCE_EXHAUSTED` (`RateLimited` / `AdmissionBusy`), to find
   the *current* synchronous-fanout gateway's real sustainable ceiling. This
   replaces the Phase 0.6 plan's code-reading estimate of ~40–160
   events/sec/instance with a measured number.
2. **Regression gate** (default, fixed-rate mode): submits at a fixed rate for
   a fixed duration and exits non-zero on FAIL, so it can be re-run after
   every later Phase 0.6 change to prove it actually moved the number.

Target scale from the plan: 20M events/day (~231/s average), with 5x and 10x
bursts (~1,157–2,315/s).

## Why this location

Lives under `deploy/compose/loadtest/`, a sibling of `deploy/compose/e2e/`,
`deploy/compose/gateway-ref/`, and `deploy/compose/live-mtls/` — the existing
homes for "drive the real stack from Python" tooling in this repo. A new
top-level `tools/loadtest/` would have split load-testing tooling away from
every other script that stands up and drives this same stack, for no benefit:
this harness reuses `live-mtls`'s PKI and `gateway-ref`'s compose profile
directly and is meaningless without them.

## Files

- `loadtest_core.py` — pure logic only (no network, no gRPC, no clock reads):
  rate scheduling, latency percentiles, the PASS/FAIL verdict, and the
  baseline ramp's ceiling selection. Unit-tested in isolation.
- `loadtest.py` — the CLI. Effectful shell around `loadtest_core.py`: real
  threads, a real (or, in `--dry-run`, fake) transport, optional Postgres
  backlog sampling.
- `test_loadtest_core.py` — pytest suite for the pure logic plus an
  end-to-end `--dry-run` integration test of the CLI.

## Standing up the stack

This harness does not start the gateway; it drives one that is already
running. Two ways to get one:

### Gateway-ref profile (what this README's examples use)

Self-contained: NATS JetStream, the Python reference ClickHouse/archive
providers, and both gateways (ingest + control), no Postgres/MinIO needed for
the ingest data path.

```powershell
# From deploy/compose/gateway-ref:
.\run.ps1
```

Or the equivalent by hand (what `run.ps1` does, useful on a shell where a
PowerShell profile isn't set up):

```bash
cd deploy/compose/live-mtls
python -m pip install --user --quiet cryptography
python generate_pki.py --out secrets
python render_configs.py
FP=$(python -c "
from cryptography import x509
from cryptography.hazmat.primitives import hashes
cert = x509.load_pem_x509_certificate(open('secrets/ingest-http-client.pem','rb').read())
print(cert.fingerprint(hashes.SHA256()).hex())
")
printf '%s' "$FP" > secrets/ingest-http-client.sha256
[ -f secrets/ingest-bearer-token ] || printf 'gateway-ref-token' > secrets/ingest-bearer-token

cd ..
APEX_BEARER_CERT_SHA256="$FP" docker compose -f compose.gateway-ref.yaml up -d --build
# gateway is now reachable at 127.0.0.1:18445 (mTLS) with secrets under
# deploy/compose/live-mtls/secrets/

# Tear down when done:
docker compose -f compose.gateway-ref.yaml down -v --remove-orphans
```

### Full e2e profile

`deploy/compose/e2e/run_gates.py` stands up `compose.e2e.yaml` (adds real
Postgres and MinIO) *and* `compose.gateway-ref.yaml` together, plus runs the
Rust adversarial/live-mTLS test suites. Heavier, but this is the profile to
use if you also want Postgres available for backlog sampling — see below.

## Running it

All three modes take the same target/credential flags:

```
--endpoint 127.0.0.1:18445           # gateway host:port
--secrets deploy/compose/live-mtls/secrets   # the fixture dir generate_pki.py wrote
--agent-id reference-agent           # must match APEX_BEARER_AGENT_ID
--workspace-id acme --namespace-id prod      # must be in APEX_ALLOWED_SCOPES
```

### Dry run — exercise the harness itself, no gateway, no network

```bash
python loadtest.py --dry-run --rate 100 --duration 10 --concurrency 16
python loadtest.py --dry-run --baseline --ramp-start 100 --ramp-step 100 --ramp-step-duration 2 --ramp-max-rate 500
```

Drives a fake in-process transport (`DryRunTransport`) that has the exact same
`ingest(event, event_id=...) -> bool` shape as the real one, so it proves
event construction (real `EventBuilder`, real UUIDv7 `event_id`s, real
canonical hashing), rate scheduling, concurrency, and the metrics/verdict
pipeline all wire together. **It says nothing about real gateway
performance** — see the numbers in "What was measured" below for that.

### Baseline mode — find the current ceiling

```bash
python loadtest.py \
  --endpoint 127.0.0.1:18445 --secrets ../live-mtls/secrets \
  --baseline \
  --ramp-start 20 --ramp-step 20 --ramp-step-duration 5 \
  --ramp-max-rate 400 --ramp-reject-threshold-pct 1.0 \
  --concurrency 64 \
  --json-report baseline-report.json
```

Runs `--ramp-step-duration` seconds at `--ramp-start`, then `--ramp-start +
--ramp-step`, and so on, stopping at the first step whose reject percentage
exceeds `--ramp-reject-threshold-pct` (or at `--ramp-max-rate`). Prints a
step-by-step table and the highest rate that stayed under threshold. Always
exits `0` — this is discovery, not a gate. Give it generous `--concurrency`
(the client should never be the bottleneck here) and don't trust the very
first step's reject count in isolation — connection/TLS-handshake warm-up on
the first few submissions can register as one spurious rejection even well
under the real ceiling (see "What was measured" for a worked example).

### Fixed-rate mode — the regression gate

```bash
# 20M events/day average (~231/s), sustained for a minute.
python loadtest.py \
  --endpoint 127.0.0.1:18445 --secrets ../live-mtls/secrets \
  --rate 231 --duration 60 --concurrency 64 \
  --target-rate 231 --max-reject-pct 1.0 \
  --json-report gate-report.json
echo "exit=$?"

# 5x burst.
python loadtest.py --endpoint 127.0.0.1:18445 --secrets ../live-mtls/secrets \
  --rate 1157 --duration 30 --concurrency 128 --target-rate 1157 --max-reject-pct 1.0

# 10x burst.
python loadtest.py --endpoint 127.0.0.1:18445 --secrets ../live-mtls/secrets \
  --rate 2315 --duration 30 --concurrency 256 --target-rate 2315 --max-reject-pct 1.0
```

Exits `0` on PASS, `1` on FAIL — wire this into CI or a pre-merge check the
same way `run_gates.py`'s gates are used.

## How to read the output

```
RATE       target=231.0/s achieved=231.0/s wall=20.00s attempted=4620
OUTCOMES   accepted=1630 duplicate=0 resource_exhausted=2990 unavailable=0 auth_error=0 other_error=0
LATENCY_MS p50=1.98 p95=11.12 p99=12.73 max=98.03 mean=5.24 min=1.40
BACKLOG    TODO: no --postgres-dsn given. Exact query this harness would run: SELECT count(*) FROM apex_event_outbox WHERE state = 'pending'

VERDICT    FAIL
  - reject rate 64.72% (2990/4620) exceeds the 1.00% threshold
```

- **RATE**: target vs. achieved submission rate (issued, not necessarily
  accepted) and how many submissions the run actually attempted.
- **OUTCOMES**: one bucket per `Outcome` (see `loadtest_core.Outcome`).
  `accepted` + `duplicate` is "the gateway durably admitted this event".
  **`resource_exhausted` intentionally merges `RateLimited` and
  `AdmissionBusy`** — see "Outcome classification" below for why; do not read
  this as one code being more common than the other.
- **LATENCY_MS**: p50/p95/p99/max/mean/min, in milliseconds, over every
  submission's *intended-send-time to response* latency (see "Latency
  definition" below) — including rejections. A rejection still has a latency;
  excluding them would hide exactly the tail this number exists to catch.
- **BACKLOG**: outbox pending-row depth samples if `--postgres-dsn` was given,
  else the literal TODO with the exact query (see below).
- **VERDICT**: `PASS`/`FAIL` and the specific reasons for FAIL, from
  `loadtest_core.evaluate_verdict`: achieved rate too far below target, reject
  rate too high, or (if `--backlog-max-pending` was given) the backlog
  exceeded its bound or was still growing at the end of the run.

### Outcome classification

`apps/event-ingest/src/errors/code.rs` maps both `GatewayErrorCode::RateLimited`
(per-scope admission throttle, `service.rs`) and `GatewayErrorCode::AdmissionBusy`
(the single-adapter mutex — literally the "synchronous fanout" this whole
phase exists to remove — is momentarily held by another request) to the *same*
gRPC status, `RESOURCE_EXHAUSTED` (`errors/gateway.rs`). This harness, like
`apex_sdk.ingest_transport.GrpcEventIngestTransport._status_name`, never reads
a server-supplied `details()` string — that is attacker-influenced text from
the client's point of view, by the same discipline the SDK itself follows — so
the two codes are genuinely indistinguishable at this boundary without
inventing a channel the production SDK does not have. `Outcome.RESOURCE_EXHAUSTED`
reports that honestly as one bucket instead of fabricating a split the wire
contract doesn't support. If a future phase adds a way to tell them apart at
the client (e.g. rich error details, a documented and audited
grpc-status-details field), split this bucket then — see `classify_grpc_status`
in `loadtest_core.py`.

### Latency definition

Latency is measured as *completion time − intended send time*, not
*completion time − actual dispatch time*. This corrects for what load-testing
literature calls coordinated omission: if the harness's own concurrency cap is
the bottleneck, the time a submission spent queued behind it is real latency a
caller would experience, and silently excluding it would make an overloaded
harness report suspiciously good numbers. It also means p99/max latency is a
signal of *either* gateway slowness *or* insufficient `--concurrency` — if
`achieved rate` is holding at target and latency is still high, raise
`--concurrency` before concluding the gateway is slow.

### Backlog sampling

Exact query, run against a **read-only** DSN when `--postgres-dsn` is given:

```sql
SELECT count(*) FROM apex_event_outbox WHERE state = 'pending'
```

(`deploy/postgres/outbox.sql`'s `apex_event_outbox` table; matches the
partial index `apex_event_outbox_pending_idx`, so this is an index-only scan,
not a sequential one, even without the gateway's own `n_live_tup` shortcut —
see `sample_outbox_pending`'s docstring in `loadtest.py` for why an exact
count is the right call for a periodic sampler even though the gateway's own
hot path deliberately avoids one.)

**This is a TODO in practice, not a working default**, and here is exactly
why: `compose.gateway-ref.yaml` — the profile these examples use — runs
`ingest-gateway` with `APEX_OUTBOX_FILE=/var/lib/apex/outbox.jsonl`, a
JSONL-file outbox, not Postgres. The Postgres outbox backend
(`apps/event-ingest/src/outbox/postgres.rs`) is compiled in only behind the
`postgres` Cargo feature and is exercised in this repo only by
`run_gates.py`'s `cargo test --features postgres` step and by
`compose.control-pg.yaml` (which wires Postgres for the *control* gateway, not
`event-ingest`). No compose profile in this repo currently starts
`event-ingest` itself against Postgres with a host-reachable DSN.

To make `--postgres-dsn` do something today, someone needs to either:

1. Add an ingest-gateway compose overlay that sets `APEX_OUTBOX_BACKEND=postgres`
   (or whatever the Rust side's config knob is named — check
   `apps/event-ingest/src/startup/service.rs`) plus `APEX_POSTGRES_URL`
   pointing at a `postgres` service with its port published to the host, the
   way `compose.e2e.yaml`'s `postgres` service already does
   (`127.0.0.1:15432`); or
2. Run against a manually configured Postgres-backed gateway deployment and
   pass its DSN directly.

Either way, once a DSN is reachable: `pip install 'psycopg[binary]'` (or
`psycopg2-binary`) — deliberately not a hard dependency of this harness, the
same lazy-import discipline `apex_sdk.ingest_transport` uses for `grpc` — and
pass `--postgres-dsn postgresql://user:pass@host:port/dbname`. **This is Phase
0.6 item 6's concern** (the plan calls out wiring a durability backend); this
harness is ready for it the moment a DSN exists.

## What was measured here

Docker was available in the environment this was built in, so the
`gateway-ref` profile was actually stood up (build, run, load-tested, torn
down cleanly — `docker compose ... down -v`, verified no leftover containers,
volumes, or networks) rather than only exercised via `--dry-run`. These are
real numbers from one instance of this reference stack — reference Python
`clickhouse-projection`/`archive-provider` providers, not real ClickHouse, on
whatever CPU/disk the build host had that day — not a portable constant. **Re-run
before quoting a number in a design doc.**

Baseline ramp (`--baseline --ramp-start 20 --ramp-step 20
--ramp-step-duration 5 --ramp-max-rate 400 --concurrency 64`):

```
rate,achieved_rate,attempted,reject_pct
20.0,20.2,100,1.00     <- first step; 1 reject was TLS/connection warm-up, not steady-state
40.0,40.1,200,0.00
60.0,60.1,300,0.00
80.0,80.0,400,0.25
100.0,100.0,500,3.40   <- exceeded the 1% threshold, ramp stopped
BASELINE_RESULT sustainable ceiling ~= 80.0 events/sec
```

This lands inside the Phase 0.6 plan's own code-reading estimate (~40–160
events/sec/instance) — a measured number replacing a guess, in the same
ballpark as the guess.

Fixed-rate gate at the 20M/day average target (`--rate 231 --duration 20
--concurrency 64 --target-rate 231 --max-reject-pct 1.0`):

```
RATE       target=231.0/s achieved=231.0/s wall=20.00s attempted=4620
OUTCOMES   accepted=1630 duplicate=0 resource_exhausted=2990 ...
LATENCY_MS p50=1.98 p95=11.12 p99=12.73 max=98.03 mean=5.24 min=1.40
VERDICT    FAIL — reject rate 64.72% (2990/4620) exceeds the 1.00% threshold
```

Expected and correct: the current synchronous-fanout gateway cannot yet hold
the target rate, which is exactly the fact later Phase 0.6 items exist to fix
and this harness exists to re-check after each one.

## Known limitations

- **Windows timer resolution.** `time.sleep` on Windows defaults to ~15.6ms
  granularity, which can make the open-loop scheduler dispatch in small
  bursts rather than perfectly evenly at high rates (hundreds+ events/sec) on
  a Windows host. Linux/WSL/CI runners do not have this limitation. The
  ramp/gate numbers above were still captured on Windows and look evenly
  paced in practice (see `achieved` tracking `target` closely in every step
  above), but for the 1,157–2,315/s burst targets, prefer running this on
  Linux/CI if pacing precision at that rate matters to the result.
- **One TCP connection (mTLS channel) per concurrent worker thread.** This
  models many independent concurrent agents, which is the realistic shape of
  the intended workload, but means `--concurrency 256` opens 256 channels. If
  a test ever needs to isolate "one shared connection, many streams" behavior
  instead, that is a deliberate scope cut, not an oversight.
- **`--postgres-dsn` has nothing to point at by default** — see "Backlog
  sampling" above.

## Validation performed

- `python -m py_compile loadtest_core.py loadtest.py test_loadtest_core.py`
- `python loadtest.py --help`
- `python -m pytest test_loadtest_core.py -v` — 49 tests, all pure-logic
  (rate scheduling, percentile computation, verdict decisions, ceiling
  selection) plus `--dry-run` CLI integration tests; no live gateway.
- A real `gateway-ref` stack was built, started, load-tested in both baseline
  and fixed-rate mode against the real mTLS endpoint, and torn down cleanly
  (see "What was measured" above).
