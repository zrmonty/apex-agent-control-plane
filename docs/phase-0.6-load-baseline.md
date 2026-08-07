# Phase 0.6 load baseline (measured)

**Status: measured, not estimated.** This document replaces the Phase 0.6 plan's "Measured baseline" section, every number in which came from reading code. The numbers below come from real gRPC over real mTLS against the built `apex-event-ingest` image running under `deploy/compose/compose.gateway-ref.yaml`, with its full durability chain live. Nothing here was measured in-process.

Scope of this pass: Phase 0.6 work item 1 only -- build the harness, take the baseline. No gateway behaviour was changed.

## Headline

| Question | Answer |
|---|---|
| Sustained accepted throughput | **87-92 events/sec** at the 10M/day target offering of 116/s. Peak accepted rate anywhere in the sweep: **~117/s**. |
| Serial (one-at-a-time) ceiling | **111-115 events/sec** (p50 full-path latency 8.7-9.0 ms). |
| Does the 10M/day average admit today? | **No.** At 116/s offered, 24.5% of events are refused with `RESOURCE_EXHAUSTED`. |
| Does a 5x/10x peak admit? | **No, and it is worse than shedding the excess.** Goodput *falls* to 45/s at 5x and 25/s at 10x -- below the rate the same gateway sustains at 1x. |
| Where is the time going? | Outbox commit + fanout: **7.9-8.1 ms of an 8.7-9.0 ms request.** Admission (auth + validate + RFC 8785 canonicalize + SHA-256) does not resolve above the transport round trip. |
| Does concurrency help? | **No.** Accepted throughput is flat at ~105-117/s from 1 to 64 in-flight clients. The plan doc's single-flight claim is confirmed. |

Against the plan doc's code-reading estimate of "40-160 events/sec, 6-25 ms/event": the **latency estimate was accurate** (8.7-9.0 ms measured, inside the 6-25 ms band) and the **throughput estimate was in range but its top half is unreachable** -- the real number is 111-115/s serial and 87-92/s under paced load, not up to 160/s. Two ceilings the plan doc did not mention were found, and one of them turns overload into goodput collapse rather than graceful shedding. See "Corrections to the plan doc's baseline".

## The harness

| Piece | Path | Job |
|---|---|---|
| Load generator | `apps/event-ingest/src/bin/load_baseline.rs` (bin `apex-load-baseline`) | Drives real gRPC/mTLS at a live gateway. Per-stage latency probes, concurrency sweep, paced sustained and burst load, JSON report. |
| Orchestrator | `deploy/compose/loadtest/run_load_baseline.py` | Builds the image, starts the stack under its own Compose project, runs the generator, merges the dependency probe, tears the stack down. |
| Dependency probe | `deploy/compose/loadtest/stage_probe.py`, service `loadtest-stage-probe` in `compose.gateway-ref.yaml` | Times JetStream publish+ack, the ClickHouse write, and the archive PUT+verify from a peer container with the gateway's own client certificates. |

### Re-running it

One command, from the repository root:

```bash
python deploy/compose/loadtest/run_load_baseline.py
```

That is the full baseline: it builds `apps/event-ingest/Dockerfile`, starts Compose project `apex-gateway-loadtest` on host port 18455, waits for the gateway to serve TLS, runs every scenario, and tears the stack down with `down -v`. Useful flags: `--skip-build` (reuse `apex-event-ingest-ref:latest`), `--keep-up` (leave the stack running for follow-up runs), `--quick` (a ~30 s smoke run rather than a baseline), `--min-accepted-per-sec R` (exit non-zero below R), `--namespaces`, `--sustained-rate`, `--sustained-secs`, `--burst-multipliers`, `--concurrency-levels`.

The generator can also be pointed at any already-running gateway:

```bash
cd apps/event-ingest
cargo run --release --bin apex-load-baseline --features test-support -- \
  --endpoint https://localhost:18455 \
  --secrets ../../deploy/compose/live-mtls/secrets-host \
  --scenario all --json ../../.local/apex-lab/load-baseline.json
```

`--scenario` is `stages`, `concurrency`, `sustained`, `burst`, or `all`. `--help` lists every flag.

### Why Rust for the generator

The gateway rejects any envelope whose `integrity.event_hash` does not match the SHA-256 of the RFC 8785 (JCS) canonicalization of the envelope. A Python generator would need a byte-exact re-implementation of that canonicalization; one byte of drift and the harness would be measuring the validation rejection path at full speed while reporting it as throughput. The Rust binary calls this crate's own `canonical_event_hash` and its own generated protobuf types, so a well-formed envelope is well-formed by construction. The orchestration around it is Python, matching `deploy/compose/e2e/run_gates.py` and `deploy/compose/object_lock_acceptance.py`.

The generator is a client. It never links the gateway in-process, never writes to a store, and never disables a control. `required-features = ["test-support"]` in `Cargo.toml` keeps it out of a default `cargo build`, and `apps/event-ingest/Dockerfile` builds `--bin apex-event-ingest` explicitly, so it never enters the runtime image.

## What an event looked like

"Events/sec" is meaningless without the payload, so both ends of the realistic range were measured. Both shapes are `LLM` events with the full v1 envelope (identifiers, scope, actor, version, integrity), signed with a real canonical hash.

| Shape | Encoded envelope | Contents |
|---|---|---|
| `small` | **489 bytes** | Operation, provider, model, input/output token counts, latency, stop reason, two tool names. What a high-rate agent runtime emits most of. |
| `large` | **8,721 bytes** | The same, plus an 8 KiB captured output excerpt and its digest, under the contract's 32 KiB per-text-field cap. |

Payload size makes almost no difference at this scale: full-path p50 8.70 ms (small) vs 8.98 ms (large), a 3% difference for 18x the bytes. The chain is dominated by fixed per-event costs -- four `fsync`-backed journal appends and three network round trips -- not by payload handling. All throughput and burst numbers below use the `small` shape.

## Per-stage latency

The gateway emits no timing or tracing signal, so stages are separated by **where a request stops**, measured over the same channel under the same conditions. Adjacent rows differ by exactly one stage.

Serial, one request in flight, 200 rounds per payload, paced to 25 ms per round so the probe stream itself never meets a rate limiter.

| Probe stops at | small p50 | small p99 | large p50 | large p99 |
|---|---|---|---|---|
| tonic's router (unknown method) -- TLS + HTTP/2 + gRPC round trip, no handler | 0.84 ms | 1.00 ms | 0.84 ms | 1.27 ms |
| `IngestRequest::from_validated_transport` -- + bearer verify, admission buckets, blocking-pool handoff, adapter mutex, decode, validate, JCS canonicalize, SHA-256 compare | 0.82 ms | 1.00 ms | 0.90 ms | 1.25 ms |
| `IdempotencyStore::reserve` -> `Duplicate` -- + committed-key lookup | 0.81 ms | 0.98 ms | 0.90 ms | 1.71 ms |
| acknowledged event -- + outbox enqueue, JetStream publish+ack, ClickHouse POST, archive PUT+verify, outbox complete, idempotency commit | **8.70 ms** | 10.27 ms | **8.98 ms** | 10.79 ms |

Attributed, p50, small payload:

| Stage | Cost | Share |
|---|---|---|
| Transport round trip (client-side floor, not gateway work) | 0.84 ms | -- |
| Admission: auth + validate + canonicalize + hash | **below the 0.1 ms measurement floor** | ~0% |
| Idempotency committed-key lookup | below the measurement floor | ~0% |
| **Outbox commit + fanout** | **7.89 ms** | **~91%** |

The admission row measures *lower* than the transport row in two of the three runs (by 0.02-0.05 ms). That is not negative work: it means the entire authenticate-validate-canonicalize path costs less than the run-to-run noise on a loopback gRPC round trip. Admission is effectively free at this event size. Everything the gateway spends is downstream of it.

### Splitting the fanout band

The 7.9 ms band cannot be split by stopping a request early -- there is no request that completes the outbox commit and then stops. It was split instead by timing each dependency from a peer container on the stack's own network, presenting the same `ingest-http-client` certificate the gateway presents, reusing one connection per dependency the way the gateway's `reqwest` and `async-nats` clients do (300 iterations, first 5 discarded as handshake):

| Dependency | p50 | p90 | p99 |
|---|---|---|---|
| JetStream publish + PubAck | 0.20 ms | 0.23 ms | 0.42 ms |
| ClickHouse projection write (POST) | 2.55 ms | 2.88 ms | 3.15 ms |
| Archive PUT + read-back verify | 2.56 ms | 2.88 ms | 3.36 ms |
| **Sum of the three** | **5.31 ms** | | |
| Residual (7.89 - 5.31): outbox `Pending` append+fsync, outbox `Complete` append+fsync, idempotency `Committed` append+fsync, and the glue between them | **~2.6 ms** | | |

Read the dependency numbers as a **floor** for each stage: they are the dependency's service time seen from a peer, and they exclude whatever the gateway's own client stack adds. They are also measured against reference providers whose storage is `tmpfs` (`compose.gateway-ref.yaml` mounts `tmpfs: [/var/lib/apex]` for both, and JetStream's `/data`), so real S3-class object storage and a real ClickHouse would be materially slower -- probably by more than everything else in the chain combined.

## Concurrency behaviour

Closed loop, small payload, 600 requests per level, spread over 8 namespaces of one workspace.

| In-flight clients | Accepted | Accepted/sec | p50 ms | p99 ms | Refused |
|---|---|---|---|---|---|
| 1 | 600 | 107.1 | 8.38 | 37.40 | 0.0% |
| 2 | 242 | 105.5 | 0.86 | 9.27 | 59.7% |
| 4 | 271 | 117.2 | 0.92 | 8.91 | 54.8% |
| 8 | 271 | 115.4 | 0.92 | 8.97 | 54.8% |
| 16 | 274 | 116.4 | 0.98 | 10.34 | 54.3% |
| 32 | 277 | 116.0 | 0.92 | 9.11 | 53.8% |
| 64 | 275 | 115.8 | 0.89 | 9.06 | 54.2% |

**The plan doc's single-flight claim is confirmed.** Accepted throughput is flat within noise from 1 to 64 concurrent clients; the second and every later client buys nothing. The bimodal latency is the signature: an accepted request takes ~8.5 ms, a refused one takes ~0.9 ms, and past one in-flight client the median request is a refusal. `apps/event-ingest/src/auth/service.rs` still wraps the whole ingest adapter in `Arc<Mutex<_>>` and reaches it with a non-blocking `try_lock()`, so a concurrent caller is refused rather than queued -- exactly as described.

One correction to how that is *observed*: **a client cannot tell `ADMISSION_BUSY` from `RATE_LIMITED`.** `errors/gateway.rs` maps both to `RESOURCE_EXHAUSTED` and gives both the identical message "Request capacity is temporarily unavailable. Retry with exponential backoff." The harness therefore reports them as one `busy_or_rate_limited` bucket, and separates them by construction: runs whose offered rate stays under the admission quota can only be producing `ADMISSION_BUSY`. This is a real operability gap -- an operator cannot distinguish "the gateway is single-threaded" from "this tenant is over quota" from the response.

## Load shape: sustained, then burst

Open loop: requests are dispatched on a fixed schedule and both latencies are reported -- *service* latency from the moment a request actually left the harness, and *arrival* latency from the moment it was scheduled to leave. The gap between them is harness backlog, reported rather than hidden.

### Sustained at the 10M/day average

116 events/sec offered for 60 s, 8 namespaces, small payload:

| Metric | Value |
|---|---|
| Offered | 6,960 (116.0/s achieved) |
| **Accepted** | **5,252 (87.5/s)** |
| Refused `RESOURCE_EXHAUSTED` | 1,708 (**24.5%**) |
| Service latency | p50 8.43 ms, p99 11.26 ms, max 40.69 ms |
| Arrival latency | p50 10.39 ms, p99 22.61 ms, max 47.15 ms |

A second identical run gave 5,525 accepted (92.1/s, 20.6% refused). **The gateway does not sustain the 10M/day average today**, and it fails by refusing events, not by queueing or slowing down: latency stays flat and one event in four to five is simply lost unless the producer retries.

### Burst

Each rate offered for 10 s, 8 namespaces, small payload. Two runs of the ladder, plus a finer sweep around the knee:

| Offered/sec | Accepted/sec | Accepted share |
|---|---|---|
| 116 (1x, 60 s) | 87.5 | 75.5% |
| 174 (1.5x) | 88.7 | 51.0% |
| 200 | 84.5 | 42.3% |
| 232 (2x) | 91.6 | 39.5% |
| 240 | 89.4 | 37.3% |
| 256 | 85.8 | 33.6% |
| 300 | 82.4 | 27.5% |
| 348 (3x) | 70.9 | 20.4% |
| 400 | 62.1 | 15.5% |
| 580 (5x) | 45.1 | 7.8% |
| 600 | 44.7 | 7.5% |
| 1,160 (10x) | 25.4 | 2.2% |

**Degradation shape: not graceful shedding but goodput collapse.** Up to ~256/s offered, accepted throughput holds at 82-92/s and the excess is refused, which is the expected behaviour for a single-flight admitter. Above ~256/s the *accepted* rate starts falling, and by 10x peak the gateway delivers **25/s -- 3.5x less than it delivers at 1x**. Latency does not climb: p99 service latency is *lower* under 10x load (8.80 ms) than at 1x (11.26 ms), because almost every request is a fast refusal. Offering more load makes the system carry less.

The mechanism was isolated. `AuthenticatedGrpcService::admit_request` consults the `EphemeralStore` rate limiter with

```rust
let key = RateLimitKey { namespace: workspace_id, bucket: "admission" };
guard.check_rate_limit(&key, MAX_ADMISSION_REQUESTS_PER_SECOND /* 256 */, Duration::from_secs(1))
```

-- the key carries the **workspace only**, so all namespaces of a tenant share one 256 req/s bucket, and `InMemoryEphemeralStore::check_rate_limit` is a **fixed window**, not a sliding one or a token bucket. At an offered rate of R > 256/s, the whole 256-request quota is consumed in the first `256/R` of each second; the single-flight adapter admits ~115/s during that fraction and then sits idle for the rest of the window. Predicted goodput is therefore `~115 x 256/R`, which matches every measured point above the knee within ~10%:

| Offered | Predicted | Measured |
|---|---|---|
| 300 | 98 | 82 |
| 400 | 74 | 62 |
| 600 | 49 | 45 |
| 1,160 | 25 | 25 |

Three independent checks rule out the obvious alternatives. Client in-flight ceilings of 4, 16, 128, and 512 all give 23.7-25.4/s at 1,160/s offered, so it is not client-side contention. The harness achieved 1,158.7/s offered against a 1,160/s target, so it is not a generator limit. `docker stats` during a 20 s 10x burst shows the gateway container at **15-16% of one CPU** and the two providers at ~2.7% each, so nothing is CPU-saturated -- the gateway is idle most of the time while refusing 1,135 events/sec.

## Two hard ceilings the plan doc did not record

Both were confirmed live, not inferred.

### 1. The gateway stops accepting a scope after 3,125 events, permanently

`FileIdempotencyStore::reserve` enforces `scope_capacity(capacity) = capacity/16`. With the profile's shipped `APEX_IDEMPOTENCY_CAPACITY=50000` that is **3,125 committed events per `workspace/namespace`**, after which every new event in that scope is refused with `IDEMPOTENCY_CAPACITY`. Nothing prunes the journal, so the refusal is permanent for the life of the volume.

Driving one scope at 200/s for 45 s:

```
outcomes: {"busy_or_rate_limited": 5167, "idempotency_capacity": 2626, "ok": 1207}
```

and the container's journal holds exactly `3125` committed keys for `acme/prod`. At the 10M/day target rate that ceiling is reached in **27 seconds** of single-tenant traffic. The 50,000 global capacity is reached in about 7 minutes.

### 2. The outbox file is full after ~116,000 events

`FileOutbox` refuses an append past `MAX_OUTBOX_FILE_BYTES = 256 MiB`. Measured growth over the run: 16,781 accepted events produced 38,662,667 bytes of `outbox.jsonl` -- **2,304 bytes of journal per 489-byte event**, because the `Pending` record serializes the protobuf envelope as a JSON array of decimal byte values. That gives ~116,000 events before the file is refused, or **~17 minutes at 116/s**. The idempotency journal is far cheaper (243 bytes/event) and its in-memory capacity binds long before its 256 MiB file cap.

`docs/phase-0.5-progress.md`'s Postgres backends are the multi-writer answer for both, but the reference profile that CI and every local run exercise uses the file backends, and these are their real limits.

## Corrections to the plan doc's "Measured baseline"

| Plan doc claim | Verdict |
|---|---|
| Global single-flight admission via `Arc<Mutex<_>>` + `try_lock()`; concurrent callers get `AdmissionBusy` rather than queueing | **Confirmed.** Accepted throughput is flat from 1 to 64 in-flight clients. |
| Fully synchronous in-mutex fanout per event | **Confirmed**, and it is where ~91% of request time goes. |
| Rough estimated ceiling 40-160 events/sec, 6-25 ms/event | **Latency confirmed** (8.7-9.0 ms). **Throughput narrowed and lowered**: 111-115/s serial, 87-92/s under paced load. The upper half of the estimated band is not reachable on this hardware with these dependencies. |
| Target ~116/s average, 580-1,160/s at 5-10x peak | **The average does not admit** (24.5% refused at 116/s), and **peaks make it worse, not merely insufficient** (25/s goodput at 10x). |
| Unbounded `SELECT COUNT(*)` in the Postgres outbox; no prune job | Not exercised -- the reference profile runs the **file** backends. Their equivalents are worse and are documented above: a 3,125-per-scope hard stop and a 256 MiB outbox file. |
| Bottleneck implicitly the whole synchronous chain | **Refined.** Admission is free. Within the chain: ClickHouse 2.55 ms and archive PUT+verify 2.56 ms (both against `tmpfs`-backed reference providers), journal `fsync`s ~2.6 ms, JetStream 0.20 ms. |

## What the next pass should target

Work item 2 (decouple admission from fanout) is aimed correctly: 7.9 ms of an 8.7 ms request is outbox commit plus fanout, and moving it out of the request path is the whole win. Three things this measurement adds:

1. **Removing the fanout is necessary but not sufficient.** If admission acknowledges after the outbox `Pending` append+fsync alone, the request path drops to roughly `0.9 ms + one fsync`, so the serial ceiling rises to somewhere in the high hundreds per second -- but the fixed-window per-workspace 256 req/s admission quota then becomes the binding limit, and it is the thing that converts overload into collapse. Either raise it, key it per scope rather than per workspace, or replace the fixed window with a sliding window or token bucket. Otherwise a decoupled gateway will still deliver less at 10x peak than at 1x.
2. **The file backends' capacity ceilings will terminate any exit-gate run before throughput does.** Work item 7 re-runs this harness at 10M/day; against the file backends that run stops after 3,125 events per scope, or ~116,000 events overall. Work item 5's prune policy, or running the exit gate against the Postgres backends, has to land first.
3. **Two operability gaps worth fixing while the request path is being rewritten.** `ADMISSION_BUSY` and `RATE_LIMITED` are indistinguishable to a client (same code, same message), so a producer cannot tell "retry, the gateway is briefly busy" from "back off, you are over quota". And `RateLimitKey.namespace` carrying the workspace id -- not the workspace/namespace pair -- is either a bug or an undocumented tenant-level ceiling; it should be one or the other on purpose.

## Environment, and what that means for the numbers

| | |
|---|---|
| Host | Windows 11, Docker Desktop 29.6.2 (WSL2 backend), 30 GiB available to the VM |
| Gateway | `apex-event-ingest-ref:latest`, built from `apps/event-ingest/Dockerfile` with no optional features (no `valkey`, no `postgres`) |
| Stores | File outbox and file idempotency journal on a Docker named volume; JetStream, ClickHouse projection, and archive provider from `compose.gateway-ref.yaml`, all `tmpfs`-backed |
| Client | On the host, reaching the container through the published loopback port |
| Report | `.local/apex-lab/load-baseline.json` (not committed) |

These are absolute numbers for **this** environment. Treat the *shape* as portable and the magnitudes as not: the dependency service times would rise substantially against real S3-class storage and a real ClickHouse, the journal `fsync` cost depends on the volume's backing store, and the loopback round trip is optimistic against any real network. What does not depend on the environment is that concurrency buys nothing, that admission is free relative to fanout, that overload reduces goodput, and that the file backends stop accepting after a fixed number of events.

## What was not tested

- **Postgres outbox and idempotency backends.** The reference profile runs the file backends; `--features postgres` was not built or measured. The plan doc's `SELECT COUNT(*)`-per-enqueue claim is therefore neither confirmed nor refuted here.
- **Real S3, Azure, or GCS archive backends.** The archive provider ran its `local` SQLite backend on `tmpfs`. Per-event Object-Lock PUT+verify against managed object storage is the number Phase 0.6's decision on "real S3 vs self-hosted MinIO" needs, and it is not this one.
- **Multiple gateway replicas.** Everything above is one gateway process.
- **Sustained runs longer than 60 s**, because the capacity ceilings above make a longer run measure the ceiling rather than the throughput.
- **Any drift over a long run.** First-decile and last-decile p50 full-path latency over 200 serial events differ by under 0.15 ms, so no growth was visible at that scale -- but 200 events is far too few to see the linear committed-key scan in `FileIdempotencyStore::reserve`, and this pass did not size a run to expose it.
- **The per-stage split inside the gateway process.** The dependency numbers come from a peer container, not from a trace taken inside the gateway. Getting a true in-process split needs instrumentation, which is a change to a pen-test-hardened request path and belongs to a pass that intends to change it.

## An unrelated contract gap found while building the harness

The `large` payload initially carried `output_excerpt_sha256`, the sibling digest field `docs/event-schema.md` requires ("They must include the original SHA-256 in a sibling `*_sha256` field"). The gateway refused it with `SECRET_EXPOSURE`: `validation/secrets.rs::is_hash_like_key` exempts a 64-hex value only under a key ending in `hash`, `digest`, `ref`, or `id`, and `..._sha256` ends in none of them, so `looks_like_encoded_secret` fires. **A producer that follows the documented contract literally is rejected.** The harness sidesteps it by naming the field `output_excerpt_digest`; the contract and the detector should be reconciled, which is not this pass's job.

## CI

`.github/workflows/live-mtls-e2e.yml` runs the harness in `--quick` shape against the gateway container it already stands up, with `--min-accepted-per-sec` as a loose tripwire. It is a "did something obviously break" check, not a performance gate: the floor is set far below the measured baseline so normal runner variance cannot fail it, and it adds well under a minute to a workflow that already builds the image and runs the adversarial corpus. `.github/workflows/ci.yml` additionally `cargo check`s the harness binary so it cannot bit-rot, which costs nothing in a job that has already compiled the crate.

A strict per-commit performance gate was deliberately **not** added. Throughput on a shared GitHub runner varies by more than the regressions worth catching, and a gate that fails on noise gets disabled.

---

Writing style: [ASD-STE100](writing-style-ste100.md).
