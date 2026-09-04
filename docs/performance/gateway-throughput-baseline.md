# Active gateway throughput baseline

Date: 2026-09-03
Worktree: `codex/codebase-hardening`, based on `2e3245f`

## Harness baseline

Command:

```text
python deploy/compose/loadtest/loadtest.py --dry-run --rate 1000 --duration 2 --concurrency 64 --target-rate 1000 --max-reject-pct 1
```

Result: 2,000 attempts, 995.6 events/s achieved, p50 5.28 ms, p95 8.53
ms, and zero rejects. This validates the harness and local event-construction
cost only; it is not a gateway or downstream capacity claim.

## Struct serialization microbenchmark

Command:

```text
node --import tsx scripts/benchmark-events.mjs
```

The benchmark performs five samples of 100,000 equivalent metadata encodes,
comparing the pre-refactor `Object.fromEntries(...map(...))` implementation
with the current direct accumulator loop in `live/events.ts`:

| Measurement | Median | Range |
| --- | ---: | ---: |
| pre-refactor | 126.72 ms | 123.34–129.34 ms |
| current | 70.51 ms | 67.92–71.47 ms |

The current helper is approximately 44.4% faster in this isolated operation
and allocates fewer intermediate arrays. End-to-end live throughput must still
be measured against the running mTLS gateway with the real load harness before
quoting a production capacity number.

## Optimization guardrails

The change preserves the protobuf `Value` oneof mapping, canonical event
hashing, metadata-only event shape, and the durable-admission-before-success
ordering. The live gRPC package definitions are also cached after first load;
that is a startup allocation reduction and is not included in the microbench
number above.

## Managed proxy measurement protocol

The managed proxy gate uses
`deploy/compose/loadtest/mcp_proxy_loadtest.py` to record, without inventing
targets, cold start, readiness, first-call, warm p50/p95/p99, upstream reuse,
CLI startup, filtering, evidence admission, and bounded concurrency. Run the
matrix only against a running disposable proxy profile:

```text
python deploy/compose/loadtest/mcp_proxy_loadtest.py --proxies 1,2,8 --concurrency 1,8,32
```

Each report must preserve the environment, image/config revision, container
limits, sample count, failures, and the exact command. A result with no
reachable endpoint is a failed measurement, not a zero-latency baseline. The
first run establishes an engineering baseline; it does not establish a
production SLO or capacity claim.
