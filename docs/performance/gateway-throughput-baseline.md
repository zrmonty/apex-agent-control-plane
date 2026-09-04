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
targets, MCP session cold start (`initialize` + `tools/list`), warm
`tools/call` p50/p95/p99, session reuse, and bounded concurrency. The harness
does not by itself split gateway CPU time into auth, governance, CLI,
filtering, or evidence stages; collect those from service instrumentation and
downstream metrics alongside the JSON report. Run the matrix only against a
running disposable proxy profile:

```text
python deploy/compose/loadtest/mcp_proxy_loadtest.py --url http://127.0.0.1:18460/mcp --proxies 1,2,8 --concurrency 1,8,32
```

Each report must preserve the environment, image/config revision, container
limits, sample count, failures, and the exact command. A result with no
reachable endpoint is a failed measurement, not a zero-latency baseline. The
first run establishes an engineering baseline; it does not establish a
production SLO or capacity claim.

The managed HTTP revision also requires its configured allowed origin. The
complete command for the disposable fixture is:

```text
python deploy/compose/loadtest/mcp_proxy_loadtest.py --url http://127.0.0.1:18460/mcp --bearer-token fixture-token --origin https://console.example.test --tool portfolio.read --input-json '{"portfolioId":"fixture"}' --proxies 1,2,8 --concurrency 1,8,32 --samples 64 --timeout 3
```

On 2026-09-04, the harness was verified against the actual
`ManagedHttpServer` Streamable HTTP implementation with a deterministic
test-only executor. All 9 scenarios completed 64/64 calls successfully. Warm
throughput ranged from 138.513 calls/s at one session to 1,009.262 calls/s at
32 concurrent sessions for one proxy; the highest observed warm p95 was
22.817 ms. These are protocol-layer fixture measurements, not production
capacity claims: the executor bypassed live governance, upstream I/O, and
durable event admission.

The disposable Docker Compose profile was also built and started successfully
with its non-root, read-only, dropped-capability controls. It cannot be used
by this HTTP harness yet: its revision is configured for `stdio`, the service
publishes no host port, and its test upstream is not an HTTPS Streamable HTTP
fixture. A run against `127.0.0.1:18460` therefore correctly failed
reachability. The next integration item is a real HTTP runtime profile wired
to live Apex governance/event services and an HTTPS upstream before quoting
end-to-end numbers.
