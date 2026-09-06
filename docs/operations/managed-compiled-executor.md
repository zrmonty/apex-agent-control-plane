# Compiled managed call executor

`CompiledManagedExecutor` is a dormant composition boundary for the approved
`portfolio.read` profile. It is not wired into a production root and does not
establish protected staging, enrollment, live network policy or Serving.

## Trusted composition

Supply `preparation` (the existing `CallPreparationOptions`), `calls` (the actual
`OwnedCallCoordinator.start` capability) and `evidence` (the actual
`ManagedEvidenceClient.start` capability). The executor constructs the real
`CompiledCallPreparer` and `ManagedEvidenceBuilder` against the same compiled
binding/policy profile. Injected capabilities are trusted local root/test seams,
not proof that caller-supplied objects or receipts are authoritative.

The production root must bind those dependencies to the same protected deployment,
clock, policy, enrolled evidence workload and selected upstream session. Use the
reviewed typed evidence client, not a structural receipt-producing stub. It owns
canonical reply decoding; the executor additionally checks the receipt against
the exact prepared event ID/hash. No new TLS/channel/factory activation is added.

Configuration compilation rejects **all nonempty `spec.authBindings`**. Per-subject
outbound credential selection is not implemented by this boundary. Existing
preparation compilation also rejects unsupported schemas, aliases, CLI profiles,
transports and approval configuration. A runtime authorization reply requiring
approval is handled as non-success, never an implicit approval or replay.

## Job API and ownership

`start(identity, alias, input, originalClockSnapshot, deadlineMonotonicNs)` returns:

- `result`: only newly constructed, allowlisted MCP output after required evidence
  acceptance, or the static error `compiled managed execution refused safely`.
- `closed`: actual local raw-call/evidence closure and completed local processing.
  Logical success, cancellation, a timer or a failed close is not this receipt.
- `cancel()`: requests cancellation and refuses an unsettled outward result.
- `observation()`: immutable passive state, fresh call/trace/span IDs, evidence
  linkage and local closure state; no dependency or clock calls when read.
- `completion()`: immutable admission payload/hash, optional accepted receipt,
  observed evidence result/closure boundaries and raw-owner metadata, when a
  canonical admission payload could be built. Earlier snapshots do not mutate.

At most 128 jobs are retained, including pending dispatch and cancelled jobs with
held physical ownership. `close()` revokes new admission before cancellation,
cancels this executor's jobs and awaits their exact closure. It does not close
the shared raw coordinator, MCP sessions, evidence client/channel or grant root.
The trusted root retains responsibility for those owners and their shutdown.

Rejected/unknown physical closure stays pending and retains capacity; process-level
supervision must handle irrecoverable uncertainty. No timeout fabricates remote
reservation release. In particular, a raw coordinator may be locally closed while
its `pending()` still contains an unknown reservation or failed completion receipt.
Those records and any explicit retry remain owned by that coordinator, not by
this executor. There is no automatic upstream or evidence replay here.

Settled raw/evidence exchange references are dropped after local closure. This is
not byte zeroization or a whole-heap secrecy guarantee; JS objects/strings, external
promises and consumer-retained output have their usual independent lifetimes.

## Output boundary

Raw output must be an MCP `CallToolResult`, with non-error `structuredContent`.
The passive input tree is bounded to 262144 serialized bytes, 8193 nodes and depth
64, then copied before executor clock/observation callbacks. Getters, proxies,
custom prototypes, cycles, nonfinite numbers and active serialization hooks refuse.
This bound is intentionally tighter than the upstream wire parser's 1 MiB limit.

SDK envelope validation is followed by the existing portfolio allowlist filter.
Returned `portfolio_id` must equal the prepared input's `portfolioId`. Unsupported
field restrictions refuse. Untrusted text/image/resource content, `_meta`, unknown
portfolio fields and upstream error text are never forwarded. Missing structured
content has no legacy text-JSON fallback. Output contains only a newly constructed
public `structuredContent`, its JSON text representation and `isError: false`.
The allowlist is not content-based DLP of values in approved public fields.

## Evidence and timing meanings

Known allowed/denied/approval decisions remain exact typed metadata, including
bigint policy revision. Upstream/validation/filtering failures with known decisions
produce failed admission evidence. An authorization transport failure without a
known decision does not manufacture a denial. If cancellation/stop/deadline occurs,
no new evidence exchange is opened. A canonical failed payload is retained when
the known decision and valid local clocks permit it. Broken clocks can prevent
canonical evidence construction; that failure never permits outward success.

Admission `succeeded` describes successfully validated/filtered output ready for
the required evidence gate, not HTTP response completion. Receipt acceptance is
required before outward success. Failed evidence never exposes the prepared output.

The original overall deadline is unchanged. Evidence starts at a fresh actual
local attempt sample, with its deadline clamped by the typed client to the earlier
of five seconds from that attempt and the original overall deadline.

Authorization/upstream stages use raw-owner monotonic result boundaries, not
physical-close times. Wall presentation for those stages is reconstructed from
the intersection of the original/observed microsecond quantization intervals;
the exact nanosecond offsets and durations are preserved. This does not recover
unknown submicrosecond wall phase or claim UTC accuracy. Output validation and
filtering use local snapshots. Missing boundaries are omitted or marked missing,
not invented zero-duration stages. Real equal clock samples may measure zero.

Admission cannot measure its own commit, response finish/abort or cleanup.
Distinct admission/completion event IDs link the later response owner; completion
context retains actual evidence and raw closure observations separately. This
slice emits no completion event and never fabricates an HTTP finish timestamp.

| Counter | Exact meaning |
| --- | --- |
| `inputBytes` | UTF-8 JSON of the copied prepared input |
| `sourceBytes` | UTF-8 JSON of the copied structured portfolio after envelope/resource validation; retained even if filtering then fails |
| `filteredBytes` | UTF-8 JSON of the completed allowlisted public view, or zero when filtering did not complete within the valid budget |
| `outputBytes` | UTF-8 JSON of the new safe MCP result for a successful admission candidate; zero for failed/denied outcomes |

Unreached/unvalidated source measurement is zero, not an assertion that no network
bytes arrived. None of these counts includes HTTP, JSON-RPC framing, TLS or bytes
physically written. `removedFields` means acknowledged explicit policy restrictions
reported by the existing filter, not every unknown/default-private field omitted.

The focused tests cover actual compiled/raw/business/evidence dependencies and a
native guard/TLS/HTTP/MCP session path with explicitly synthetic loopback fixtures.
Their controlled evidence transport is not real EventIngest/NATS durability,
enrollment, protected network provenance, production activation or full Task 5.
