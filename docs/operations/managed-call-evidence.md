# Managed MCP call evidence

This is the canonical evidence component for the managed gateway, not a claim
that the production serving factory or complete tracing pipeline is enabled.
Production wiring must join the protected installation, published revision,
enrolled evidence identity, guarded endpoint and physically owned call first.

## Admission and completion

Allocate a distinct UUIDv7 event ID for admission and completion once per call.
Each envelope links to its partner through `data.linked_event_id`. The admission
event records the business outcome available before the outward response. It
cannot claim its own durable commit, response finish/abort, or final cleanup.
The later completion event may record those measured stages. An absent
completion is partial evidence, never an invented zero-duration success.

`ManagedEvidenceBuilder.prepare()` produces a frozen event-ID/hash handle backed
by module-owned protobuf bytes. Copies of the handle are not sendable handles.
`ManagedEvidenceClient.start()` accepts only a genuine prepared handle and uses
the separate evidence channel's fixed `/apex.v1.EventIngest/Ingest` method.
No governance proof metadata or caller-selected RPC method is emitted.

The typed result contains the submitted event ID and canonical hash plus the
server's `duplicate` flag. A valid duplicate is an acknowledgement of the same
durably accepted event, not permission to repeat an upstream business call.
There is no automatic retry. An explicit retry reuses the original handle,
bytes, event IDs, observed time and hash; its bounded attempt must still fit
the original overall operation deadline.

The result and `closed` promises have different meanings. Receipt validation
does not prove stream cleanup. Cancelled or completed jobs retain capacity and
owned payload buffers until the original native stream closes. The typed owner
does not close the root's shared evidence channel. Uncertain physical closure
does not manufacture a drain receipt.

## Wire format and integrity

The frozen `event.proto` is generated separately as `@apex/contracts/event`.
Its legacy `ControlAction` namespace must not be merged into the management
descriptor. The generated event service is not a browser RPC. The generator's
inventory and verification cover both isolated artifact trees.

Envelopes use `TOOL`, an `AGENT` actor, the enrolled evidence agent ID, the call
UUID as `run_id`, and the true 32-hex OTel ID in the envelope's `trace_id` field.
The trace ID is not duplicated into generic `data`: the incumbent secret
scanner correctly treats opaque payload strings conservatively. Do not weaken
that scanner to accommodate redundant correlation data.

The integrity hash is SHA-256 of the existing RFC 8785/JCS representation:
snake-case envelope fields; lowercase `tool` and `agent` enum names; omitted
`parent_run_id` and `integrity.prev_hash` represented as JSON null; and no
`integrity.event_hash` inside its own hash input. Generated protobuf enums and
field names are transport details, not a different canonical hash algorithm.

The fixed `data` schema includes:

| Group | Fields |
| --- | --- |
| Identity | `kind=mcp_proxy_call`, `schema_version=1`, `phase`, paired event ID, full installation/scope/proxy/revision/generation/fence/process binding and configuration/launch hashes |
| Business | call ID, known admission ID when allowed, verified principal, evidence agent, tool/action/resource/argument hash, classification, business status |
| Policy | outcome, policy ID, exact revision, reason code, field restrictions |
| Filtering | bounded input/source/filtered/output byte counts and removed field names |
| Timing | root span ID, process clock domain, source/resolution/optional uncertainty, start/observed Unix microseconds, local elapsed nanoseconds/microseconds, measured stages |

No raw arguments, upstream output, authorization headers, credentials, or tool
secret values belong in the event. The builder rejects active object containers
and unknown top-level fields rather than invoking accessors or coercions.
Its defensive binding comparisons do not authenticate its caller or replace
deployment provenance checks at the real composition root.

## Exact timing and bounds

All time values inside protobuf `Struct` are decimal strings. Integer `BigInt`
arithmetic computes same-process elapsed nanoseconds and floor-microseconds.
Unix time is not narrowed through JavaScript `Number`; RFC 3339 timestamps retain
exactly six fractional digits. Do not subtract wall clocks from different
processes or label storage precision as actual clock accuracy.

Stages have distinct names and 16-hex span IDs, a previously established parent,
bounded local start/end times, and `ok`, `error` or `missing` status. Missing
durations are omitted. Admission cannot include post-admission stage names.

Limits are 32 stage aggregates, 64 KiB per encoded envelope, 32 physically owned
typed sends, 8 KiB per receipt and five seconds per attempt, capped by its
original overall deadline. Deadline checks occur before dispatch and after
receipt decoding; an overdue callback cannot beat its timer. The typed receipt
decoder refuses unknown, duplicate and noncanonical protobuf bytes.

## Verification

Focused TypeScript tests are in `src/managed/evidence/*.test.ts` under the gateway.
Contract isolation is exercised by `contracts/tests/event-isolation.test.mjs`.
The opt-in Rust test `managed_evidence_typescript_client_durable_microseconds`
starts the actual authenticated mTLS ingest service, launches the real TypeScript
builder/channel/client, verifies initial and duplicate receipts, stops the
server and reopens its fsync-backed journal. It verifies 1/7/999 microseconds and
Unix values beyond 2^53 against Rust's independent canonical hash implementation.

Set `APEX_MCP_EVIDENCE_NODE` to the Node executable and
`APEX_BROWSER_TEST_PKI_DIR` to the existing trusted-host test PKI directory.
The default probe uses the gateway's installed `tsx` and test script. For Linux
verification, `APEX_MCP_EVIDENCE_PROBE` can name its explicitly built bundle.
These are test-only process settings; they are not production bootstrap seams.
Without the opt-in Node setting the test reports its skip, which is not evidence
of cross-language acceptance. Both Windows and isolated Linux runs have passed.

This proof covers canonical durable admission, not PostgreSQL Activity
projection, JetStream delivery, cross-service span completeness, UI trace
queries, production enrollment-file provenance or deployment readiness. Those
remain separate acceptance gates.
