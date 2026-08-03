# How to connect an external agent for event ingestion

This guide describes the intended external ingestion boundary for agent logs and
telemetry. The wire contract is the authenticated `apex.v1.EventIngest.Ingest`
gRPC method defined in [`contracts/proto/apex/v1/event.proto`](../contracts/proto/apex/v1/event.proto).

> **Phase 0 status:** the Rust authenticated gRPC service boundary, envelope
> validation, and durable publisher seams are implemented and tested. A packaged
> ingest gateway binary and Compose service are not shipped yet. Until that
> deployment work is complete, an operator must embed the service library in a
> gateway process; the dependency Compose profile alone does not expose an
> ingestion endpoint.

## 1. Expose only the authenticated gRPC gateway

Create a private DNS name such as `ingest.example.internal` and expose only the
gateway's TLS port through the approved API gateway/load balancer. Do not expose
NATS, ClickHouse, archive storage, or their monitoring/admin ports to agents or
the public internet.

The gateway process must:

1. Terminate TLS with a certificate matching the ingest DNS name.
2. Prefer workload mTLS for agent identity; if bearer authentication is used,
   install a deployment-owned `BearerTokenResolver` that maps the token to the
   allowed workspace/namespace scopes.
3. Construct `AuthenticatedGrpcService` and publish through the configured
   durable fanout (`JetStream → ClickHouse → archive`).
4. Use `bounded_event_ingest_server`, which rejects encoded messages larger than
   256 KiB before protobuf admission work.
5. Apply network rate limits, connection limits, and request deadlines at the
   edge. Keep the gateway's internal NATS/ClickHouse/archive addresses private.

The service accepts exactly one ASCII `Authorization: Bearer <token>` metadata
value when bearer auth is enabled. Tokens are limited to 4,096 bytes and may not
contain whitespace/control characters. Duplicate authorization metadata is
rejected rather than choosing an ambiguous value.

## 2. Generate a client from the contract

Generate the client and message types from the versioned Protobuf contract. Do
not hand-build a JSON or REST equivalent for ingestion; Protobuf field names and
validation are part of the compatibility contract.

For Python, the generated client normally provides:

```python
channel = grpc.secure_channel("ingest.example.internal:443", tls_credentials)
stub = event_pb2_grpc.EventIngestStub(channel)
response = stub.Ingest(
    envelope,
    metadata=(("authorization", f"Bearer {token}"),),
    timeout=10.0,
)
if not response.duplicate:
    print("event accepted")
```

The repository's Python SDK supplies event construction, validation, canonical
hashing, and a bounded exporter seam. A production transport adapter should
implement that seam using the generated gRPC client; it must not log bearer
tokens, raw gRPC error text, or event payloads.

## 3. Build a valid log event

For an agent log, use an appropriate event type (`ERROR`, `MESSAGE`, `TOOL`,
`LLM`, or `TURN_START`/`TURN_END`) and populate the required envelope fields:

- `event_id`: lowercase UUIDv7; generate once and retain it for retries.
- `timestamp`: UTC RFC 3339 with six fractional digits, ending in `Z`.
- `scope`: the authorized `workspace_id` and `namespace_id`; include only valid
  safe identifiers and approved `agent_group_ids`.
- `agent_id`, `run_id`, `trace_id`: stable safe identifiers for correlation.
- `actor`: one of `USER`, `AGENT`, `SYSTEM`, or `SCHEDULE`, plus its identifier.
- `version`: agent code, prompt revision identifier, and model identifier. Never
  put raw prompts or secrets in these fields.
- `data`: structured log content. Treat tool output, model text, and control
  injection content as untrusted data, not instructions.
- `schema_version`: `1`.
- `integrity`: `prev_hash` for the prior event in the run, or omitted at the
  chain root, and the computed `event_hash`.

The complete serialized envelope is limited to 256 KiB. Captured text fields
are limited to 32 KiB by the event contract. Redact secrets before construction;
the ingest gateway intentionally does not repair, truncate, or reinterpret
payloads.

`event_hash` is the SHA-256 of the RFC 8785/JCS canonical envelope with
`integrity.event_hash` omitted. See [`docs/event-schema.md`](event-schema.md) for
the exact canonical representation and control-event rules.

## 4. Handle acknowledgements and retries

Treat both responses as successful delivery:

- `duplicate = false`: this event ID was newly accepted.
- `duplicate = true`: the same event ID and identical payload were already
  accepted; do not create a new ID merely because it was a replay.

Retry only transient statuses (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, and bounded
capacity responses). Reuse the original event ID and byte-identical payload.
Never retry a validation, authentication, authorization, or idempotency-conflict
error blindly. Reusing an accepted ID with changed bytes returns
`IDEMPOTENCY_CONFLICT`/`INVALID_ARGUMENT` and must be investigated.

The server returns stable, redacted error codes with a summary, cause, and first
recovery action. Use the event ID and diagnostic report correlation, not raw
transport text, when escalating an ingestion failure.

## 5. Verify the deployment before onboarding agents

Before sending production logs, verify:

1. The gateway certificate chain and hostname validation from the agent network.
2. The workload identity/token maps to the intended workspace and namespace only.
3. An invalid token, duplicate authorization header, invalid scope, oversized
   envelope, malformed timestamp, and changed-payload replay are all rejected.
4. A valid event is visible in JetStream and the configured downstream sinks in
   order, without exposing those services to the agent network.
5. Diagnostic output contains no token, raw payload, secret, or untrusted text.

For a zero-credential local smoke test, use the [reference-agent quickstart](../README.md#home-test-in-five-minutes). It exercises the SDK and safe JSONL trace without pretending that the not-yet-packaged external gateway is running.
