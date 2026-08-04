# How to connect an external agent for event ingestion

This guide describes the external ingestion boundary for agent logs and telemetry.

The wire contract is the authenticated gRPC method `apex.v1.EventIngest.Ingest` in [`contracts/proto/apex/v1/event.proto`](../contracts/proto/apex/v1/event.proto).

> **Phase 0 status:** The Rust authenticated gRPC service boundary, envelope validation, and durable publisher seams are implemented and tested. Lab and gateway-ref paths can run a gateway. Hardened production Compose still needs operator-owned digest-pinned images.

Day-one paths: [Getting started](getting-started.md).

## 1. Expose only the authenticated gRPC gateway

1. Create a private DNS name such as `ingest.example.internal`.
2. Expose only the gateway TLS port through the approved API gateway or load balancer.
3. Do not expose NATS, ClickHouse, archive storage, or their monitoring ports to agents or the public internet.

The gateway process must:

1. Terminate TLS with a certificate that matches the ingest DNS name.
2. Prefer workload mTLS for agent identity. If you use the Phase 0 file-bearer gateway, set a unique `APEX_BEARER_AGENT_ID` and `APEX_BEARER_CERT_SHA256` for each credential/certificate pair. The gateway fails closed without those bindings and rejects the token when presented by another trusted certificate. It accepts only matching `agent_id` or AGENT actor events. Delegated actor identities need a separate resolver.
3. Construct `AuthenticatedGrpcService` and publish through the persistent outbox and durable fanout (`JetStream → ClickHouse → archive`).
4. Use `bounded_event_ingest_server`. It rejects encoded messages larger than 256 KiB before protobuf admission work.
5. Apply network rate limits, connection limits, and request deadlines at the edge. Keep internal NATS, ClickHouse, and archive addresses private.

When bearer auth is enabled, the service accepts exactly one ASCII `Authorization: Bearer <token>` metadata value. Tokens are limited to 4,096 bytes. Tokens must not contain whitespace or control characters. Duplicate authorization metadata is rejected.

## 2. Generate a client from the contract

Generate the client and message types from the versioned Protobuf contract. Do not hand-build a JSON or REST equivalent for ingestion. Protobuf field names and validation are part of the compatibility contract.

Python example:

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

The Python SDK supplies event construction, validation, canonical hashing, and a bounded exporter seam. A production transport adapter must implement that seam with the generated gRPC client. It must not log bearer tokens, raw gRPC error text, or event payloads.

## 3. Build a valid log event

Select an appropriate event type (`ERROR`, `MESSAGE`, `TOOL`, `LLM`, or `TURN_START` / `TURN_END`). Fill the required envelope fields:

- `event_id`: lowercase UUIDv7. Generate once. Keep it for retries.
- `timestamp`: UTC RFC 3339 with six fractional digits, ending in `Z`.
- `scope`: authorized `workspace_id` and `namespace_id`. Use only safe identifiers and approved `agent_group_ids`.
- `agent_id`, `run_id`, `trace_id`: stable safe identifiers for correlation.
- `actor`: one of `USER`, `AGENT`, `SYSTEM`, or `SCHEDULE`, plus its identifier.
- `version`: agent code, prompt revision identifier, and model identifier. Never put raw prompts or secrets in these fields.
- `data`: structured log content. Treat tool output, model text, and control injection content as untrusted data, not instructions.
- `schema_version`: `1`.
- `integrity`: `prev_hash` for the prior event in the run, or omit at the chain root, and the computed `event_hash`.

The full serialized envelope is limited to 256 KiB. Captured text fields are limited to 32 KiB. Redact secrets before construction. The ingest gateway does not repair, truncate, or reinterpret payloads.

`event_hash` is the SHA-256 of the RFC 8785/JCS canonical envelope with `integrity.event_hash` omitted. See [`docs/event-schema.md`](event-schema.md).

## 4. Handle acknowledgements and retries

Treat both responses as successful delivery:

- `duplicate = false`: this event ID was newly accepted.
- `duplicate = true`: the same event ID and identical payload were already accepted. Do not create a new ID only because this was a replay.

Retry only transient statuses (`UNAVAILABLE`, `DEADLINE_EXCEEDED`, and bounded capacity responses). Reuse the original event ID and a byte-identical payload.

Never retry a validation, authentication, authorization, or idempotency-conflict error without investigation. Reusing an accepted ID with changed bytes returns `IDEMPOTENCY_CONFLICT` or `INVALID_ARGUMENT`.

The server returns stable, redacted error codes with a summary, cause, and first recovery action. Use the event ID and diagnostic correlation. Do not rely on raw transport text.

## 5. Verify the deployment before agent onboarding

Before production logs:

1. Validate the gateway certificate chain and hostname from the agent network.
2. Confirm the workload identity or token maps only to the intended workspace and namespace.
3. Confirm rejection of invalid token, duplicate authorization header, invalid scope, oversized envelope, malformed timestamp, and changed-payload replay.
4. Confirm a valid event is visible in JetStream and configured sinks without exposing those services to the agent network.
5. Confirm diagnostic output contains no token, raw payload, secret, or untrusted text.

For a zero-credential local smoke test, use the [reference-agent path in Getting started](getting-started.md#a--local-first-trace).

Writing style: [ASD-STE100](writing-style-ste100.md).
