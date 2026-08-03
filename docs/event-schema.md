# Apex v1 event contract

`contracts/proto/apex/v1/event.proto` is the wire-contract source. The checked-in JSON Schema at `contracts/jsonschema/apex/v1/event.schema.json` is its JSON validation companion. Both use the same field names and v1 event-type vocabulary.

## Compatibility

Within a major schema version, producers may add optional data fields only. They must not change the meaning, type, or required status of an existing field. Consumers must ignore unknown data fields. Envelope fields are closed: additions require a schema-version increment. A breaking change creates `apex.v2`.

## Validation and limits

Validate before enqueueing. Reject malformed envelopes rather than silently repairing them. Production scope identifiers, actor and version fields are required. Identifiers are UTF-8 strings of 1–256 characters; an event contains at most 128 AgentGroup identifiers.

Payload limits are enforced by the ingest service: 256 KiB for the complete JSON envelope and 32 KiB for any captured text field. SDKs may truncate captured text only at UTF-8 character boundaries and append `…[truncated]`; they must include the original SHA-256 in a sibling `*_sha256` field. Arguments and raw tool results are never silently dropped.

## Prompt-injection boundary

Event identifiers are restricted to 1-256 ASCII letters, digits, `.`, `_`, `:`, or `-`; they are metadata, never instructions. `control.inject` content is capped at 32 KiB UTF-8 and always carries `content_classification: "untrusted"`. A runtime adapter must never concatenate that content into a system or developer prompt, or use it as authorization; it may process it only as untrusted data under explicit policy.

## Integrity and archive bytes

`event_hash` is SHA-256 of the RFC 8785 JSON Canonicalization Scheme (JCS) serialization of the whole envelope after omitting `integrity.event_hash`. `prev_hash` is the preceding event hash for the same run, or `null` for its first event. In Protobuf, an omitted `prev_hash` is normalized to JSON `null` before hashing. The archive-provider API accepts the validated Protobuf envelope at its transport boundary, then stores the complete JCS-serialized envelope followed by a single LF byte as the canonical evidence representation. Provider manifests record the input event hash and the hash of the exact stored bytes. Do not hash the LF byte.

All timestamps are RFC 3339 UTC strings ending in `Z`; emitters use microsecond precision. New events use lowercase UUIDv7 values. UUID version is validated at the API boundary because protobuf strings cannot encode that constraint.

## Telemetry export

Apex events are canonical. OpenTelemetry GenAI attributes are an optional, one-way interoperability export and cannot replace or reconstruct the envelope. The SDK maps Apex identity into `apex.*` attributes and maps supported LLM operation, provider, model, and input/output token fields into `gen_ai.*` attributes. Unmapped OpenTelemetry fields must not be backfilled into the canonical event.

## Control semantics

V1 supports `stop`, `pause`, `resume`, `inject`, and `set_budget` only as cooperative controls. The runtime receives a request and chooses a documented safe boundary at which to honor it; Apex does not claim that a running process has been preempted. `control` event data must include `action`, `enforcement: "cooperative"`, `reason_code`, and action-specific parameters. Injection text is always marked `content_classification: "untrusted"`. Forced termination is out of scope until process isolation and its safety model are available.
