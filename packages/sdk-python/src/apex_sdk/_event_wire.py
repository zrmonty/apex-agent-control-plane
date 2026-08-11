"""``apex.v1.EventEnvelope`` and ``google.protobuf.Struct`` wire encoding.

Split out of ``ingest_transport.py``: this half is the pure encode/decode
layer -- a validated event dict in, wire bytes out (and the small amount of
response decoding the other direction needs) -- with no dependency on the
gRPC channel, credentials, or ``GrpcEventIngestTransport`` class that module
still owns. It mirrors ``control_transport``'s own decoder/transport split
(see ``_struct_wire.py``).

``EventEncodingError`` moves with it because the encoder is what raises
nearly every variant of it; keeping the error class next to the code that
constructs it avoids a circular import with ``ingest_transport``, which
imports the encoder back. Everything ``ingest_transport.py`` (and its tests)
import by name -- ``EventEncodingError``, the encode/decode entry points, the
enum tables, and the size ceilings -- is re-imported there, so
``apex_sdk.ingest_transport.X`` continues to resolve exactly as before the
split.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .control_transport import MAX_STRUCT_DEPTH, MAX_STRUCT_ENTRIES, _read_field
from .errors import ApexError
from .exporter import GrpcStatusError

#: Fully-qualified method name. Must match ``contracts/proto/apex/v1/event.proto``.
INGEST_METHOD = "/apex.v1.EventIngest/Ingest"

#: The gateway's own ceiling (``apex_event_ingest::MAX_ENVELOPE_BYTES``). An
#: envelope larger than this is refused by ``event-ingest`` before it is looked
#: at, and the attempt is recorded as an admission-abuse security signal -- so
#: refusing it locally turns a wasted round trip and a security finding into an
#: error the caller can act on.
MAX_ENVELOPE_BYTES = 256 * 1024

#: ``apex.v1.EventType``. Keys are the canonical JSON/JCS spellings the event
#: hash is computed over; values are the protobuf wire values. Checked against
#: ``contracts/proto/apex/v1/event.proto`` by the test suite, because a wrong
#: entry here would produce an envelope the gateway hashes differently -- a
#: rejection whose cause would be invisible from either side alone.
EVENT_TYPE_VALUES = {
    "turn_start": 1,
    "llm": 2,
    "tool": 3,
    "message": 4,
    "memory": 5,
    "decision": 6,
    "workflow": 7,
    "agent_spawn": 8,
    "control": 9,
    "score": 10,
    "turn_end": 11,
    "error": 12,
}

#: ``apex.v1.ActorType``, same reasoning as above.
ACTOR_TYPE_VALUES = {
    "user": 1,
    "agent": 2,
    "system": 3,
    "schedule": 4,
}

#: JSON numbers are IEEE-754 doubles, so only integers in this range survive a
#: ``google.protobuf.Struct`` round trip unchanged. ``rfc8785`` refuses anything
#: outside it while hashing, so an event that reached this module already
#: satisfies the bound; this constant is the encoder declining to be the place
#: where that invariant is first broken, not a new restriction.
MAX_EXACT_INTEGER = 2**53 - 1

_WIRE_VARINT = 0
_WIRE_FIXED64 = 1
_WIRE_LENGTH = 2


class EventEncodingError(ApexError):
    """An event could not be faithfully encoded for the ingest wire format.

    Never retryable: the input is the problem, and re-sending the same dict
    produces the same answer. Always raised *before* any network request, so an
    event that fails this has definitively not been submitted and has consumed
    no idempotency slot at the gateway.
    """

    code = "EVENT_ENCODE_FAILED"
    category = "contract"
    retryable = False
    safe_message = "The event could not be encoded for ingest."
    cause = "The event cannot be represented in the v1 wire format without changing its meaning."
    recommended_next_steps = (
        "Confirm the event was produced by EventBuilder and passes validate_event.",
        "Confirm event data holds only JSON values inside the JCS numeric domain.",
    )


# Kept as a private negative-input guard for existing callers/tests. Message
# serialization itself is performed only by the generated protobuf classes.
def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise EventEncodingError(cause="A negative value cannot be encoded as a protobuf varint.")
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


# --------------------------------------------------------------------------
# apex.v1.EventEnvelope
# --------------------------------------------------------------------------


def _require_mapping(event: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = event.get(name)
    if not isinstance(value, Mapping):
        raise EventEncodingError(cause=f"The event's {name} must be an object.")
    return value


def _validate_ingest_response_wire(buffer: bytes) -> None:
    offset = 0
    while offset < len(buffer):
        field, wire, _raw, offset = _read_field(buffer, offset)
        if field == 1 and wire != _WIRE_VARINT:
            raise GrpcStatusError("UNKNOWN", "ingest response duplicate flag used the wrong wire type")


def _generated_event_pb2() -> Any:
    try:
        from ._generated.apex.v1 import event_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise EventEncodingError(
            cause="Install the ingest transport's protobuf runtime before sending events.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[ingest]'",),
        ) from exc
    return event_pb2


def _generated_struct_pb2() -> Any:
    try:
        from google.protobuf import struct_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise EventEncodingError(
            cause="Install the ingest transport's protobuf runtime before sending events.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[ingest]'",),
        ) from exc
    return struct_pb2


def _generated_struct_value(value: Any, depth: int) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    struct_pb2 = _generated_struct_pb2()
    result = struct_pb2.Value()
    if value is None:
        result.null_value = 0
    elif isinstance(value, bool):
        result.bool_value = value
    elif isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER:
            raise EventEncodingError(cause="An integer in event data cannot survive the protobuf double conversion.")
        result.number_value = float(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise EventEncodingError(cause="Event data numbers must be finite.")
        result.number_value = value
    elif isinstance(value, str):
        result.string_value = value
    elif isinstance(value, Mapping):
        result.struct_value.CopyFrom(_generated_struct(value, depth + 1))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_STRUCT_ENTRIES:
            raise EventEncodingError(cause="An array in event data holds more entries than this client encodes.")
        result.list_value.values.extend(_generated_struct_value(item, depth + 1) for item in value)
    else:
        raise EventEncodingError(cause="A value in event data is not JSON-compatible.")
    return result


def _generated_struct(fields: Mapping[str, Any], depth: int = 0) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    if not isinstance(fields, Mapping):
        raise EventEncodingError(cause="Event data must be an object.")
    if len(fields) > MAX_STRUCT_ENTRIES:
        raise EventEncodingError(cause="An object in event data holds more entries than this client encodes.")
    result = _generated_struct_pb2().Struct()
    for key, value in fields.items():
        if not isinstance(key, str):
            raise EventEncodingError(cause="Event data object keys must be strings.")
        result.fields[key].CopyFrom(_generated_struct_value(value, depth + 1))
    return result


def encode_struct(fields: Mapping[str, Any], depth: int = 0) -> bytes:
    """Encodes a JSON-like mapping with the generated Struct message."""
    return _generated_struct(fields, depth).SerializeToString(deterministic=True)


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EventEncodingError(cause=f"{label} must be a string.")
    return value


def encode_event_envelope(event: Mapping[str, Any]) -> bytes:
    """Encodes a validated Apex v1 event with the generated message class."""
    if not isinstance(event, Mapping):
        raise EventEncodingError(cause="An event must be an object.")
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPE_VALUES:
        raise EventEncodingError(cause="The event type is not a member of the v1 EventType enum.")
    scope = _require_mapping(event, "scope")
    actor = _require_mapping(event, "actor")
    version = _require_mapping(event, "version")
    integrity = _require_mapping(event, "integrity")
    actor_type = actor.get("type")
    if not isinstance(actor_type, str) or actor_type not in ACTOR_TYPE_VALUES:
        raise EventEncodingError(cause="The event actor type is not a member of the v1 ActorType enum.")
    schema_version = event.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or not 0 <= schema_version <= 0xFFFFFFFF:
        raise EventEncodingError(cause="schema_version must be a uint32.")
    agent_group_ids = scope.get("agent_group_ids")
    if not isinstance(agent_group_ids, list):
        raise EventEncodingError(cause="scope.agent_group_ids must be an array.")

    event_pb2 = _generated_event_pb2()
    envelope = event_pb2.EventEnvelope(
        event_id=_required_string(event.get("event_id"), "event_id"),
        timestamp=_required_string(event.get("timestamp"), "timestamp"),
        type=EVENT_TYPE_VALUES[event_type],
        agent_id=_required_string(event.get("agent_id"), "agent_id"),
        run_id=_required_string(event.get("run_id"), "run_id"),
        trace_id=_required_string(event.get("trace_id"), "trace_id"),
        schema_version=schema_version,
    )
    parent_run_id = event.get("parent_run_id")
    if parent_run_id is not None:
        envelope.parent_run_id = _required_string(parent_run_id, "parent_run_id")
    envelope.scope.workspace_id = _required_string(scope.get("workspace_id"), "scope.workspace_id")
    envelope.scope.namespace_id = _required_string(scope.get("namespace_id"), "scope.namespace_id")
    for group in agent_group_ids:
        envelope.scope.agent_group_ids.append(_required_string(group, "scope.agent_group_ids[]"))
    envelope.actor.type = ACTOR_TYPE_VALUES[actor_type]
    envelope.actor.id = _required_string(actor.get("id"), "actor.id")
    envelope.version.agent_code = _required_string(version.get("agent_code"), "version.agent_code")
    envelope.version.prompt = _required_string(version.get("prompt"), "version.prompt")
    envelope.version.model = _required_string(version.get("model"), "version.model")
    prev_hash = integrity.get("prev_hash")
    if prev_hash is not None:
        envelope.integrity.prev_hash = _required_string(prev_hash, "integrity.prev_hash")
    envelope.integrity.event_hash = _required_string(integrity.get("event_hash"), "integrity.event_hash")
    data = event.get("data")
    if not isinstance(data, Mapping):
        raise EventEncodingError(cause="The event's data must be an object.")
    # event_pb2 uses a private descriptor pool because event.proto and
    # control.proto currently declare the same apex.v1.ControlAction enum.
    # The wire contract for google.protobuf.Struct is identical; crossing the
    # pool boundary through serialized bytes keeps the generated message type
    # authoritative without importing a second Struct class into the SDK.
    envelope.data.ParseFromString(_generated_struct(data).SerializeToString(deterministic=True))
    payload = envelope.SerializeToString(deterministic=True)
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise EventEncodingError(
            "The encoded event is larger than ingest accepts.",
            correlation={"event_id": str(event.get("event_id", ""))},
            cause="The encoded envelope exceeded the gateway's 256 KiB admission ceiling.",
            recommended_next_steps=("Reduce the size of the event's data payload before exporting it.",),
        )
    return payload


def decode_ingest_response(buffer: bytes) -> bool:
    if hasattr(buffer, "duplicate"):
        return bool(buffer.duplicate)
    if not isinstance(buffer, (bytes, bytearray)):
        raise GrpcStatusError("UNKNOWN", "ingest response was not bytes")
    buffer = bytes(buffer)
    if len(buffer) > MAX_ENVELOPE_BYTES:
        raise GrpcStatusError("UNKNOWN", "ingest response exceeded the client's read ceiling")
    try:
        _validate_ingest_response_wire(buffer)
        return _generated_event_pb2().IngestResponse.FromString(buffer).duplicate
    except Exception as exc:  # protobuf DecodeError is version-dependent
        raise GrpcStatusError("UNKNOWN", "ingest response was not well-formed protobuf") from exc


def _extract_data_field(payload: bytes) -> bytes:
    """Returns the bytes of field 11 (``data``) from an encoded envelope.

    Reads the encoded form rather than trusting the value that was passed to the
    encoder: the point of the check this feeds is to inspect what is actually
    about to be transmitted.
    """
    offset = 0
    body = b""
    while offset < len(payload):
        field_number, wire_type, value, offset = _read_field(payload, offset)
        if field_number == 11 and wire_type == _WIRE_LENGTH:
            body = bytes(value)
    return body
