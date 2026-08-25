"""Bounded validation for the provider-facing ``apex.v1.EventEnvelope``."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass
from typing import Any

import rfc8785
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, struct_pb2

from .common import HASH, MAX_EVENT_BYTES, UUID_V7

MAX_STRUCT_DEPTH = 64
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")

EVENT_TYPES = {
    1: "turn_start",
    2: "llm",
    3: "tool",
    4: "message",
    5: "memory",
    6: "decision",
    7: "workflow",
    8: "agent_spawn",
    9: "control",
    10: "score",
    11: "turn_end",
    12: "error",
}
ACTOR_TYPES = {1: "user", 2: "agent", 3: "system", 4: "schedule"}


class EnvelopeValidationError(ValueError):
    """The provider request is not a valid v1 envelope."""


@dataclass(frozen=True)
class ValidatedEnvelope:
    event_id: str
    event_hash: str
    workspace_id: str
    namespace_id: str


def _field(
    message: descriptor_pb2.DescriptorProto,
    name: str,
    number: int,
    field_type: int,
    *,
    label: int = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL,
    type_name: str | None = None,
    proto3_optional: bool = False,
    oneof_index: int | None = None,
) -> None:
    field = message.field.add(
        name=name,
        number=number,
        label=label,
        type=field_type,
        proto3_optional=proto3_optional,
    )
    if type_name:
        field.type_name = type_name
    if oneof_index is not None:
        field.oneof_index = oneof_index


def _enum(file: descriptor_pb2.FileDescriptorProto, name: str, values: dict[str, int]) -> None:
    enum = file.enum_type.add(name=name)
    for value, number in values.items():
        enum.value.add(name=value, number=number)


def _build_descriptor() -> Any:
    """Build the small provider-side descriptor without copying generated SDK code."""
    file = descriptor_pb2.FileDescriptorProto(
        name="apex/v1/provider_event.proto",
        package="apex.v1",
        syntax="proto3",
        dependency=["google/protobuf/struct.proto"],
    )
    _enum(
        file,
        "EventType",
        {"EVENT_TYPE_UNSPECIFIED": 0, **{name.upper(): value for value, name in EVENT_TYPES.items()}},
    )
    _enum(
        file,
        "ActorType",
        {"ACTOR_TYPE_UNSPECIFIED": 0, **{name.upper(): value for value, name in ACTOR_TYPES.items()}},
    )

    scope = file.message_type.add(name="Scope")
    _field(scope, "workspace_id", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(scope, "namespace_id", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(
        scope,
        "agent_group_ids",
        3,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        label=descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED,
    )

    actor = file.message_type.add(name="Actor")
    _field(actor, "type", 1, descriptor_pb2.FieldDescriptorProto.TYPE_ENUM, type_name=".apex.v1.ActorType")
    _field(actor, "id", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    version = file.message_type.add(name="Version")
    _field(version, "agent_code", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(version, "prompt", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(version, "model", 3, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    integrity = file.message_type.add(name="Integrity")
    integrity.oneof_decl.add(name="_prev_hash")
    _field(
        integrity,
        "prev_hash",
        1,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        proto3_optional=True,
        oneof_index=0,
    )
    _field(integrity, "event_hash", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)

    envelope = file.message_type.add(name="EventEnvelope")
    envelope.oneof_decl.add(name="_parent_run_id")
    _field(envelope, "event_id", 1, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(envelope, "timestamp", 2, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(envelope, "type", 3, descriptor_pb2.FieldDescriptorProto.TYPE_ENUM, type_name=".apex.v1.EventType")
    _field(envelope, "agent_id", 4, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(envelope, "run_id", 5, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(
        envelope,
        "parent_run_id",
        6,
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING,
        proto3_optional=True,
        oneof_index=0,
    )
    _field(envelope, "trace_id", 7, descriptor_pb2.FieldDescriptorProto.TYPE_STRING)
    _field(envelope, "scope", 8, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name=".apex.v1.Scope")
    _field(envelope, "actor", 9, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name=".apex.v1.Actor")
    _field(envelope, "version", 10, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name=".apex.v1.Version")
    _field(
        envelope,
        "data",
        11,
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE,
        type_name=".google.protobuf.Struct",
    )
    _field(envelope, "integrity", 12, descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE, type_name=".apex.v1.Integrity")
    _field(envelope, "schema_version", 13, descriptor_pb2.FieldDescriptorProto.TYPE_UINT32)

    pool = descriptor_pool.DescriptorPool()
    pool.AddSerializedFile(struct_pb2.DESCRIPTOR.serialized_pb)
    return pool.Add(file).message_types_by_name["EventEnvelope"]


_EVENT_DESCRIPTOR = _build_descriptor()


def event_envelope_class() -> Any:
    """Return the generated-compatible dynamic ``EventEnvelope`` class."""
    return message_factory.GetMessageClass(_EVENT_DESCRIPTOR)


def _invalid() -> EnvelopeValidationError:
    return EnvelopeValidationError("The event envelope failed provider validation.")


def _valid_identifier(value: str) -> bool:
    return bool(SAFE_IDENTIFIER.fullmatch(value)) and ".." not in value


def _valid_timestamp(value: str) -> bool:
    raw = value.encode("ascii", "ignore")
    if len(value) != 27 or len(raw) != 27:
        return False
    if (
        raw[4] != ord("-")
        or raw[7] != ord("-")
        or raw[10] != ord("T")
        or raw[13] != ord(":")
        or raw[16] != ord(":")
        or raw[19] != ord(".")
        or raw[26] != ord("Z")
    ):
        return False
    digit_ranges = (raw[:4], raw[5:7], raw[8:10], raw[11:13], raw[14:16], raw[17:19], raw[20:26])
    if any(not part.isdigit() for part in digit_ranges):
        return False
    year = int(raw[:4])
    month = int(raw[5:7])
    day = int(raw[8:10])
    hour = int(raw[11:13])
    minute = int(raw[14:16])
    second = int(raw[17:19])
    days = {1: 31, 3: 31, 5: 31, 7: 31, 8: 31, 10: 31, 12: 31, 4: 30, 6: 30, 9: 30, 11: 30}
    if month == 2:
        max_day = 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    else:
        max_day = days.get(month, 0)
    return year != 0 and 1 <= day <= max_day and hour <= 23 and minute <= 59 and second <= 59


def _struct_to_json(value: Any, depth: int = 0) -> dict[str, Any]:
    if depth > MAX_STRUCT_DEPTH:
        raise _invalid()
    result: dict[str, Any] = {}
    for key, item in value.fields.items():
        result[key] = _value_to_json(item, depth + 1)
    return result


def _value_to_json(value: Any, depth: int) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise _invalid()
    kind = value.WhichOneof("kind")
    if kind == "null_value":
        return None
    if kind == "number_value":
        if not math.isfinite(value.number_value):
            raise _invalid()
        return value.number_value
    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "struct_value":
        return _struct_to_json(value.struct_value, depth + 1)
    if kind == "list_value":
        return [_value_to_json(item, depth + 1) for item in value.list_value.values]
    raise _invalid()


def validate_event_envelope(body: bytes, header_event_id: str, header_event_hash: str) -> ValidatedEnvelope:
    """Decode, validate identity, and recompute the v1 canonical event hash."""
    if not isinstance(body, bytes) or not body or len(body) > MAX_EVENT_BYTES:
        raise _invalid()
    if not UUID_V7.fullmatch(header_event_id) or not HASH.fullmatch(header_event_hash):
        raise _invalid()

    envelope = event_envelope_class()()
    try:
        envelope.ParseFromString(body)
    except Exception as exc:  # protobuf DecodeError differs across runtimes
        raise _invalid() from exc

    if envelope.event_id != header_event_id or not envelope.HasField("scope"):
        raise _invalid()
    if not _valid_timestamp(envelope.timestamp):
        raise _invalid()
    if envelope.schema_version != 1 or envelope.type not in EVENT_TYPES:
        raise _invalid()
    if not all(_valid_identifier(value) for value in (envelope.agent_id, envelope.run_id, envelope.trace_id)):
        raise _invalid()
    if envelope.HasField("parent_run_id") and not _valid_identifier(envelope.parent_run_id):
        raise _invalid()

    scope = envelope.scope
    if not _valid_identifier(scope.workspace_id) or not _valid_identifier(scope.namespace_id):
        raise _invalid()
    if len(scope.agent_group_ids) > 128 or len(set(scope.agent_group_ids)) != len(scope.agent_group_ids):
        raise _invalid()
    if any(not _valid_identifier(value) for value in scope.agent_group_ids):
        raise _invalid()

    if not envelope.HasField("actor") or envelope.actor.type not in ACTOR_TYPES:
        raise _invalid()
    if not _valid_identifier(envelope.actor.id):
        raise _invalid()
    if not envelope.HasField("version") or not all(
        _valid_identifier(value)
        for value in (envelope.version.agent_code, envelope.version.prompt, envelope.version.model)
    ):
        raise _invalid()
    if not envelope.HasField("data") or not envelope.HasField("integrity"):
        raise _invalid()

    integrity = envelope.integrity
    if integrity.event_hash != header_event_hash or not HASH.fullmatch(integrity.event_hash):
        raise _invalid()
    previous_hash = integrity.prev_hash if integrity.HasField("prev_hash") else None
    if previous_hash is not None and not HASH.fullmatch(previous_hash):
        raise _invalid()
    data = _struct_to_json(envelope.data)
    unsigned = {
        "event_id": envelope.event_id,
        "timestamp": envelope.timestamp,
        "type": EVENT_TYPES[envelope.type],
        "agent_id": envelope.agent_id,
        "run_id": envelope.run_id,
        "parent_run_id": envelope.parent_run_id if envelope.HasField("parent_run_id") else None,
        "trace_id": envelope.trace_id,
        "scope": {
            "workspace_id": scope.workspace_id,
            "namespace_id": scope.namespace_id,
            "agent_group_ids": list(scope.agent_group_ids),
        },
        "actor": {"type": ACTOR_TYPES[envelope.actor.type], "id": envelope.actor.id},
        "version": {
            "agent_code": envelope.version.agent_code,
            "prompt": envelope.version.prompt,
            "model": envelope.version.model,
        },
        "data": data,
        "integrity": {"prev_hash": previous_hash},
        "schema_version": envelope.schema_version,
    }
    try:
        expected = hashlib.sha256(rfc8785.dumps(unsigned)).hexdigest()
    except Exception as exc:  # rfc8785 uses version-specific exception classes
        raise _invalid() from exc
    if not hmac.compare_digest(expected, integrity.event_hash):
        raise _invalid()
    return ValidatedEnvelope(
        event_id=envelope.event_id,
        event_hash=integrity.event_hash,
        workspace_id=scope.workspace_id,
        namespace_id=scope.namespace_id,
    )
