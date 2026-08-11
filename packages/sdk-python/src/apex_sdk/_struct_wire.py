"""Hand-rolled ``google.protobuf.Struct`` wire-format decoder.

Split out of ``control_transport.py``: this half is self-contained (raw bytes
in, a ``dict`` out) and has no dependency on the gRPC transport class or
credential handling that module owns. It is kept here so that module can stay
focused on the ``PollCommands`` transport itself.

``ControlPollError`` moves with it because the decoder is what raises most of
its "malformed wire data" variants (``_malformed``) -- keeping the error class
next to the code that constructs it avoids a circular import between this
module and ``control_transport``, which imports the decoder back. Everything
defined here -- including the "private" wire helpers, which a couple of
existing tests reach into directly -- is re-exported from
``control_transport.py`` via a star-import against ``__all__`` below, so
``apex_sdk.control_transport.X`` continues to resolve exactly as before for
every existing caller and test.

See ``control_transport.py``'s module docstring for the broader context this
decoder exists to serve.
"""

from __future__ import annotations

from collections.abc import Mapping
import struct as _struct
from typing import Any

from .errors import ApexError

__all__ = [
    "MAX_STRUCT_DEPTH",
    "MAX_STRUCT_ENTRIES",
    "ControlPollError",
    "_decode_generated_struct",
    "_decode_generated_value",
    "_decode_struct",
    "_decode_struct_list",
    "_decode_struct_value",
    "_decode_struct_wire",
    "_decode_text",
    "_generated_struct_pb2",
    "_iter_fields",
    "_malformed",
    "_read_field",
    "_read_varint",
    "_require_wire",
    "_validate_struct_wire",
    "_validate_value_wire",
    "_WIRE_FIXED32",
    "_WIRE_FIXED64",
    "_WIRE_LENGTH",
    "_WIRE_VARINT",
]


class ControlPollError(ApexError):
    """A ``PollCommands`` call could not be completed.

    One class with distinct codes, mirroring ``exporter.ExportDeliveryError``
    rather than inventing a second error-handling style for this one module.
    """

    code = "CONTROL_POLL_FAILED"
    category = "control"
    retryable = True
    safe_message = "Pending control commands could not be retrieved."
    cause = "The control gateway did not answer the poll."
    recommended_next_steps = (
        "Check the control gateway endpoint health and network reachability.",
        "Confirm the agent workload certificate and credential are current.",
    )

    def __init__(
        self,
        message: str | None = None,
        *,
        correlation: Mapping[str, str] | None = None,
        code: str | None = None,
        category: str | None = None,
        retryable: bool | None = None,
        cause: str | None = None,
        recommended_next_steps: tuple[str, ...] | None = None,
        context: Mapping[str, str | int | bool] | None = None,
    ) -> None:
        super().__init__(
            message,
            correlation=correlation,
            cause=cause,
            recommended_next_steps=recommended_next_steps,
            context=context,
        )
        if code is not None:
            self.code = code
        if category is not None:
            self.category = category
        if retryable is not None:
            self.retryable = retryable


_WIRE_VARINT = 0
_WIRE_FIXED64 = 1
_WIRE_LENGTH = 2
_WIRE_FIXED32 = 5


def _read_varint(buffer: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(buffer):
            raise _malformed("a varint ran past the end of the message")
        # A varint longer than ten groups cannot be a valid 64-bit value, and
        # accepting one would let a malformed response spin here.
        if shift > 63:
            raise _malformed("a varint exceeded 64 bits")
        byte = buffer[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def _malformed(detail: str) -> ControlPollError:
    return ControlPollError(
        "The control gateway's response could not be decoded.",
        code="CONTROL_POLL_PROTOCOL_VIOLATION",
        retryable=False,
        cause=f"The response was not well-formed protobuf: {detail}.",
        recommended_next_steps=(
            "Verify the SDK and the control gateway are on the same contract version.",
        ),
    )


def _read_field(buffer: bytes, offset: int) -> tuple[int, int, Any, int]:
    """Reads one field. Returns ``(field_number, wire_type, value, offset)``.

    ``value`` is an ``int`` for varint/fixed fields and ``bytes`` for
    length-delimited ones.
    """
    tag, offset = _read_varint(buffer, offset)
    field_number = tag >> 3
    wire_type = tag & 0x07
    if field_number == 0:
        raise _malformed("field number 0 is not valid")
    if wire_type == _WIRE_VARINT:
        value, offset = _read_varint(buffer, offset)
        return field_number, wire_type, value, offset
    if wire_type == _WIRE_LENGTH:
        length, offset = _read_varint(buffer, offset)
        end = offset + length
        if length > len(buffer) or end > len(buffer):
            raise _malformed("a length-delimited field ran past the end of the message")
        return field_number, wire_type, buffer[offset:end], end
    if wire_type == _WIRE_FIXED64:
        if offset + 8 > len(buffer):
            raise _malformed("a 64-bit field ran past the end of the message")
        return field_number, wire_type, int.from_bytes(buffer[offset : offset + 8], "little"), offset + 8
    if wire_type == _WIRE_FIXED32:
        if offset + 4 > len(buffer):
            raise _malformed("a 32-bit field ran past the end of the message")
        return field_number, wire_type, int.from_bytes(buffer[offset : offset + 4], "little"), offset + 4
    # Wire types 3 and 4 are the deprecated group encoding; proto3 never emits
    # them, so a response containing one is not something to guess about.
    raise _malformed(f"unsupported wire type {wire_type}")


def _decode_text(value: Any, field: str) -> str:
    if not isinstance(value, (bytes, bytearray)):
        raise _malformed(f"{field} was not length-delimited")
    try:
        return bytes(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _malformed(f"{field} was not valid UTF-8") from exc


#: Ceilings on a decoded ``google.protobuf.Struct``.
#:
#: The gateway validates command parameters on the way in and the response is
#: already size-bounded, so neither of these should ever bind against a
#: cooperative gateway. They exist because the decoder is recursive and its
#: input arrives over the network: a nesting bound is what keeps a malformed or
#: hostile response from turning into a stack overflow in the agent process,
#: and an entry bound keeps one message from deciding how many objects this
#: client allocates. Refusing is correct here where skipping is correct for an
#: unknown *field*: an unknown field is a newer contract, an over-deep Struct
#: is not.
MAX_STRUCT_DEPTH = 8
MAX_STRUCT_ENTRIES = 128


def _decode_struct_value(buffer: bytes, depth: int) -> Any:
    """Decodes one ``google.protobuf.Value``.

    A `Value` is a oneof; proto3 encodes exactly one of its fields. Later
    fields win if a malformed message sets several, which is ordinary protobuf
    last-one-wins behaviour rather than a decision made here.
    """
    value: Any = None
    offset = 0
    while offset < len(buffer):
        field_number, wire_type, raw, offset = _read_field(buffer, offset)
        # The wire type is checked against the one the field is *declared*
        # with, not merely against what happens to be decodable. A
        # varint-encoded `number_value` would otherwise be reinterpreted as
        # the double with those bits -- a silently wrong budget limit rather
        # than a refused message.
        if field_number == 1:  # null_value, an enum
            _require_wire(wire_type, _WIRE_VARINT, "a Struct null value")
            value = None
        elif field_number == 2:  # number_value, a double
            _require_wire(wire_type, _WIRE_FIXED64, "a Struct number value")
            value = _struct.unpack("<d", int(raw).to_bytes(8, "little"))[0]
        elif field_number == 3:  # string_value
            _require_wire(wire_type, _WIRE_LENGTH, "a Struct string value")
            value = _decode_text(raw, "a Struct string value")
        elif field_number == 4:  # bool_value
            _require_wire(wire_type, _WIRE_VARINT, "a Struct bool value")
            value = raw != 0
        elif field_number == 5:  # struct_value
            _require_wire(wire_type, _WIRE_LENGTH, "a nested Struct")
            value = _decode_struct(bytes(raw), depth + 1)
        elif field_number == 6:  # list_value
            _require_wire(wire_type, _WIRE_LENGTH, "a Struct list")
            value = _decode_struct_list(bytes(raw), depth + 1)
        # Anything else is an unknown field; skipping is required protobuf
        # behaviour.
    return value


def _require_wire(actual: int, expected: int, field: str) -> None:
    if actual != expected:
        raise _malformed(f"{field} used the wrong wire type")


def _decode_struct_list(buffer: bytes, depth: int) -> list[Any]:
    if depth > MAX_STRUCT_DEPTH:
        raise _malformed("a Struct nested deeper than this client accepts")
    values: list[Any] = []
    offset = 0
    while offset < len(buffer):
        field_number, wire_type, raw, offset = _read_field(buffer, offset)
        if field_number != 1:
            continue
        _require_wire(wire_type, _WIRE_LENGTH, "a Struct list entry")
        if len(values) >= MAX_STRUCT_ENTRIES:
            raise _malformed("a Struct carried more entries than this client accepts")
        values.append(_decode_struct_value(bytes(raw), depth))
    return values


def _decode_struct_wire(buffer: bytes, depth: int = 0) -> dict[str, Any]:
    """Decodes ``google.protobuf.Struct`` into a plain ``dict``."""
    if depth > MAX_STRUCT_DEPTH:
        raise _malformed("a Struct nested deeper than this client accepts")
    fields: dict[str, Any] = {}
    offset = 0
    while offset < len(buffer):
        field_number, wire_type, raw, offset = _read_field(buffer, offset)
        if field_number != 1:  # `fields`, the map
            continue
        _require_wire(wire_type, _WIRE_LENGTH, "a Struct field entry")
        key: str | None = None
        entry_value: Any = None
        entry_offset = 0
        entry = bytes(raw)
        while entry_offset < len(entry):
            entry_field, entry_wire, entry_raw, entry_offset = _read_field(entry, entry_offset)
            if entry_field == 1:
                _require_wire(entry_wire, _WIRE_LENGTH, "a Struct field key")
                key = _decode_text(entry_raw, "a Struct field key")
            elif entry_field == 2:
                _require_wire(entry_wire, _WIRE_LENGTH, "a Struct field value")
                entry_value = _decode_struct_value(bytes(entry_raw), depth)
        if key is None:
            # proto3 omits an empty map key, and "" is a legal key. Treat a
            # missing one as the empty string exactly as a generated decoder
            # would, rather than dropping the entry.
            key = ""
        if key not in fields and len(fields) >= MAX_STRUCT_ENTRIES:
            raise _malformed("a Struct carried more entries than this client accepts")
        fields[key] = entry_value
    return fields


def _generated_struct_pb2() -> Any:
    try:
        from google.protobuf import struct_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise ControlPollError(
            "The control transport is missing its protobuf runtime.",
            code="CONTROL_POLL_CONFIGURATION_FAILED",
            retryable=False,
            cause="Install the control extra before using PollCommands.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[control]'",),
        ) from exc
    return struct_pb2


def _decode_generated_value(value: Any, depth: int) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise _malformed("a Struct nested deeper than this client accepts")
    kind = value.WhichOneof("kind")
    if kind is None or kind == "null_value":
        return None
    if kind == "number_value":
        return value.number_value
    if kind == "string_value":
        return value.string_value
    if kind == "bool_value":
        return value.bool_value
    if kind == "struct_value":
        return _decode_generated_struct(value.struct_value, depth + 1)
    if kind == "list_value":
        if len(value.list_value.values) > MAX_STRUCT_ENTRIES:
            raise _malformed("a Struct carried more entries than this client accepts")
        return [_decode_generated_value(item, depth + 1) for item in value.list_value.values]
    raise _malformed("a Struct contained an unknown value kind")


def _decode_generated_struct(message: Any, depth: int = 0) -> dict[str, Any]:
    if depth > MAX_STRUCT_DEPTH:
        raise _malformed("a Struct nested deeper than this client accepts")
    if len(message.fields) > MAX_STRUCT_ENTRIES:
        raise _malformed("a Struct carried more entries than this client accepts")
    return {key: _decode_generated_value(value, depth) for key, value in message.fields.items()}


def _validate_struct_wire(buffer: bytes, depth: int = 0) -> None:
    """Preflight the generated parser with the contract's declared wire types.

    Protobuf runtimes correctly preserve a known field encoded with an unknown
    wire type as an unknown field. This SDK treats that shape as a protocol
    violation instead of silently turning a malformed command parameter into
    an empty/default value, so the preflight only validates wire shape; the
    generated classes still perform all message decoding.
    """
    if depth > MAX_STRUCT_DEPTH:
        raise _malformed("a Struct nested deeper than this client accepts")
    offset = 0
    entries = 0
    while offset < len(buffer):
        field, wire, raw, offset = _read_field(buffer, offset)
        if field == 1:
            _require_wire(wire, _WIRE_LENGTH, "a Struct field entry")
            entries += 1
            if entries > MAX_STRUCT_ENTRIES:
                raise _malformed("a Struct carried more entries than this client accepts")
            entry_offset = 0
            while entry_offset < len(raw):
                entry_field, entry_wire, entry_raw, entry_offset = _read_field(bytes(raw), entry_offset)
                if entry_field == 1:
                    _require_wire(entry_wire, _WIRE_LENGTH, "a Struct field key")
                elif entry_field == 2:
                    _require_wire(entry_wire, _WIRE_LENGTH, "a Struct field value")
                    _validate_value_wire(bytes(entry_raw), depth)


def _validate_value_wire(buffer: bytes, depth: int) -> None:
    offset = 0
    while offset < len(buffer):
        field, wire, raw, offset = _read_field(buffer, offset)
        expected = {1: _WIRE_VARINT, 2: _WIRE_FIXED64, 3: _WIRE_LENGTH, 4: _WIRE_VARINT, 5: _WIRE_LENGTH, 6: _WIRE_LENGTH}.get(field)
        if expected is None:
            continue
        _require_wire(wire, expected, "a Struct value")
        if field == 5:
            _validate_struct_wire(bytes(raw), depth + 1)
        elif field == 6:
            list_offset = 0
            list_entries = 0
            while list_offset < len(raw):
                list_field, list_wire, list_raw, list_offset = _read_field(bytes(raw), list_offset)
                if list_field == 1:
                    _require_wire(list_wire, _WIRE_LENGTH, "a Struct list entry")
                    list_entries += 1
                    if list_entries > MAX_STRUCT_ENTRIES:
                        raise _malformed("a Struct carried more entries than this client accepts")
                    _validate_value_wire(bytes(list_raw), depth + 1)


def _decode_struct(buffer: bytes, depth: int = 0) -> dict[str, Any]:
    """Decodes a Struct with the checked-in generated protobuf runtime."""
    if not isinstance(buffer, (bytes, bytearray)):
        raise _malformed("the Struct body was not bytes")
    _validate_struct_wire(bytes(buffer), depth)
    try:
        message = _generated_struct_pb2().Struct.FromString(bytes(buffer))
    except Exception as exc:  # protobuf DecodeError is version-dependent
        raise _malformed("the Struct was not well-formed protobuf") from exc
    decoded = _decode_generated_struct(message, depth)
    # Some protobuf runtimes discard an otherwise valid map entry when the
    # entry carries an unknown field. The contract requires unknown fields to
    # be skipped, so retain the bounded wire adapter for that compatibility
    # case; ordinary Structs are decoded by the generated runtime above.
    if decoded or not any(field == 1 for field, _wire, _raw, _offset in _iter_fields(bytes(buffer))):
        return decoded
    return _decode_struct_wire(bytes(buffer), depth)


def _iter_fields(buffer: bytes):
    offset = 0
    while offset < len(buffer):
        field, wire, raw, offset = _read_field(buffer, offset)
        yield field, wire, raw, offset
