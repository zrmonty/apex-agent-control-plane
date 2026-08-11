"""Tests for the ``google.protobuf.Struct`` encoder in ``ingest_transport``.

Split out of a larger ``test_ingest_transport.py`` -- see
``test_ingest_transport_envelope.py``, ``test_ingest_transport_credentials.py``,
``test_ingest_transport_integrity.py``, and ``test_ingest_transport_live.py``
for the envelope encoder, credential loading, pre-send integrity guard, and
live in-process mTLS suites that used to share this file.

**The Struct encoder against the SDK's existing decoder.** This is the
mandatory property: ``control_transport._decode_struct`` was written first,
is already CI-proven against a real ``control-plane-api``, and knows nothing
about this encoder. Round-tripping through both proves the two agree with
*each other*, which is the only property that matters -- an encoder and a
decoder can each look right in isolation and still disagree about the wire.

The hand-rolled reader used to inspect what the encoder produced
(``_fields``/``_only``), and the ``_event``/``EVENT_ID`` test-event builder,
live in ``conftest.py``: most of this suite's split files need them.
"""

from __future__ import annotations

import datetime as dt
import math
import struct as _struct

import pytest

from apex_sdk.control_transport import MAX_STRUCT_DEPTH, MAX_STRUCT_ENTRIES, _decode_struct
from apex_sdk.event import event_hash
from apex_sdk.ingest_transport import (
    MAX_EXACT_INTEGER,
    EventEncodingError,
    encode_struct,
)
from conftest import _event, _fields, _only

ROUND_TRIP_CASES = [
    pytest.param({}, id="empty-object"),
    pytest.param({"s": "hello"}, id="string"),
    pytest.param({"s": ""}, id="empty-string"),
    pytest.param({"": "empty key is legal"}, id="empty-key"),
    pytest.param({"t": True, "f": False}, id="both-booleans"),
    pytest.param({"n": None}, id="null"),
    pytest.param({"f": 1.5, "neg": -2.25, "zero": 0.0}, id="floats"),
    pytest.param({"list": [1.0, "two", True, None, {"deep": 4.0}, []]}, id="heterogeneous-list"),
    pytest.param({"nested": {"a": {"b": {"c": "d"}}}}, id="nested-objects"),
    pytest.param({"unicode": "héllo 🌍 \u0000 tail"}, id="unicode-and-nul"),
    pytest.param({"big": float(MAX_EXACT_INTEGER)}, id="largest-exact-integer"),
    pytest.param({"tiny": 5e-324, "huge": 1.7976931348623157e308}, id="float-extremes"),
]


@pytest.mark.parametrize("payload", ROUND_TRIP_CASES)
def test_the_struct_encoder_and_the_sdk_decoder_agree(payload):
    """The mandatory property: encode(x) decoded by the *existing* decoder is x.

    ``_decode_struct`` predates this encoder, was written for ``PollCommands``,
    and has been exercised against a real Rust ``control-plane-api``. Nothing in
    it was changed for this module, so agreement between the two is evidence
    about the wire format rather than evidence that one file is self-consistent.
    """
    assert _decode_struct(encode_struct(payload)) == payload


def test_python_integers_round_trip_through_the_double_that_json_requires():
    """Integers come back as floats, and that is correct, not a defect.

    ``google.protobuf.Struct`` has one numeric kind and it is a double, exactly
    as JSON does. What matters for this project is not that ``5`` comes back as
    ``5`` but that ``5`` and ``5.0`` have the *same canonical form*, so the hash
    the gateway recomputes still matches. That is asserted here directly.
    """
    decoded = _decode_struct(encode_struct({"count": 5, "ratio": 2}))
    assert decoded == {"count": 5.0, "ratio": 2.0}
    assert event_hash(_event(data={"count": 5})) == event_hash(_event(data={"count": 5.0}))


def test_every_oneof_kind_is_emitted_even_when_it_holds_its_default_value():
    """The single easiest way to get a Struct encoder wrong.

    proto3 omits a scalar field holding its default -- but a member of a
    ``oneof`` is not omitted, because presence *is* the meaning. A ``Value``
    carrying ``null_value`` (enum 0) or ``bool_value: false`` that emitted
    nothing would decode as a ``Value`` with no ``kind`` set, which prost maps
    to ``None`` and ``event-ingest`` rejects as ``InvalidStructure``.
    """
    for payload, expected_field, expected_wire in (
        ({"k": None}, 1, 0),
        ({"k": False}, 4, 0),
        ({"k": 0.0}, 2, 1),
        ({"k": ""}, 3, 2),
        ({"k": {}}, 5, 2),
        ({"k": []}, 6, 2),
    ):
        entry = _only(encode_struct(payload), 1)
        value = _only(entry, 2)
        assert value != b"", f"{payload} encoded a Value with no kind set"
        assert [(field, wire) for field, wire, _ in _fields(value)] == [
            (expected_field, expected_wire)
        ], payload


def test_booleans_are_not_encoded_as_numbers():
    """``bool`` is a subclass of ``int``; testing ``int`` first would break this."""
    entry = _only(encode_struct({"k": True}), 1)
    assert _fields(_only(entry, 2))[0][0] == 4  # bool_value, not number_value
    entry = _only(encode_struct({"k": 1}), 1)
    assert _fields(_only(entry, 2))[0][0] == 2  # number_value


def test_a_number_is_a_little_endian_ieee754_double():
    entry = _only(encode_struct({"k": 1.5}), 1)
    raw = _only(_only(entry, 2), 2)
    assert raw == _struct.pack("<d", 1.5)


def test_map_entries_use_key_one_and_value_two():
    entry = _only(encode_struct({"key": "value"}), 1)
    assert _only(entry, 1) == b"key"
    assert _fields(_only(entry, 2))[0][0] == 3  # string_value


@pytest.mark.parametrize(
    "payload",
    [
        {"n": MAX_EXACT_INTEGER + 1},
        {"n": -(MAX_EXACT_INTEGER + 1)},
        {"n": 10**30},
    ],
)
def test_an_integer_that_cannot_survive_the_double_is_refused(payload):
    """Silently rounding it would be an integrity bug, not a rounding choice."""
    with pytest.raises(EventEncodingError) as caught:
        encode_struct(payload)
    assert caught.value.retryable is False


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_refused(value):
    with pytest.raises(EventEncodingError):
        encode_struct({"n": value})
    assert not math.isfinite(value)


@pytest.mark.parametrize(
    "payload",
    [
        {"b": b"bytes"},
        {"s": {1, 2}},
        {"d": dt.datetime(2026, 1, 1, tzinfo=dt.UTC)},
        {"nested": {"inner": object()}},
    ],
)
def test_a_value_with_no_json_representation_is_refused(payload):
    with pytest.raises(EventEncodingError):
        encode_struct(payload)


def test_a_non_string_key_is_refused():
    with pytest.raises(EventEncodingError):
        encode_struct({1: "one"})


def test_data_that_is_not_an_object_is_refused():
    with pytest.raises(EventEncodingError):
        encode_struct(["not", "an", "object"])  # type: ignore[arg-type]


def test_tuples_encode_as_arrays_because_that_is_what_they_canonicalize_to():
    assert _decode_struct(encode_struct({"k": (1.0, 2.0)})) == {"k": [1.0, 2.0]}


def test_the_encoder_refuses_what_the_decoder_would_refuse_to_read_back():
    """Encoder and decoder share one depth and entry ceiling, on purpose.

    The pre-send integrity check decodes what the encoder produced. An encoder
    that could emit something the decoder rejects would turn every such event
    into an unexplainable local failure instead of a clean refusal.
    """
    deep: dict = {"leaf": 1.0}
    for _ in range(MAX_STRUCT_DEPTH + 2):
        deep = {"nest": deep}
    with pytest.raises(EventEncodingError):
        encode_struct(deep)
    with pytest.raises(EventEncodingError):
        encode_struct({str(index): 1.0 for index in range(MAX_STRUCT_ENTRIES + 1)})
    with pytest.raises(EventEncodingError):
        encode_struct({"k": [1.0] * (MAX_STRUCT_ENTRIES + 1)})


def test_a_deeply_nested_list_is_bounded_too():
    deep: object = 1.0
    for _ in range(MAX_STRUCT_DEPTH + 2):
        deep = [deep]
    with pytest.raises(EventEncodingError):
        encode_struct({"k": deep})


def test_the_struct_encoder_refuses_to_start_below_the_depth_ceiling():
    with pytest.raises(EventEncodingError):
        encode_struct({}, MAX_STRUCT_DEPTH + 1)
