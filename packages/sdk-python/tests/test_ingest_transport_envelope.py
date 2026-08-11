"""Tests for the ``apex.v1.EventEnvelope`` encoder, the enum tables against
the frozen contract, and ``IngestResponse`` decoding.

Split out of a larger ``test_ingest_transport.py`` -- see
``test_ingest_transport.py`` for the Struct encoder,
``test_ingest_transport_credentials.py`` for credential loading,
``test_ingest_transport_integrity.py`` for the pre-send integrity guard, and
``test_ingest_transport_live.py`` for the live in-process mTLS suite.

Field by field, against hand-built expected bytes and against the frozen
contract in ``contracts/proto/apex/v1/event.proto`` (the enum tables are
parsed out of the ``.proto`` rather than restated, because a restated table
can drift).

The hand-rolled reader (``_fields``/``_only``/``_present``), the varint/tag
encoders, and the ``_event``/``EVENT_ID`` test-event builder live in
``conftest.py``: most of this suite's split files need them.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from apex_sdk.control_transport import _decode_struct
from apex_sdk.event import EventBuilder, event_hash
from apex_sdk.exporter import GrpcStatusError
from apex_sdk.ingest_transport import (
    ACTOR_TYPE_VALUES,
    EVENT_TYPE_VALUES,
    MAX_ENVELOPE_BYTES,
    EventEncodingError,
    decode_ingest_response,
    encode_event_envelope,
    _encode_varint,
)
from conftest import EVENT_ID, _event, _fields, _only, _present, _tag, _varint

REPO_ROOT = Path(__file__).resolve().parents[3]
EVENT_PROTO = REPO_ROOT / "contracts" / "proto" / "apex" / "v1" / "event.proto"


def _proto_enum(name: str) -> dict[str, int]:
    """Parses one enum out of the frozen contract file."""
    text = EVENT_PROTO.read_text(encoding="utf-8")
    body = re.search(rf"enum {name} \{{(.*?)\}}", text, re.S)
    assert body is not None, f"enum {name} not found in {EVENT_PROTO}"
    return {
        member.lower(): int(value)
        for member, value in re.findall(r"(\w+)\s*=\s*(\d+);", body.group(1))
        if not member.endswith("_UNSPECIFIED")
    }


def test_the_event_type_table_matches_the_frozen_contract():
    """A wrong value here would be invisible until the gateway rejected the hash."""
    assert EVENT_TYPE_VALUES == _proto_enum("EventType")


def test_the_actor_type_table_matches_the_frozen_contract():
    assert ACTOR_TYPE_VALUES == _proto_enum("ActorType")


def test_the_envelope_carries_every_declared_field_at_its_declared_number():
    event = _event()
    encoded = encode_event_envelope(event)
    assert _only(encoded, 1) == EVENT_ID.encode()
    assert _only(encoded, 2) == event["timestamp"].encode()
    assert _only(encoded, 3) == EVENT_TYPE_VALUES["turn_start"]
    assert _only(encoded, 4) == b"reference-agent"
    assert _only(encoded, 5) == b"run-1"
    assert _only(encoded, 7) == b"trace-1"
    scope = _only(encoded, 8)
    assert _only(scope, 1) == b"acme"
    assert _only(scope, 2) == b"prod"
    actor = _only(encoded, 9)
    assert _only(actor, 1) == ACTOR_TYPE_VALUES["agent"]
    assert _only(actor, 2) == b"reference-agent"
    version = _only(encoded, 10)
    assert (_only(version, 1), _only(version, 2), _only(version, 3)) == (
        b"sdk-test",
        b"p1",
        b"reference",
    )
    assert _decode_struct(_only(encoded, 11)) == {"note": "hello"}
    integrity = _only(encoded, 12)
    assert _only(integrity, 2).decode() == event["integrity"]["event_hash"]
    assert _only(encoded, 13) == 1


def test_the_chain_root_omits_prev_hash_rather_than_sending_an_empty_string():
    """``optional string`` -- absence is the chain root, "" is a bad hash."""
    encoded = encode_event_envelope(_event())
    assert not _present(_only(encoded, 12), 1)


def test_a_chained_event_carries_its_predecessor_hash():
    builder = EventBuilder(
        agent_id="reference-agent",
        run_id="run-1",
        trace_id="trace-1",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        actor={"type": "agent", "id": "reference-agent"},
        version={"agent_code": "sdk-test", "prompt": "p1", "model": "reference"},
    )
    first = builder.build("turn_start", {}, event_id=EVENT_ID)
    second = builder.build("turn_end", {}, event_id="018f5c91-2d88-7c00-8000-0000000000ab")
    integrity = _only(encode_event_envelope(second), 12)
    assert _only(integrity, 1).decode() == first["integrity"]["event_hash"]


def test_data_is_always_present_even_when_it_is_empty():
    """The gateway refuses an envelope with no ``data`` field at all."""
    encoded = encode_event_envelope(_event(data={}))
    assert _present(encoded, 11)
    assert _only(encoded, 11) == b""


def test_an_absent_parent_run_id_is_omitted_and_a_present_one_is_sent():
    assert not _present(encode_event_envelope(_event()), 6)
    event = _event()
    event["parent_run_id"] = "run-0"
    event["integrity"]["event_hash"] = event_hash(event)
    assert _only(encode_event_envelope(event), 6) == b"run-0"


def test_agent_group_ids_are_repeated_in_order():
    event = _event()
    event["scope"]["agent_group_ids"] = ["alpha", "beta"]
    event["integrity"]["event_hash"] = event_hash(event)
    scope = _only(encode_event_envelope(event), 8)
    assert [value for field, _wire, value in _fields(scope) if field == 3] == [b"alpha", b"beta"]


@pytest.mark.parametrize("event_type", sorted(EVENT_TYPE_VALUES))
def test_every_event_type_encodes_to_its_contract_value(event_type):
    event = _event()
    event["type"] = event_type
    assert _only(encode_event_envelope(event), 3) == EVENT_TYPE_VALUES[event_type]


@pytest.mark.parametrize("actor_type", sorted(ACTOR_TYPE_VALUES))
def test_every_actor_type_encodes_to_its_contract_value(actor_type):
    event = _event()
    event["actor"]["type"] = actor_type
    actor = _only(encode_event_envelope(event), 9)
    assert _only(actor, 1) == ACTOR_TYPE_VALUES[actor_type]


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda event: event.update(type="not-a-type"), id="unknown-type"),
        pytest.param(lambda event: event.update(type=3), id="numeric-type"),
        pytest.param(lambda event: event["actor"].update(type="robot"), id="unknown-actor-type"),
        pytest.param(lambda event: event.update(scope="acme/prod"), id="scope-not-object"),
        pytest.param(lambda event: event.update(actor=None), id="actor-missing"),
        pytest.param(lambda event: event.update(version=[]), id="version-not-object"),
        pytest.param(lambda event: event.update(integrity="deadbeef"), id="integrity-not-object"),
        pytest.param(lambda event: event.update(data=["a"]), id="data-not-object"),
        pytest.param(lambda event: event.update(schema_version="1"), id="schema-version-not-int"),
        pytest.param(lambda event: event.update(schema_version=True), id="schema-version-bool"),
        pytest.param(lambda event: event.update(schema_version=-1), id="schema-version-negative"),
        pytest.param(lambda event: event.update(event_id=7), id="event-id-not-string"),
        pytest.param(lambda event: event.update(parent_run_id=7), id="parent-run-id-not-string"),
        pytest.param(lambda event: event["integrity"].update(prev_hash=7), id="prev-hash-not-string"),
        pytest.param(
            lambda event: event["scope"].update(agent_group_ids="alpha"), id="groups-not-array"
        ),
        pytest.param(
            lambda event: event["scope"].update(agent_group_ids=[7]), id="group-not-string"
        ),
    ],
)
def test_a_structurally_wrong_event_is_refused_before_encoding(mutate):
    event = _event()
    mutate(event)
    with pytest.raises(EventEncodingError):
        encode_event_envelope(event)


def test_an_event_that_is_not_an_object_is_refused():
    with pytest.raises(EventEncodingError):
        encode_event_envelope("not an event")  # type: ignore[arg-type]


def test_an_envelope_over_the_gateway_ceiling_is_refused_locally():
    """The gateway would answer PayloadTooLarge and record an abuse signal."""
    event = _event(data={"blob": "x" * (MAX_ENVELOPE_BYTES + 1024)})
    with pytest.raises(EventEncodingError) as caught:
        encode_event_envelope(event)
    assert "larger than ingest accepts" in caught.value.summary


# ---------------------------------------------------------------------------
# IngestResponse
# ---------------------------------------------------------------------------


def test_an_empty_response_means_a_first_submission():
    assert decode_ingest_response(b"") is False


def test_the_duplicate_flag_is_read_from_field_one():
    assert decode_ingest_response(_tag(1, 0) + _varint(1)) is True
    assert decode_ingest_response(_tag(1, 0) + _varint(0)) is False


def test_unknown_response_fields_are_skipped_not_refused():
    """A newer gateway adding a field must not break an older client."""
    body = _tag(1, 0) + _varint(1) + _tag(7, 2) + _varint(4) + b"news"
    assert decode_ingest_response(body) is True


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_tag(1, 2) + _varint(1) + b"x", id="wrong-wire-type"),
        pytest.param(b"\x08", id="truncated-varint"),
        pytest.param(b"\x12\x7f", id="length-past-end"),
    ],
)
def test_a_malformed_response_is_a_typed_transport_error(body):
    with pytest.raises(GrpcStatusError) as caught:
        decode_ingest_response(body)
    assert caught.value.status == "UNKNOWN"


def test_a_response_that_is_not_bytes_is_refused():
    with pytest.raises(GrpcStatusError):
        decode_ingest_response("not bytes")  # type: ignore[arg-type]


def test_an_oversized_response_is_refused_before_it_is_parsed():
    with pytest.raises(GrpcStatusError):
        decode_ingest_response(b"\x00" * (MAX_ENVELOPE_BYTES + 1))


# ---------------------------------------------------------------------------
# Guards that no ordinary input can reach, exercised directly
# ---------------------------------------------------------------------------


def test_the_varint_encoder_refuses_a_negative_value():
    """No caller can reach this today; it must stay unreachable, not become silent."""
    with pytest.raises(EventEncodingError):
        _encode_varint(-1)


def test_a_zero_valued_varint_field_is_omitted_as_proto3_requires():
    event = _event()
    event["schema_version"] = 0
    assert not _present(encode_event_envelope(event), 13)
