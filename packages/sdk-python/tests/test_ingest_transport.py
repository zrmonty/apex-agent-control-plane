"""Tests for the real gRPC + mTLS ``Ingest`` client.

Four layers, deliberately:

1. **The Struct encoder against the SDK's existing decoder.** This is the
   mandatory one. ``control_transport._decode_struct`` was written first, is
   already CI-proven against a real ``control-plane-api``, and knows nothing
   about this encoder. Round-tripping through both proves the two agree with
   *each other*, which is the only property that matters -- an encoder and a
   decoder can each look right in isolation and still disagree about the wire.
2. The envelope encoder, field by field, against hand-built expected bytes and
   against the frozen contract in ``contracts/proto/apex/v1/event.proto`` (the
   enum tables are parsed out of the ``.proto`` rather than restated, because a
   restated table can drift).
3. The pre-send integrity guard: an event whose data cannot survive the trip
   must be refused locally, before any request, rather than becoming an opaque
   ``InvalidIntegrity`` rejection at the gateway.
4. **A real gRPC server over real mTLS, in process**, with a throwaway CA and
   client/server leaves minted here, so "the transport works" is a claim about
   TLS handshakes and HTTP/2 framing rather than about a mock.

Layer 4 is still not the end-to-end proof: it does not run the actual
``apex-event-ingest`` binary, so it cannot catch a contract mismatch between
this client and the Rust service -- notably that the gateway recomputes the
canonical hash from the bytes it received and rejects any disagreement. The live
container proof (``deploy/compose/gateway-ref/agent_submits_events.py``, gated
in ``.github/workflows/live-mtls-e2e.yml``) is what does that, and it is in
addition to this, not a replacement for it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import math
import os
import re
import socket
import struct as _struct
from concurrent import futures
from pathlib import Path

import pytest

from apex_sdk.control_transport import MAX_STRUCT_DEPTH, MAX_STRUCT_ENTRIES, _decode_struct
from apex_sdk.errors import ConfigurationError
from apex_sdk.event import EventBuilder, event_hash
from apex_sdk.exporter import BoundedGrpcExporter, ExportDeliveryError, GrpcStatusError
from apex_sdk.ingest_transport import (
    ACTOR_TYPE_VALUES,
    EVENT_TYPE_VALUES,
    INGEST_METHOD,
    MAX_ENVELOPE_BYTES,
    MAX_EXACT_INTEGER,
    AgentIngestCredentials,
    EventEncodingError,
    GrpcEventIngestTransport,
    decode_ingest_response,
    encode_event_envelope,
    encode_struct,
)

grpc = pytest.importorskip("grpc")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
EVENT_PROTO = REPO_ROOT / "contracts" / "proto" / "apex" / "v1" / "event.proto"

EVENT_ID = "018f5c91-2d88-7c00-8000-0000000000aa"


# ---------------------------------------------------------------------------
# Hand-rolled reader, so the expected bytes are not produced by the code
# under test
# ---------------------------------------------------------------------------


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _fields(buffer: bytes) -> list[tuple[int, int, object]]:
    """Parses a message into ``(field_number, wire_type, value)`` triples."""
    out: list[tuple[int, int, object]] = []
    offset = 0
    while offset < len(buffer):
        tag = 0
        shift = 0
        while True:
            byte = buffer[offset]
            offset += 1
            tag |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        number, wire = tag >> 3, tag & 0x07
        if wire == 0:
            value = 0
            shift = 0
            while True:
                byte = buffer[offset]
                offset += 1
                value |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            out.append((number, wire, value))
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                byte = buffer[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
            out.append((number, wire, buffer[offset : offset + length]))
            offset += length
        elif wire == 1:
            out.append((number, wire, buffer[offset : offset + 8]))
            offset += 8
        else:  # pragma: no cover - this encoder never emits other wire types
            raise AssertionError(f"unexpected wire type {wire}")
    return out


def _only(buffer: bytes, number: int):
    matches = [value for field, _wire, value in _fields(buffer) if field == number]
    assert len(matches) == 1, f"expected exactly one field {number}, got {len(matches)}"
    return matches[0]


def _present(buffer: bytes, number: int) -> bool:
    return any(field == number for field, _wire, _value in _fields(buffer))


# ---------------------------------------------------------------------------
# 1. The Struct encoder, against the SDK's existing decoder
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# 2. The envelope encoder, and the enum tables against the frozen contract
# ---------------------------------------------------------------------------


def _event(**overrides) -> dict:
    builder = EventBuilder(
        agent_id="reference-agent",
        run_id="run-1",
        trace_id="trace-1",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        actor={"type": "agent", "id": "reference-agent"},
        version={"agent_code": "sdk-test", "prompt": "p1", "model": "reference"},
    )
    event = builder.build(
        overrides.pop("event_type", "turn_start"),
        overrides.pop("data", {"note": "hello"}),
        event_id=overrides.pop("event_id", EVENT_ID),
        timestamp=dt.datetime(2026, 8, 9, 12, 0, 0, tzinfo=dt.UTC),
    )
    event.update(overrides)
    return event


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
# PKI fixtures
# ---------------------------------------------------------------------------


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pem_key(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _issue(ca_key, ca_cert, common_name: str, *, server: bool):
    key = _rsa_key()
    now = dt.datetime.now(dt.UTC)
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    eku = [ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture(scope="module")
def pki():
    ca_key = _rsa_key()
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "apex-sdk-ingest-test-ca")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    server_key, server_cert = _issue(ca_key, ca_cert, "event-ingest", server=True)
    client_key, client_cert = _issue(ca_key, ca_cert, "apex-agent-workload", server=False)
    return {
        "ca_pem": ca_cert.public_bytes(serialization.Encoding.PEM),
        "server_cert_pem": server_cert.public_bytes(serialization.Encoding.PEM),
        "server_key_pem": _pem_key(server_key),
        "client_cert_pem": client_cert.public_bytes(serialization.Encoding.PEM),
        "client_key_pem": _pem_key(client_key),
    }


@pytest.fixture
def credential_files(tmp_path, pki):
    paths = {}
    for name, blob, private in (
        ("ca.pem", pki["ca_pem"], False),
        ("client.pem", pki["client_cert_pem"], False),
        ("client.key", pki["client_key_pem"], True),
        ("ingest-bearer-token", b"gateway-ref-token\n", True),
    ):
        path = tmp_path / name
        path.write_bytes(blob)
        if os.name == "posix":
            path.chmod(0o600 if private else 0o644)
        paths[name] = path
    return paths


def _credentials(pki) -> AgentIngestCredentials:
    return AgentIngestCredentials(
        ca_certificate=pki["ca_pem"],
        client_certificate=pki["client_cert_pem"],
        client_key=pki["client_key_pem"],
        token="gateway-ref-token",
    )


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_credentials_load_from_files_and_strip_the_token(credential_files):
    credentials = AgentIngestCredentials.from_files(
        ca_file=credential_files["ca.pem"],
        client_certificate_file=credential_files["client.pem"],
        client_key_file=credential_files["client.key"],
        token_file=credential_files["ingest-bearer-token"],
    )
    assert credentials.token == "gateway-ref-token"
    assert credentials.ca_certificate.startswith(b"-----BEGIN CERTIFICATE-----")
    assert credentials.client_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_supplying_both_or_neither_token_source_is_refused(credential_files):
    common = {
        "ca_file": credential_files["ca.pem"],
        "client_certificate_file": credential_files["client.pem"],
        "client_key_file": credential_files["client.key"],
    }
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(**common)
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            **common, token="a-token", token_file=credential_files["ingest-bearer-token"]
        )


@pytest.mark.parametrize(
    "token",
    ["", "   ", "has space", "téken", "with\x01control", "x" * 4097],
)
def test_a_token_the_gateway_would_refuse_is_refused_here_first(credential_files, token):
    """``auth/verifier.rs`` requires ASCII-graphic bytes and at most 4096 of them.

    Rejecting locally turns a malformed credential into a configuration error at
    startup rather than an opaque UNAUTHENTICATED on first export -- and it is
    strictly stricter than the control transport's check, which admits
    non-printable ASCII.
    """
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token=token,
        )


def test_a_missing_credential_file_is_a_typed_configuration_error(tmp_path, credential_files):
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=tmp_path / "nope.pem",
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="gateway-ref-token",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are only meaningful on POSIX")
def test_a_world_readable_private_key_is_refused(credential_files):
    credential_files["client.key"].chmod(0o644)
    with pytest.raises(ConfigurationError):
        AgentIngestCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="gateway-ref-token",
        )


# ---------------------------------------------------------------------------
# Transport construction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "endpoint",
    ["", "   ", "https://localhost:8443", "local host:8443", 8443],
)
def test_a_malformed_endpoint_is_refused(pki, endpoint):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport(endpoint, _credentials(pki))  # type: ignore[arg-type]


def test_credentials_must_be_the_typed_object(pki):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", {"token": "x"})  # type: ignore[arg-type]


def test_a_control_credential_object_is_not_accepted_here(pki):
    """The two services authenticate independently; their credentials are not interchangeable."""
    from apex_sdk.control_transport import AgentControlCredentials

    control = AgentControlCredentials(
        ca_certificate=pki["ca_pem"],
        client_certificate=pki["client_cert_pem"],
        client_key=pki["client_key_pem"],
        token="gateway-ref-token",
    )
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", control)  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0, -1, 301, True, "5"])
def test_an_out_of_range_timeout_is_refused(pki, timeout):
    with pytest.raises(ConfigurationError):
        GrpcEventIngestTransport("localhost:8443", _credentials(pki), timeout_seconds=timeout)  # type: ignore[arg-type]


def test_the_missing_grpc_extra_is_a_typed_configuration_error(monkeypatch, pki):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "grpc":
            raise ImportError("no grpc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConfigurationError) as caught:
        GrpcEventIngestTransport("localhost:8443", _credentials(pki))
    assert "grpc extra" in str(caught.value)


# ---------------------------------------------------------------------------
# 3. The pre-send integrity guard
# ---------------------------------------------------------------------------


class _StubChannel:
    """A channel that records what would have gone on the wire."""

    def __init__(self, response: bytes = b"", raiser=None) -> None:
        self.response = response
        self.raiser = raiser
        self.sent: list[bytes] = []
        self.metadata: list[tuple[str, str]] = []
        self.closed = False

    def unary_unary(self, *_args, **_kwargs):
        def invoke(payload, timeout=None, metadata=()):
            self.sent.append(payload)
            self.metadata = list(metadata)
            if self.raiser is not None:
                raise self.raiser()
            return self.response

        return invoke

    def close(self):
        self.closed = True


def _transport(pki, channel, **kwargs) -> GrpcEventIngestTransport:
    return GrpcEventIngestTransport(
        "127.0.0.1:1", _credentials(pki), channel_factory=lambda *_a, **_k: channel, **kwargs
    )


def test_an_event_whose_hash_does_not_cover_what_would_be_sent_is_never_sent(pki):
    """The integrity guard, stated as the property that matters.

    ``data`` is mutated *after* the hash was computed. The bytes about to go out
    therefore mean something the hash does not describe -- exactly the condition
    the gateway would answer ``InvalidIntegrity`` for. Nothing may leave this
    process, and no idempotency slot may be consumed at the gateway.
    """
    channel = _StubChannel()
    transport = _transport(pki, channel)
    event = _event(data={"note": "hello"})
    event["data"]["note"] = "tampered"
    with pytest.raises(EventEncodingError) as caught:
        transport.ingest(event, event_id=event["event_id"])
    assert channel.sent == []
    assert caught.value.retryable is False
    assert caught.value.correlation.get("event_id") == EVENT_ID


def test_the_guard_accepts_an_event_whose_data_survives_the_double_conversion(pki):
    """Ints becoming floats must *not* trip the guard: they canonicalize the same."""
    channel = _StubChannel()
    transport = _transport(pki, channel)
    event = _event(data={"count": 5, "ratio": 1.5, "ok": True, "none": None, "list": [1, "a"]})
    assert transport.ingest(event, event_id=event["event_id"]) is True
    assert len(channel.sent) == 1


def test_the_guard_can_be_disabled_but_is_on_by_default(pki):
    channel = _StubChannel()
    permissive = _transport(pki, channel, verify_canonical_round_trip=False)
    event = _event()
    event["data"]["note"] = "tampered"
    # Sends it; the gateway is then the one that refuses. Off by choice only.
    assert permissive.ingest(event, event_id=event["event_id"]) is True
    assert len(channel.sent) == 1


def test_an_event_id_that_does_not_describe_the_payload_is_refused(pki):
    """A mismatched idempotency key is how a poisoned gateway entry is created."""
    channel = _StubChannel()
    transport = _transport(pki, channel)
    event = _event()
    with pytest.raises(EventEncodingError):
        transport.ingest(event, event_id="018f5c91-2d88-7c00-8000-0000000000ff")
    assert channel.sent == []


def test_ingesting_something_that_is_not_an_event_is_refused(pki):
    transport = _transport(pki, _StubChannel())
    with pytest.raises(EventEncodingError):
        transport.ingest("not an event", event_id=EVENT_ID)  # type: ignore[arg-type]


def test_ingesting_on_a_closed_transport_is_refused(pki):
    channel = _StubChannel()
    transport = _transport(pki, channel)
    transport.close()
    assert channel.closed is True
    with pytest.raises(EventEncodingError) as caught:
        transport.ingest(_event(), event_id=EVENT_ID)
    assert "closed" in caught.value.summary


def test_a_channel_close_failure_is_typed(pki):
    class _BrokenChannel(_StubChannel):
        def close(self):
            raise RuntimeError("channel is wedged")

    transport = _transport(pki, _BrokenChannel())
    with pytest.raises(GrpcStatusError):
        transport.close()


def test_an_untyped_transport_fault_surfaces_as_a_grpc_status_error(pki):
    transport = _transport(pki, _StubChannel(raiser=lambda: RuntimeError("boom")))
    with pytest.raises(GrpcStatusError) as caught:
        transport.ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "UNKNOWN"


def test_the_duplicate_flag_is_inverted_into_the_transport_contract(pki):
    """``IngestResponse.duplicate`` is ``True``; ``ingest()`` reports ``False``."""
    duplicate = _StubChannel(response=_tag(1, 0) + _varint(1))
    assert _transport(pki, duplicate).ingest(_event(), event_id=EVENT_ID) is False
    fresh = _StubChannel(response=b"")
    assert _transport(pki, fresh).ingest(_event(), event_id=EVENT_ID) is True


def test_the_bearer_credential_travels_in_metadata_and_never_in_an_error(pki):
    channel = _StubChannel()
    transport = _transport(pki, channel)
    transport.ingest(_event(), event_id=EVENT_ID)
    assert dict(channel.metadata)["authorization"] == "Bearer gateway-ref-token"
    error = EventEncodingError()
    assert "gateway-ref-token" not in repr(error.to_diagnostic())


def test_the_endpoint_is_exposed_for_diagnostics(pki):
    assert _transport(pki, _StubChannel()).endpoint == "127.0.0.1:1"


class _FakeRpcError(grpc.RpcError):
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def code(self):
        return type("Code", (), {"name": self._name})()

    def details(self):  # pragma: no cover - deliberately never called
        raise AssertionError("details() must never be read: it is server-controlled text")


@pytest.mark.parametrize(
    "status",
    ["UNAUTHENTICATED", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "UNAVAILABLE", "INVALID_ARGUMENT"],
)
def test_a_grpc_rejection_surfaces_as_its_status_and_nothing_else(pki, status):
    channel = _StubChannel(raiser=lambda: _FakeRpcError(status))
    with pytest.raises(GrpcStatusError) as caught:
        _transport(pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == status


def test_an_rpc_error_with_no_usable_code_is_reported_as_unknown(pki):
    class _Codeless(grpc.RpcError):
        pass

    channel = _StubChannel(raiser=_Codeless)
    with pytest.raises(GrpcStatusError) as caught:
        _transport(pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "UNKNOWN"


# ---------------------------------------------------------------------------
# Integration with BoundedGrpcExporter
# ---------------------------------------------------------------------------


def test_the_exporter_drives_the_real_transport_and_counts_duplicates(pki):
    """The transport is what a consumer swaps in for ``InMemoryIdempotentIngest``."""
    channel = _StubChannel(response=b"")
    exporter = BoundedGrpcExporter(_transport(pki, channel))
    event = _event()
    exporter.write(event)
    channel.response = _tag(1, 0) + _varint(1)
    exporter.write(event)
    assert exporter.stats["delivered"] == 1
    assert exporter.stats["duplicates"] == 1
    assert exporter.stats["failed"] == 0


def test_a_deterministic_encoding_refusal_is_not_retried():
    """Re-sending an identical dict produces an identical refusal.

    Before this, any non-``GrpcStatusError`` from a transport was classified as
    retryable, so the exporter would burn its whole attempt budget on a failure
    that cannot succeed and then hand the caller a ``retryable=True`` error
    inviting a replay that can never be accepted. The retry and backoff policy
    is unchanged; a decision the transport already made is simply no longer
    overwritten with a softer one.
    """

    class _RefusingTransport:
        def __init__(self) -> None:
            self.calls = 0

        def ingest(self, event, *, event_id):
            self.calls += 1
            raise EventEncodingError(cause="deliberate refusal")

        def close(self):
            return None

    transport = _RefusingTransport()
    exporter = BoundedGrpcExporter(transport, max_attempts=3, backoff=lambda _: 0)
    with pytest.raises(ExportDeliveryError) as caught:
        exporter.write(_event())
    assert caught.value.retryable is False
    assert caught.value.code == "EVENT_ENCODE_FAILED"
    assert transport.calls == 1
    assert exporter.stats["attempted"] == 1


def test_a_transport_fault_with_no_verdict_is_still_retried():
    """The pre-existing behaviour, unchanged: an untyped fault is retryable."""

    class _FlakyTransport:
        def __init__(self) -> None:
            self.calls = 0

        def ingest(self, event, *, event_id):
            self.calls += 1
            raise RuntimeError("socket went away")

        def close(self):
            return None

    transport = _FlakyTransport()
    exporter = BoundedGrpcExporter(transport, max_attempts=3, backoff=lambda _: 0)
    with pytest.raises(ExportDeliveryError) as caught:
        exporter.write(_event())
    assert caught.value.retryable is True
    assert transport.calls == 3


# ---------------------------------------------------------------------------
# 4. Live in-process mTLS
# ---------------------------------------------------------------------------


class _RecordingIngest(grpc.GenericRpcHandler):
    """An in-process ``Ingest`` that answers ``duplicate`` on a repeated id."""

    def __init__(self, *, abort_with=None) -> None:
        self._abort_with = abort_with
        self.seen_metadata: list[tuple[str, str]] = []
        self.seen_requests: list[bytes] = []
        self._ids: set[bytes] = set()

    def service(self, handler_call_details):
        if handler_call_details.method != INGEST_METHOD:
            return None

        def handle(request: bytes, context):
            self.seen_metadata = list(context.invocation_metadata())
            self.seen_requests.append(request)
            if self._abort_with is not None:
                context.abort(self._abort_with, "refused")
            event_id = _only(request, 1)
            duplicate = event_id in self._ids
            self._ids.add(event_id)
            return _tag(1, 0) + _varint(1) if duplicate else b""

        return grpc.unary_unary_rpc_method_handler(
            handle,
            request_deserializer=lambda value: value,
            response_serializer=lambda value: value,
        )


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _serve(pki, handler) -> tuple[object, int]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    server.add_generic_rpc_handlers((handler,))
    credentials = grpc.ssl_server_credentials(
        [(pki["server_key_pem"], pki["server_cert_pem"])],
        root_certificates=pki["ca_pem"],
        # Client certificate mandatory, matching the real gateway's
        # `client_auth_optional(false)`. A fixture that made it optional would
        # be testing a posture this SDK never actually meets.
        require_client_auth=True,
    )
    port = _free_port()
    server.add_secure_port(f"127.0.0.1:{port}", credentials)
    server.start()
    return server, port


def test_a_real_mtls_submission_is_accepted_and_the_replay_is_a_duplicate(pki):
    handler = _RecordingIngest()
    server, port = _serve(pki, handler)
    try:
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}",
            _credentials(pki),
            server_hostname="localhost",
            timeout_seconds=10,
        ) as transport:
            event = _event(data={"note": "hello", "count": 3, "flag": True, "none": None})
            assert transport.ingest(event, event_id=event["event_id"]) is True
            assert transport.ingest(event, event_id=event["event_id"]) is False
    finally:
        server.stop(0).wait()

    assert len(handler.seen_requests) == 2
    assert handler.seen_requests[0] == handler.seen_requests[1]
    assert _decode_struct(_only(handler.seen_requests[0], 11)) == {
        "note": "hello",
        "count": 3.0,
        "flag": True,
        "none": None,
    }
    assert dict(handler.seen_metadata)["authorization"] == "Bearer gateway-ref-token"


def test_a_client_with_no_certificate_cannot_complete_the_handshake(pki):
    handler = _RecordingIngest()
    server, port = _serve(pki, handler)
    try:
        anonymous = AgentIngestCredentials(
            ca_certificate=pki["ca_pem"],
            client_certificate=b"",
            client_key=b"",
            token="gateway-ref-token",
        )
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}", anonymous, server_hostname="localhost", timeout_seconds=5
        ) as transport:
            with pytest.raises(GrpcStatusError):
                transport.ingest(_event(), event_id=EVENT_ID)
    finally:
        server.stop(0).wait()
    assert handler.seen_requests == []


def test_a_server_rejection_surfaces_as_its_status(pki):
    handler = _RecordingIngest(abort_with=grpc.StatusCode.UNAUTHENTICATED)
    server, port = _serve(pki, handler)
    try:
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}", _credentials(pki), server_hostname="localhost", timeout_seconds=10
        ) as transport:
            with pytest.raises(GrpcStatusError) as caught:
                transport.ingest(_event(), event_id=EVENT_ID)
    finally:
        server.stop(0).wait()
    assert caught.value.status == "UNAUTHENTICATED"


def test_a_server_certificate_from_an_untrusted_ca_is_refused(pki, tmp_path):
    """The transport never offers a way to skip verification; prove it holds."""
    other_ca_key = _rsa_key()
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-ca")])
    other_ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(other_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(other_ca_key, hashes.SHA256())
    )
    rogue_key, rogue_cert = _issue(other_ca_key, other_ca, "event-ingest", server=True)
    rogue_pki = {
        "ca_pem": other_ca.public_bytes(serialization.Encoding.PEM),
        "server_cert_pem": rogue_cert.public_bytes(serialization.Encoding.PEM),
        "server_key_pem": _pem_key(rogue_key),
    }
    handler = _RecordingIngest()
    server, port = _serve(rogue_pki, handler)
    try:
        # Client still trusts only the real CA.
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}", _credentials(pki), server_hostname="localhost", timeout_seconds=5
        ) as transport:
            with pytest.raises(GrpcStatusError):
                transport.ingest(_event(), event_id=EVENT_ID)
    finally:
        server.stop(0).wait()
    assert handler.seen_requests == []


# ---------------------------------------------------------------------------
# Guards that no ordinary input can reach, exercised directly
# ---------------------------------------------------------------------------


def test_the_varint_encoder_refuses_a_negative_value():
    """No caller can reach this today; it must stay unreachable, not become silent."""
    from apex_sdk.ingest_transport import _encode_varint

    with pytest.raises(EventEncodingError):
        _encode_varint(-1)


def test_a_zero_valued_varint_field_is_omitted_as_proto3_requires():
    event = _event()
    event["schema_version"] = 0
    assert not _present(encode_event_envelope(event), 13)


def test_the_struct_encoder_refuses_to_start_below_the_depth_ceiling():
    with pytest.raises(EventEncodingError):
        encode_struct({}, MAX_STRUCT_DEPTH + 1)


def test_a_status_error_raised_by_the_channel_is_not_rewrapped(pki):
    channel = _StubChannel(raiser=lambda: GrpcStatusError("RESOURCE_EXHAUSTED"))
    with pytest.raises(GrpcStatusError) as caught:
        _transport(pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "RESOURCE_EXHAUSTED"


def test_credentials_never_print_the_private_key_or_the_bearer_token(pki):
    """A dataclass prints every field by default; these two must not be printed.

    ``logging.debug("%r", credentials)``, a pytest ``--showlocals`` traceback,
    or any exception renderer that walks local variables would otherwise put a
    workload private key and a live bearer credential into a log. Asserted for
    both transports' credential objects, because they are the same shape and a
    leak in either is the same incident.
    """
    from apex_sdk.control_transport import AgentControlCredentials

    ingest = _credentials(pki)
    control = AgentControlCredentials(
        ca_certificate=pki["ca_pem"],
        client_certificate=pki["client_cert_pem"],
        client_key=pki["client_key_pem"],
        token="agent-a-token-abcdefgh",
    )
    for credentials, token in ((ingest, "gateway-ref-token"), (control, "agent-a-token-abcdefgh")):
        rendered = repr(credentials)
        assert token not in rendered
        assert "PRIVATE KEY" not in rendered
        # The certificate material is not secret and stays visible, so the
        # object is still identifiable in a diagnostic.
        assert "BEGIN CERTIFICATE" in rendered
    # The values themselves are still reachable by the code that needs them.
    assert ingest.token == "gateway-ref-token"
    assert ingest.client_key == pki["client_key_pem"]
