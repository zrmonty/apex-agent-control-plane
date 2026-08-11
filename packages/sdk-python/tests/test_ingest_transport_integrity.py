"""Tests for the pre-send canonical round-trip integrity guard, and
``GrpcEventIngestTransport`` integration with ``BoundedGrpcExporter``.

Split out of a larger ``test_ingest_transport.py`` -- see
``test_ingest_transport.py`` for the Struct encoder,
``test_ingest_transport_envelope.py`` for the envelope encoder,
``test_ingest_transport_credentials.py`` for credential loading, and
``test_ingest_transport_live.py`` for the live in-process mTLS suite.

The pre-send integrity guard: an event whose data cannot survive the trip
must be refused locally, before any request, rather than becoming an opaque
``InvalidIntegrity`` rejection at the gateway.
"""

from __future__ import annotations

import pytest

from apex_sdk.exporter import BoundedGrpcExporter, ExportDeliveryError, GrpcStatusError
from apex_sdk.ingest_transport import EventEncodingError, GrpcEventIngestTransport
from conftest import EVENT_ID, _event, _ingest_credentials, _tag, _varint

grpc = pytest.importorskip("grpc")
pytest.importorskip("cryptography")


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
        "127.0.0.1:1", _ingest_credentials(pki), channel_factory=lambda *_a, **_k: channel, **kwargs
    )


def test_an_event_whose_hash_does_not_cover_what_would_be_sent_is_never_sent(ingest_pki):
    """The integrity guard, stated as the property that matters.

    ``data`` is mutated *after* the hash was computed. The bytes about to go out
    therefore mean something the hash does not describe -- exactly the condition
    the gateway would answer ``InvalidIntegrity`` for. Nothing may leave this
    process, and no idempotency slot may be consumed at the gateway.
    """
    channel = _StubChannel()
    transport = _transport(ingest_pki, channel)
    event = _event(data={"note": "hello"})
    event["data"]["note"] = "tampered"
    with pytest.raises(EventEncodingError) as caught:
        transport.ingest(event, event_id=event["event_id"])
    assert channel.sent == []
    assert caught.value.retryable is False
    assert caught.value.correlation.get("event_id") == EVENT_ID


def test_the_guard_accepts_an_event_whose_data_survives_the_double_conversion(ingest_pki):
    """Ints becoming floats must *not* trip the guard: they canonicalize the same."""
    channel = _StubChannel()
    transport = _transport(ingest_pki, channel)
    event = _event(data={"count": 5, "ratio": 1.5, "ok": True, "none": None, "list": [1, "a"]})
    assert transport.ingest(event, event_id=event["event_id"]) is True
    assert len(channel.sent) == 1


def test_the_guard_can_be_disabled_but_is_on_by_default(ingest_pki):
    channel = _StubChannel()
    permissive = _transport(ingest_pki, channel, verify_canonical_round_trip=False)
    event = _event()
    event["data"]["note"] = "tampered"
    # Sends it; the gateway is then the one that refuses. Off by choice only.
    assert permissive.ingest(event, event_id=event["event_id"]) is True
    assert len(channel.sent) == 1


def test_an_event_id_that_does_not_describe_the_payload_is_refused(ingest_pki):
    """A mismatched idempotency key is how a poisoned gateway entry is created."""
    channel = _StubChannel()
    transport = _transport(ingest_pki, channel)
    event = _event()
    with pytest.raises(EventEncodingError):
        transport.ingest(event, event_id="018f5c91-2d88-7c00-8000-0000000000ff")
    assert channel.sent == []


def test_ingesting_something_that_is_not_an_event_is_refused(ingest_pki):
    transport = _transport(ingest_pki, _StubChannel())
    with pytest.raises(EventEncodingError):
        transport.ingest("not an event", event_id=EVENT_ID)  # type: ignore[arg-type]


def test_ingesting_on_a_closed_transport_is_refused(ingest_pki):
    channel = _StubChannel()
    transport = _transport(ingest_pki, channel)
    transport.close()
    assert channel.closed is True
    with pytest.raises(EventEncodingError) as caught:
        transport.ingest(_event(), event_id=EVENT_ID)
    assert "closed" in caught.value.summary


def test_a_channel_close_failure_is_typed(ingest_pki):
    class _BrokenChannel(_StubChannel):
        def close(self):
            raise RuntimeError("channel is wedged")

    transport = _transport(ingest_pki, _BrokenChannel())
    with pytest.raises(GrpcStatusError):
        transport.close()


def test_an_untyped_transport_fault_surfaces_as_a_grpc_status_error(ingest_pki):
    transport = _transport(ingest_pki, _StubChannel(raiser=lambda: RuntimeError("boom")))
    with pytest.raises(GrpcStatusError) as caught:
        transport.ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "UNKNOWN"


def test_the_duplicate_flag_is_inverted_into_the_transport_contract(ingest_pki):
    """``IngestResponse.duplicate`` is ``True``; ``ingest()`` reports ``False``."""
    duplicate = _StubChannel(response=_tag(1, 0) + _varint(1))
    assert _transport(ingest_pki, duplicate).ingest(_event(), event_id=EVENT_ID) is False
    fresh = _StubChannel(response=b"")
    assert _transport(ingest_pki, fresh).ingest(_event(), event_id=EVENT_ID) is True


def test_the_bearer_credential_travels_in_metadata_and_never_in_an_error(ingest_pki):
    channel = _StubChannel()
    transport = _transport(ingest_pki, channel)
    transport.ingest(_event(), event_id=EVENT_ID)
    assert dict(channel.metadata)["authorization"] == "Bearer gateway-ref-token"
    error = EventEncodingError()
    assert "gateway-ref-token" not in repr(error.to_diagnostic())


def test_the_endpoint_is_exposed_for_diagnostics(ingest_pki):
    assert _transport(ingest_pki, _StubChannel()).endpoint == "127.0.0.1:1"


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
def test_a_grpc_rejection_surfaces_as_its_status_and_nothing_else(ingest_pki, status):
    channel = _StubChannel(raiser=lambda: _FakeRpcError(status))
    with pytest.raises(GrpcStatusError) as caught:
        _transport(ingest_pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == status


def test_an_rpc_error_with_no_usable_code_is_reported_as_unknown(ingest_pki):
    class _Codeless(grpc.RpcError):
        pass

    channel = _StubChannel(raiser=_Codeless)
    with pytest.raises(GrpcStatusError) as caught:
        _transport(ingest_pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "UNKNOWN"


def test_a_status_error_raised_by_the_channel_is_not_rewrapped(ingest_pki):
    channel = _StubChannel(raiser=lambda: GrpcStatusError("RESOURCE_EXHAUSTED"))
    with pytest.raises(GrpcStatusError) as caught:
        _transport(ingest_pki, channel).ingest(_event(), event_id=EVENT_ID)
    assert caught.value.status == "RESOURCE_EXHAUSTED"


# ---------------------------------------------------------------------------
# Integration with BoundedGrpcExporter
# ---------------------------------------------------------------------------


def test_the_exporter_drives_the_real_transport_and_counts_duplicates(ingest_pki):
    """The transport is what a consumer swaps in for ``InMemoryIdempotentIngest``."""
    channel = _StubChannel(response=b"")
    exporter = BoundedGrpcExporter(_transport(ingest_pki, channel))
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
