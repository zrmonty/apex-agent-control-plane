"""Tests for a real in-process mTLS ``Ingest`` round trip.

Split out of a larger ``test_ingest_transport.py`` -- see
``test_ingest_transport.py`` for the Struct encoder,
``test_ingest_transport_envelope.py`` for the envelope encoder,
``test_ingest_transport_credentials.py`` for credential loading, and
``test_ingest_transport_integrity.py`` for the pre-send integrity guard.

**A real gRPC server over real mTLS, in process**, with a throwaway CA and
client/server leaves minted by the ``ingest_pki`` fixture (``conftest.py``),
so "the transport works" is a claim about TLS handshakes and HTTP/2 framing
rather than about a mock. It is still not the end-to-end proof: it does not
run the actual ``apex-event-ingest`` binary, so it cannot catch a contract
mismatch between this client and the Rust service -- notably that the
gateway recomputes the canonical hash from the bytes it received and rejects
any disagreement. The live container proof
(``deploy/compose/gateway-ref/agent_submits_events.py``, gated in
``.github/workflows/live-mtls-e2e.yml``) is what does that, and it is in
addition to this, not a replacement for it.
"""

from __future__ import annotations

import datetime as dt
import socket
from concurrent import futures

import pytest

from apex_sdk.control_transport import _decode_struct
from apex_sdk.exporter import GrpcStatusError
from apex_sdk.ingest_transport import INGEST_METHOD, AgentIngestCredentials, GrpcEventIngestTransport
from conftest import EVENT_ID, _event, _ingest_credentials, _issue, _only, _pem_key, _rsa_key, _tag, _varint

grpc = pytest.importorskip("grpc")
pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


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


def test_a_real_mtls_submission_is_accepted_and_the_replay_is_a_duplicate(ingest_pki):
    handler = _RecordingIngest()
    server, port = _serve(ingest_pki, handler)
    try:
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}",
            _ingest_credentials(ingest_pki),
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


def test_a_client_with_no_certificate_cannot_complete_the_handshake(ingest_pki):
    handler = _RecordingIngest()
    server, port = _serve(ingest_pki, handler)
    try:
        anonymous = AgentIngestCredentials(
            ca_certificate=ingest_pki["ca_pem"],
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


def test_a_server_rejection_surfaces_as_its_status(ingest_pki):
    handler = _RecordingIngest(abort_with=grpc.StatusCode.UNAUTHENTICATED)
    server, port = _serve(ingest_pki, handler)
    try:
        with GrpcEventIngestTransport(
            f"127.0.0.1:{port}", _ingest_credentials(ingest_pki), server_hostname="localhost", timeout_seconds=10
        ) as transport:
            with pytest.raises(GrpcStatusError) as caught:
                transport.ingest(_event(), event_id=EVENT_ID)
    finally:
        server.stop(0).wait()
    assert caught.value.status == "UNAUTHENTICATED"


def test_a_server_certificate_from_an_untrusted_ca_is_refused(ingest_pki, tmp_path):
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
            f"127.0.0.1:{port}", _ingest_credentials(ingest_pki), server_hostname="localhost", timeout_seconds=5
        ) as transport:
            with pytest.raises(GrpcStatusError):
                transport.ingest(_event(), event_id=EVENT_ID)
    finally:
        server.stop(0).wait()
    assert handler.seen_requests == []
