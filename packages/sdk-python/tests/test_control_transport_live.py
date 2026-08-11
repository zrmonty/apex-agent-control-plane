"""Tests for ``GrpcControlTransport`` construction, error classification, a
real in-process mTLS round trip, and the in-memory test poller.

Split out of a larger ``test_control_transport.py`` -- see
``test_control_transport.py`` for the wire codec and
``test_control_transport_credentials.py`` for ``AgentControlCredentials``
file-loading tests.

**A real gRPC server over real mTLS, in process**, with a throwaway CA and
client/server leaves minted by the ``control_pki`` fixture (``conftest.py``).
That is what makes "the transport works" a claim about TLS handshakes and
HTTP/2 framing rather than about a mock. It is still not the end-to-end
proof: it does not run the actual ``control-plane-api`` binary, so it cannot
catch a contract mismatch between this client and the Rust service. The live
container test is what does that, and it is in addition to this, not
replaced by it.
"""

from __future__ import annotations

import socket
from concurrent import futures

import pytest

from apex_sdk.control_transport import (
    ACK_COMMAND_METHOD,
    POLL_COMMANDS_METHOD,
    AgentControlCredentials,
    ControlPollError,
    GrpcControlTransport,
    InMemoryControlPoller,
    PendingControlCommand,
    PollResult,
    decode_poll_response,
)
from apex_sdk.errors import ConfigurationError
from conftest import _pending_command, _poll_response

grpc = pytest.importorskip("grpc")
pytest.importorskip("cryptography")


# ---------------------------------------------------------------------------
# Transport construction
# ---------------------------------------------------------------------------


def _credentials(pki) -> AgentControlCredentials:
    return AgentControlCredentials(
        ca_certificate=pki["ca_pem"],
        client_certificate=pki["client_cert_pem"],
        client_key=pki["client_key_pem"],
        token="agent-a-token-abcdefgh",
    )


@pytest.mark.parametrize(
    "endpoint",
    ["", "   ", "https://localhost:9443", "local host:9443", 9443],
)
def test_a_malformed_endpoint_is_refused(control_pki, endpoint):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport(endpoint, _credentials(control_pki))  # type: ignore[arg-type]


def test_credentials_must_be_the_typed_object(control_pki):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport("localhost:9443", {"token": "x"})  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0, -1, 301, True, "5"])
def test_an_out_of_range_timeout_is_refused(control_pki, timeout):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport("localhost:9443", _credentials(control_pki), timeout_seconds=timeout)  # type: ignore[arg-type]


def test_the_missing_grpc_extra_is_a_typed_configuration_error(monkeypatch, control_pki):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "grpc":
            raise ImportError("no grpc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConfigurationError) as caught:
        GrpcControlTransport("localhost:9443", _credentials(control_pki))
    assert "grpc extra" in str(caught.value)


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------


class _FakeRpcError(grpc.RpcError):
    def __init__(self, name: str) -> None:
        super().__init__()
        self._name = name

    def code(self):
        return type("Code", (), {"name": self._name})()

    def details(self):  # pragma: no cover - deliberately never called
        raise AssertionError("details() must never be read: it is server-controlled text")


@pytest.mark.parametrize(
    ("status", "code", "retryable"),
    [
        ("UNAUTHENTICATED", "CONTROL_POLL_AUTHENTICATION_FAILED", False),
        ("PERMISSION_DENIED", "CONTROL_POLL_AUTHORIZATION_FAILED", False),
        ("RESOURCE_EXHAUSTED", "CONTROL_POLL_RATE_LIMITED", True),
        ("UNAVAILABLE", "CONTROL_POLL_UNAVAILABLE", True),
        ("DEADLINE_EXCEEDED", "CONTROL_POLL_UNAVAILABLE", True),
        ("UNIMPLEMENTED", "CONTROL_POLL_UNSUPPORTED", False),
        ("INTERNAL", "CONTROL_POLL_REJECTED", False),
        ("SOMETHING_NEW", "CONTROL_POLL_REJECTED", False),
    ],
)
def test_grpc_statuses_map_to_typed_errors(status, code, retryable):
    error = GrpcControlTransport._classify(_FakeRpcError(status))
    assert error.code == code
    assert error.retryable is retryable
    # Never leaks server-supplied detail text: only the enumerated status.
    assert error.context.get("grpc_status") in {status, "UNRECOGNIZED"}


def test_an_error_with_no_usable_code_is_classified_as_unknown():
    error = GrpcControlTransport._classify(object())
    assert error.code == "CONTROL_POLL_REJECTED"
    assert error.context.get("grpc_status") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Live in-process mTLS
# ---------------------------------------------------------------------------


class _RecordingHandler(grpc.GenericRpcHandler):
    """Serves ``PollCommands`` with a canned body, recording the metadata."""

    def __init__(self, response: bytes, *, abort_with=None) -> None:
        self._response = response
        self._abort_with = abort_with
        self.seen_metadata: list[tuple[str, str]] = []
        self.seen_requests: list[bytes] = []

    def service(self, handler_call_details):
        if handler_call_details.method != POLL_COMMANDS_METHOD:
            return None

        def handle(request: bytes, context):
            self.seen_metadata = list(context.invocation_metadata())
            self.seen_requests.append(request)
            if self._abort_with is not None:
                context.abort(self._abort_with, "refused")
            return self._response

        return grpc.unary_unary_rpc_method_handler(
            handle,
            request_deserializer=lambda value: value,
            response_serializer=lambda value: value,
        )


class _AckRecordingHandler(grpc.GenericRpcHandler):
    """Serves the generated ``AckCommand`` method over the same TLS path."""

    def __init__(self) -> None:
        self.seen_metadata: list[tuple[str, str]] = []
        self.seen_requests: list[bytes] = []

    def service(self, handler_call_details):
        if handler_call_details.method != ACK_COMMAND_METHOD:
            return None

        def handle(request: bytes, context):
            self.seen_metadata = list(context.invocation_metadata())
            self.seen_requests.append(request)
            from apex_sdk._generated.apex.v1 import control_pb2

            decoded = control_pb2.AckCommandRequest.FromString(request)
            return control_pb2.AckCommandResponse(
                command_id=decoded.command_id,
                acknowledged=True,
            ).SerializeToString()

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
        # be testing a transport posture this SDK never actually meets.
        require_client_auth=True,
    )
    port = _free_port()
    server.add_secure_port(f"127.0.0.1:{port}", credentials)
    server.start()
    return server, port


def test_a_real_mtls_poll_returns_the_stop_and_sends_the_bearer_credential(control_pki):
    handler = _RecordingHandler(_poll_response([_pending_command()]))
    server, port = _serve(control_pki, handler)
    try:
        with GrpcControlTransport(
            f"127.0.0.1:{port}",
            _credentials(control_pki),
            server_hostname="localhost",
            timeout_seconds=10,
        ) as transport:
            result = transport.poll(max_commands=4)
    finally:
        server.stop(0).wait()

    assert isinstance(result, PollResult)
    assert result.agent_id == "agent-a"
    stop = result.first_stop()
    assert stop is not None
    assert stop.action == "stop"
    # The request really did carry the clamp hint and nothing else.
    assert handler.seen_requests == [b"\x08\x04"]
    metadata = dict(handler.seen_metadata)
    assert metadata["authorization"] == "Bearer agent-a-token-abcdefgh"


def test_a_real_mtls_ack_round_trips_the_generated_request_and_bearer(control_pki):
    handler = _AckRecordingHandler()
    server, port = _serve(control_pki, handler)
    command = decode_poll_response(_poll_response([_pending_command()])).commands[0]
    try:
        with GrpcControlTransport(
            f"127.0.0.1:{port}",
            _credentials(control_pki),
            server_hostname="localhost",
            timeout_seconds=10,
        ) as transport:
            assert transport.acknowledge(command) is True
    finally:
        server.stop(0).wait()

    from apex_sdk._generated.apex.v1 import control_pb2

    assert len(handler.seen_requests) == 1
    request = control_pb2.AckCommandRequest.FromString(handler.seen_requests[0])
    assert request.command_id == command.command_id
    assert request.workspace_id == command.workspace_id
    assert request.namespace_id == command.namespace_id
    assert request.delivery_attempt == command.delivery_attempt
    assert dict(handler.seen_metadata)["authorization"] == "Bearer agent-a-token-abcdefgh"


def test_a_client_with_no_certificate_cannot_complete_the_handshake(control_pki):
    handler = _RecordingHandler(_poll_response([]))
    server, port = _serve(control_pki, handler)
    try:
        anonymous = AgentControlCredentials(
            ca_certificate=control_pki["ca_pem"],
            client_certificate=b"",
            client_key=b"",
            token="agent-a-token-abcdefgh",
        )
        with GrpcControlTransport(
            f"127.0.0.1:{port}", anonymous, server_hostname="localhost", timeout_seconds=5
        ) as transport:
            with pytest.raises(ControlPollError) as caught:
                transport.poll()
    finally:
        server.stop(0).wait()
    # The transport must surface a typed, retryable-or-not error rather than a
    # raw gRPC exception, whatever the handshake failure looks like.
    assert caught.value.code.startswith("CONTROL_POLL_")


def test_a_server_rejection_surfaces_as_the_matching_typed_error(control_pki):
    handler = _RecordingHandler(b"", abort_with=grpc.StatusCode.UNAUTHENTICATED)
    server, port = _serve(control_pki, handler)
    try:
        with GrpcControlTransport(
            f"127.0.0.1:{port}", _credentials(control_pki), server_hostname="localhost", timeout_seconds=10
        ) as transport:
            with pytest.raises(ControlPollError) as caught:
                transport.poll()
    finally:
        server.stop(0).wait()
    assert caught.value.code == "CONTROL_POLL_AUTHENTICATION_FAILED"
    assert caught.value.retryable is False


def test_polling_a_closed_transport_is_refused(control_pki):
    handler = _RecordingHandler(_poll_response([]))
    server, port = _serve(control_pki, handler)
    try:
        transport = GrpcControlTransport(
            f"127.0.0.1:{port}", _credentials(control_pki), server_hostname="localhost", timeout_seconds=5
        )
        assert transport.endpoint == f"127.0.0.1:{port}"
        transport.poll()
        transport.close()
        with pytest.raises(ControlPollError) as caught:
            transport.poll()
    finally:
        server.stop(0).wait()
    assert caught.value.code == "CONTROL_POLL_TRANSPORT_CLOSED"


def test_a_channel_close_failure_is_typed(control_pki, monkeypatch):
    class _BrokenChannel:
        def unary_unary(self, *_args, **_kwargs):
            return lambda *a, **k: b""

        def close(self):
            raise RuntimeError("channel is wedged")

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(control_pki),
        channel_factory=lambda *_a, **_k: _BrokenChannel(),
    )
    with pytest.raises(ControlPollError) as caught:
        transport.close()
    assert caught.value.code == "CONTROL_TRANSPORT_CLOSE_FAILED"


def test_an_untyped_transport_fault_is_still_a_typed_error(control_pki):
    class _AngryChannel:
        def unary_unary(self, *_args, **_kwargs):
            def invoke(*_a, **_k):
                raise RuntimeError("something unexpected")

            return invoke

        def close(self):
            return None

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(control_pki),
        channel_factory=lambda *_a, **_k: _AngryChannel(),
    )
    with pytest.raises(ControlPollError) as caught:
        transport.poll()
    assert caught.value.code == "CONTROL_POLL_FAILED"
    transport.close()


def test_a_decode_failure_from_the_wire_propagates_unchanged(control_pki):
    class _GarbageChannel:
        def unary_unary(self, *_args, **_kwargs):
            return lambda *a, **k: b"\x08"

        def close(self):
            return None

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(control_pki),
        channel_factory=lambda *_a, **_k: _GarbageChannel(),
    )
    with pytest.raises(ControlPollError) as caught:
        transport.poll()
    assert caught.value.code == "CONTROL_POLL_PROTOCOL_VIOLATION"
    transport.close()


# ---------------------------------------------------------------------------
# In-memory poller
# ---------------------------------------------------------------------------


def _command(action: str = "stop", command_id: str = "cmd-1") -> PendingControlCommand:
    return PendingControlCommand(
        command_id=command_id,
        workspace_id="acme",
        namespace_id="prod",
        agent_id="agent-a",
        run_id="run-1",
        trace_id="trace-1",
        action=action,
        reason_code="operator.request",
        issued_at="2026-08-08T00:00:00.000000Z",
        delivery_attempt=1,
    )


def test_the_in_memory_poller_drains_and_records_polls():
    poller = InMemoryControlPoller([_command(), _command(command_id="cmd-2")], agent_id="agent-a")
    first = poller.poll(max_commands=1)
    assert [command.command_id for command in first.commands] == ["cmd-1"]
    second = poller.poll()
    assert [command.command_id for command in second.commands] == ["cmd-2"]
    assert poller.poll().commands == ()
    assert poller.polls == 3
    poller.close()
    assert poller.closed is True
