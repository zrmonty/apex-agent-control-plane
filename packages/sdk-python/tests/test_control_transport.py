"""Tests for the real gRPC + mTLS ``PollCommands`` client.

Three layers, deliberately:

1. The wire codec, exhaustively, because it is hand-rolled (see the module
   docstring in ``control_transport.py`` for why) and a decoder that silently
   mis-parses a `stop` is the worst possible failure here.
2. Credential loading and error classification.
3. **A real gRPC server over real mTLS, in process**, with a throwaway CA and
   client/server leaves minted here. That is what makes "the transport works"
   a claim about TLS handshakes and HTTP/2 framing rather than about a mock.

Layer 3 is still not the end-to-end proof: it does not run the actual
`control-plane-api` binary, so it cannot catch a contract mismatch between this
client and the Rust service. The live container test is what does that, and it
is in addition to this, not replaced by it.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import socket
import stat
from concurrent import futures
from pathlib import Path

import pytest

from apex_sdk.control_transport import (
    MAX_CREDENTIAL_BYTES,
    POLL_COMMANDS_METHOD,
    AgentControlCredentials,
    ControlPollError,
    GrpcControlTransport,
    InMemoryControlPoller,
    PendingControlCommand,
    PollResult,
    decode_poll_response,
    encode_poll_request,
)
from apex_sdk.errors import ConfigurationError

grpc = pytest.importorskip("grpc")
cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402


# ---------------------------------------------------------------------------
# Wire codec
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


def _string_field(field: int, text: str) -> bytes:
    body = text.encode("utf-8")
    return _tag(field, 2) + _varint(len(body)) + body


def _varint_field(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _bytes_field(field: int, body: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(body)) + body


def _pending_command(
    *,
    command_id: str = "018f0000-0000-7000-8000-000000000001",
    action: int = 1,
    reason_code: str | None = "operator.request",
    attempt: int = 1,
    extra: bytes = b"",
) -> bytes:
    body = (
        _string_field(1, command_id)
        + _string_field(2, "acme")
        + _string_field(3, "prod")
        + _string_field(4, "agent-a")
        + _string_field(5, "run-1")
        + _string_field(6, "trace-1")
        + _varint_field(7, action)
    )
    if reason_code is not None:
        body += _string_field(8, reason_code)
    body += _string_field(10, "2026-08-08T00:00:00.000000Z")
    body += _varint_field(11, attempt)
    return body + extra


def _poll_response(commands: list[bytes], agent_id: str = "agent-a", interval: int = 1) -> bytes:
    body = b"".join(_bytes_field(1, command) for command in commands)
    return body + _string_field(2, agent_id) + _varint_field(3, interval)


def test_a_request_carries_no_target_selector_and_omits_the_default_limit():
    # The empty encoding is the whole point: there is no agent_id/run_id/
    # workspace field to put on the wire, so a client cannot ask for another
    # agent's commands even by constructing the request by hand.
    assert encode_poll_request(0) == b""
    assert encode_poll_request(1) == b"\x08\x01"
    assert encode_poll_request(300) == b"\x08" + _varint(300)


def test_a_negative_or_non_integer_limit_is_refused():
    for bad in (-1, True, 1.5, "4", None):
        with pytest.raises(ConfigurationError):
            encode_poll_request(bad)  # type: ignore[arg-type]


def test_a_stop_command_round_trips_every_field():
    result = decode_poll_response(_poll_response([_pending_command()]))
    assert result.agent_id == "agent-a"
    assert result.min_poll_interval_seconds == 1
    assert len(result.commands) == 1
    command = result.commands[0]
    assert command.command_id == "018f0000-0000-7000-8000-000000000001"
    assert command.workspace_id == "acme"
    assert command.namespace_id == "prod"
    assert command.agent_id == "agent-a"
    assert command.run_id == "run-1"
    assert command.trace_id == "trace-1"
    assert command.action == "stop"
    assert command.reason_code == "operator.request"
    assert command.issued_at == "2026-08-08T00:00:00.000000Z"
    assert command.delivery_attempt == 1
    assert result.first_stop() is command


def test_an_empty_response_is_the_normal_case_not_an_error():
    result = decode_poll_response(b"")
    assert result.commands == ()
    assert result.agent_id == ""
    assert result.first_stop() is None


def test_every_defined_action_decodes_and_an_unknown_one_stays_inert():
    names = {1: "stop", 2: "pause", 3: "resume", 4: "inject", 5: "set_budget"}
    for value, name in names.items():
        result = decode_poll_response(_poll_response([_pending_command(action=value)]))
        assert result.commands[0].action == name
    # An action from a newer gateway must not be guessed at: it decodes as
    # "unspecified", which no runtime enacts.
    future = decode_poll_response(_poll_response([_pending_command(action=99)]))
    assert future.commands[0].action == "unspecified"
    assert future.first_stop() is None


def test_first_stop_skips_actions_this_pass_does_not_enact():
    response = _poll_response([_pending_command(action=2), _pending_command(action=1, command_id="stop-id")])
    result = decode_poll_response(response)
    assert result.first_stop() is not None
    assert result.first_stop().command_id == "stop-id"


def test_unknown_fields_and_the_parameters_struct_are_skipped_not_rejected():
    # `parameters` (field 9) is skipped by design, and a field the client has
    # never heard of must not break it -- a gateway that starts sending new
    # fields cannot be allowed to brick older agents.
    extra = _bytes_field(9, b"\x0a\x03abc") + _varint_field(77, 5) + _bytes_field(78, b"xyz")
    body = _poll_response([_pending_command(extra=extra)])
    body += _tag(64, 5) + b"\x00\x00\x00\x00"  # unknown fixed32 at the top level
    body += _tag(65, 1) + b"\x00" * 8  # unknown fixed64 at the top level
    result = decode_poll_response(body)
    assert result.commands[0].action == "stop"


def test_a_missing_reason_code_decodes_as_none():
    result = decode_poll_response(_poll_response([_pending_command(reason_code=None)]))
    assert result.commands[0].reason_code is None


@pytest.mark.parametrize(
    "body",
    [
        b"\x08",  # varint runs off the end
        _tag(1, 2) + _varint(40) + b"short",  # length-delimited runs off the end
        _tag(1, 3),  # deprecated group encoding
        _tag(0, 0) + b"\x01",  # field number zero
        _tag(2, 2) + _varint(2) + b"\xff\xfe",  # invalid UTF-8 in agent_id
        _tag(1, 5) + b"\x00\x00",  # truncated fixed32
        _tag(1, 1) + b"\x00\x00\x00",  # truncated fixed64
        b"\xff" * 12,  # varint longer than 64 bits
    ],
)
def test_a_malformed_response_is_a_typed_non_retryable_error(body):
    with pytest.raises(ControlPollError) as caught:
        decode_poll_response(body)
    assert caught.value.code == "CONTROL_POLL_PROTOCOL_VIOLATION"
    assert caught.value.retryable is False


def test_a_command_whose_action_is_not_a_varint_is_refused():
    body = _poll_response([_string_field(1, "id") + _string_field(7, "stop")])
    with pytest.raises(ControlPollError):
        decode_poll_response(body)


def test_a_response_that_is_not_bytes_is_refused():
    with pytest.raises(ControlPollError):
        decode_poll_response("not bytes")  # type: ignore[arg-type]


def test_an_oversized_response_is_refused_before_it_is_parsed():
    with pytest.raises(ControlPollError) as caught:
        decode_poll_response(b"\x00" * (4 * 1024 * 1024 + 1))
    assert caught.value.code == "CONTROL_POLL_RESPONSE_TOO_LARGE"


def test_a_commands_field_that_is_not_length_delimited_is_refused():
    with pytest.raises(ControlPollError):
        decode_poll_response(_varint_field(1, 3))


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
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "apex-sdk-test-ca")])
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
    server_key, server_cert = _issue(ca_key, ca_cert, "control-plane-api", server=True)
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
        ("token", b"agent-a-token-abcdefgh\n", True),
    ):
        path = tmp_path / name
        path.write_bytes(blob)
        if os.name == "posix":
            path.chmod(0o600 if private else 0o644)
        paths[name] = path
    return paths


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


def test_credentials_load_from_files_and_strip_the_token(credential_files):
    credentials = AgentControlCredentials.from_files(
        ca_file=credential_files["ca.pem"],
        client_certificate_file=credential_files["client.pem"],
        client_key_file=credential_files["client.key"],
        token_file=credential_files["token"],
    )
    assert credentials.token == "agent-a-token-abcdefgh"
    assert credentials.ca_certificate.startswith(b"-----BEGIN CERTIFICATE-----")
    assert credentials.client_key.startswith(b"-----BEGIN RSA PRIVATE KEY-----")


def test_supplying_both_or_neither_token_source_is_refused(credential_files):
    common = {
        "ca_file": credential_files["ca.pem"],
        "client_certificate_file": credential_files["client.pem"],
        "client_key_file": credential_files["client.key"],
    }
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(**common)
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            **common, token="literal-token-abcdefgh", token_file=credential_files["token"]
        )


@pytest.mark.parametrize("token", ["", "   ", "has space", "téken"])
def test_a_token_that_could_never_be_sent_in_a_bearer_header_is_refused(credential_files, token):
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token=token,
        )


def test_a_missing_credential_file_is_a_typed_configuration_error(tmp_path, credential_files):
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=tmp_path / "nope.pem",
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_a_directory_is_not_a_credential_file(tmp_path, credential_files):
    directory = tmp_path / "a-directory"
    directory.mkdir()
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=directory,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_an_empty_or_oversized_credential_file_is_refused(tmp_path, credential_files):
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=empty,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )
    huge = tmp_path / "huge.pem"
    huge.write_bytes(b"x" * (MAX_CREDENTIAL_BYTES + 1))
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=huge,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


def test_a_symlinked_credential_path_is_refused(tmp_path, credential_files):
    link = tmp_path / "linked-ca.pem"
    try:
        link.symlink_to(credential_files["ca.pem"])
    except (OSError, NotImplementedError):
        pytest.skip("this platform does not permit creating symlinks unprivileged")
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=link,
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are only meaningful on POSIX")
def test_a_world_readable_private_key_is_refused(credential_files):
    credential_files["client.key"].chmod(0o644)
    with pytest.raises(ConfigurationError):
        AgentControlCredentials.from_files(
            ca_file=credential_files["ca.pem"],
            client_certificate_file=credential_files["client.pem"],
            client_key_file=credential_files["client.key"],
            token="literal-token-abcdefgh",
        )
    assert stat.S_IMODE(credential_files["client.key"].stat().st_mode) == 0o644


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
def test_a_malformed_endpoint_is_refused(pki, endpoint):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport(endpoint, _credentials(pki))  # type: ignore[arg-type]


def test_credentials_must_be_the_typed_object(pki):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport("localhost:9443", {"token": "x"})  # type: ignore[arg-type]


@pytest.mark.parametrize("timeout", [0, -1, 301, True, "5"])
def test_an_out_of_range_timeout_is_refused(pki, timeout):
    with pytest.raises(ConfigurationError):
        GrpcControlTransport("localhost:9443", _credentials(pki), timeout_seconds=timeout)  # type: ignore[arg-type]


def test_the_missing_grpc_extra_is_a_typed_configuration_error(monkeypatch, pki):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "grpc":
            raise ImportError("no grpc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ConfigurationError) as caught:
        GrpcControlTransport("localhost:9443", _credentials(pki))
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


def test_a_real_mtls_poll_returns_the_stop_and_sends_the_bearer_credential(pki):
    handler = _RecordingHandler(_poll_response([_pending_command()]))
    server, port = _serve(pki, handler)
    try:
        with GrpcControlTransport(
            f"127.0.0.1:{port}",
            _credentials(pki),
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


def test_a_client_with_no_certificate_cannot_complete_the_handshake(pki):
    handler = _RecordingHandler(_poll_response([]))
    server, port = _serve(pki, handler)
    try:
        anonymous = AgentControlCredentials(
            ca_certificate=pki["ca_pem"],
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


def test_a_server_rejection_surfaces_as_the_matching_typed_error(pki):
    handler = _RecordingHandler(b"", abort_with=grpc.StatusCode.UNAUTHENTICATED)
    server, port = _serve(pki, handler)
    try:
        with GrpcControlTransport(
            f"127.0.0.1:{port}", _credentials(pki), server_hostname="localhost", timeout_seconds=10
        ) as transport:
            with pytest.raises(ControlPollError) as caught:
                transport.poll()
    finally:
        server.stop(0).wait()
    assert caught.value.code == "CONTROL_POLL_AUTHENTICATION_FAILED"
    assert caught.value.retryable is False


def test_polling_a_closed_transport_is_refused(pki):
    handler = _RecordingHandler(_poll_response([]))
    server, port = _serve(pki, handler)
    try:
        transport = GrpcControlTransport(
            f"127.0.0.1:{port}", _credentials(pki), server_hostname="localhost", timeout_seconds=5
        )
        assert transport.endpoint == f"127.0.0.1:{port}"
        transport.poll()
        transport.close()
        with pytest.raises(ControlPollError) as caught:
            transport.poll()
    finally:
        server.stop(0).wait()
    assert caught.value.code == "CONTROL_POLL_TRANSPORT_CLOSED"


def test_a_channel_close_failure_is_typed(pki, monkeypatch):
    class _BrokenChannel:
        def unary_unary(self, *_args, **_kwargs):
            return lambda *a, **k: b""

        def close(self):
            raise RuntimeError("channel is wedged")

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(pki),
        channel_factory=lambda *_a, **_k: _BrokenChannel(),
    )
    with pytest.raises(ControlPollError) as caught:
        transport.close()
    assert caught.value.code == "CONTROL_TRANSPORT_CLOSE_FAILED"


def test_an_untyped_transport_fault_is_still_a_typed_error(pki):
    class _AngryChannel:
        def unary_unary(self, *_args, **_kwargs):
            def invoke(*_a, **_k):
                raise RuntimeError("something unexpected")

            return invoke

        def close(self):
            return None

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(pki),
        channel_factory=lambda *_a, **_k: _AngryChannel(),
    )
    with pytest.raises(ControlPollError) as caught:
        transport.poll()
    assert caught.value.code == "CONTROL_POLL_FAILED"
    transport.close()


def test_a_decode_failure_from_the_wire_propagates_unchanged(pki):
    class _GarbageChannel:
        def unary_unary(self, *_args, **_kwargs):
            return lambda *a, **k: b"\x08"

        def close(self):
            return None

    transport = GrpcControlTransport(
        "127.0.0.1:1",
        _credentials(pki),
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
