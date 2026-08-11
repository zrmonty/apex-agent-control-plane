"""Shared pytest fixtures and test-data builders.

This package's test files were split from larger, single-file suites (see
each split file's own module docstring). This module holds the fixtures and
helper functions that ended up needed by more than one of the resulting
files -- pytest's standard mechanism for exactly that, so nothing here is
duplicated across files and no split file is left unable to find a fixture
it depends on.

Three independent groups live here, none sharing state with the others:

- ``control_pki`` and ``ingest_pki``: one throwaway CA plus server/client
  leaves each, for the ``control_transport`` and ``ingest_transport``
  in-process mTLS suites respectively. Built on shared certificate-issuing
  *mechanics* (`_rsa_key`, `_pem_key`, `_issue` -- identical between the two
  transports: same key size, same extensions), but kept as two distinctly
  named fixtures rather than one shared fixture, because the *identities*
  each asserts (CA subject, server common name) are meaningful test data,
  not incidental duplication, and each is used across more than one file
  split out of that transport's original single test file. The hand-rolled
  protobuf encode helpers (`_varint`/`_tag`/...) and the ingest-side decode
  helpers (`_fields`/`_only`/`_present`) that those two suites' split files
  need live here for the same reason.
- Reference-runtime test-data builders (`Sink`, `_loop`, `_command`,
  `_stop_command`, `_budget`, `_inject`, `ScriptedPoller`, `_drive`), used
  across the stop/pause/budget/inject/hold enactment test files that were
  split out of the original `test_reference_runtime.py`.
"""

from __future__ import annotations

import datetime as dt
import ipaddress

import pytest

from apex_sdk import (
    PendingControlCommand,
    PollResult,
    ReferenceReasonActLoop,
)
from apex_sdk.event import EventBuilder

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402


# ---------------------------------------------------------------------------
# PKI mechanics shared by the control_transport and ingest_transport
# in-process mTLS suites. Each transport's own test file builds its
# `*_pki` fixture on top of these; the identities are transport-specific,
# the mechanics below are not.
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
def control_pki():
    """A throwaway CA plus a ``control-plane-api`` server leaf and an agent
    workload client leaf, for ``control_transport``'s in-process mTLS tests.
    """
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


@pytest.fixture(scope="module")
def ingest_pki():
    """A throwaway CA plus an ``event-ingest`` server leaf and an agent
    workload client leaf, for ``ingest_transport``'s in-process mTLS tests.
    """
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


# ---------------------------------------------------------------------------
# Hand-rolled protobuf varint/tag encoding, and a `PollCommandsResponse`
# builder on top of it. `_varint`/`_tag` are generic and byte-identical to
# ingest_transport's own copies (both transports' test suites minted this
# independently); `_pending_command`/`_poll_response` build the
# control-transport-specific message shape and are needed by both
# test_control_transport.py (the wire codec, exhaustively) and
# test_control_transport_live.py (to script canned server responses).
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


# ---------------------------------------------------------------------------
# ingest_transport: a hand-rolled reader (the mirror image of the `_string_field`
# style builders above -- these decode what an encoder produced, rather than
# building input for a decoder), an event-builder, and a shared credentials
# helper. Needed across most of the files split out of the original
# test_ingest_transport.py: the Struct-encoder, envelope-encoder, credentials,
# pre-send-integrity-guard, and live-mTLS suites.
# ---------------------------------------------------------------------------


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


EVENT_ID = "018f5c91-2d88-7c00-8000-0000000000aa"


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


def _ingest_credentials(pki):
    from apex_sdk.ingest_transport import AgentIngestCredentials

    return AgentIngestCredentials(
        ca_certificate=pki["ca_pem"],
        client_certificate=pki["client_cert_pem"],
        client_key=pki["client_key_pem"],
        token="gateway-ref-token",
    )


# ---------------------------------------------------------------------------
# Reference-runtime test-data builders, shared across the stop/pause/budget/
# inject/hold enactment test files split out of test_reference_runtime.py.
# ---------------------------------------------------------------------------


class Sink:
    def __init__(self):
        self.events = []

    def write(self, event):
        self.events.append(event)

    def close(self):
        pass


def _loop(observer, control=None, **kwargs):
    return ReferenceReasonActLoop(
        observer,
        agent_id="agent",
        scope={"workspace_id": "acme", "namespace_id": "prod", "agent_group_ids": []},
        version={"agent_code": "v1", "prompt": "p1", "model": "gpt-5"},
        control=control,
        **kwargs,
    )


def _command(action, *, command_id, reason_code=None, parameters=None):
    return PendingControlCommand(
        command_id=command_id,
        workspace_id="acme",
        namespace_id="prod",
        agent_id="agent",
        run_id="run-1",
        trace_id="trace-1",
        action=action,
        reason_code=reason_code,
        issued_at="2026-08-08T00:00:00.000000Z",
        delivery_attempt=1,
        parameters=dict(parameters or {}),
    )


def _budget(limit, *, command_id="cmd-budget-1", kind="cost"):
    return _command(
        "set_budget", command_id=command_id, parameters={"budget_kind": kind, "limit": limit}
    )


def _inject(content, *, command_id="cmd-inject-1", classification="untrusted", reason_code=None):
    return _command(
        "inject",
        command_id=command_id,
        reason_code=reason_code,
        parameters={"content": content, "content_classification": classification},
    )


def _stop_command(reason_code="operator.request", command_id="018f0000-0000-7000-8000-000000000001"):
    return _command("stop", command_id=command_id, reason_code=reason_code)


class ScriptedPoller:
    """Returns one scripted batch of commands per poll, then nothing.

    Unlike ``InMemoryControlPoller`` this models *turns*: batch ``n`` is what
    the gateway hands back on the ``n``-th poll, which is how a runtime driven
    across many ``run()`` calls actually experiences the control channel.
    """

    def __init__(self, batches, *, agent_id="agent"):
        self._batches = list(batches)
        self._agent_id = agent_id
        self.polls = 0
        self.closed = False

    def poll(self, *, max_commands=0):
        batch = self._batches[self.polls] if self.polls < len(self._batches) else ()
        self.polls += 1
        return PollResult(
            commands=tuple(batch), agent_id=self._agent_id, min_poll_interval_seconds=1
        )

    def close(self):
        self.closed = True


def _drive(loop, turns, tool_calls):
    """Runs ``turns`` turns on one loop, recording which ones ran the tool."""
    terminals = []
    for turn in range(turns):
        events = loop.run(
            f"prompt-{turn}", tool=lambda value: tool_calls.append(value) or "result"
        )
        terminals.append(events[-1]["data"])
    return terminals
