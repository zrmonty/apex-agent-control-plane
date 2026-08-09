"""Real gRPC + mTLS client for the control gateway's ``PollCommands`` RPC.

This is the SDK half of the out-of-band control channel: the code that lets an
instrumented runtime discover that an operator has told it to stop. Until it
existed, ``ControlGateway.SubmitCommand`` produced a durable, audited record
that nothing could ever read back.

Scope, deliberately narrow
--------------------------
One RPC. It opens an mTLS channel to ``control-plane-api`` using the agent's
own workload certificate and key, calls ``PollCommands``, and returns what came
back. It does not submit commands (that is an operator's authority, not an
agent's), and it is not a general ingest transport.

**The adjacent gap this module used to flag is now closed.** When this was
written, ``exporter.GrpcIngestTransport`` was a ``Protocol`` with no concrete
implementation anywhere in the repository -- the only thing satisfying it was
``InMemoryIdempotentIngest``, a test double -- so the SDK had no real
event-ingest transport. ``ingest_transport.GrpcEventIngestTransport`` is that
implementation, and it deliberately mirrors this module's credential loading,
channel construction and error-classification shape rather than inventing a
second style. It also *encodes* a ``google.protobuf.Struct``, which is the
mirror image of the decoder below; the two are tested against each other.

Why the wire format is encoded by hand
--------------------------------------
This package has no protobuf code-generation step and no ``protobuf`` runtime
dependency, and adding both to ship one read-only RPC would be a larger change
to the SDK's build and dependency surface than the RPC itself. ``grpcio``
accepts arbitrary ``request_serializer`` / ``response_deserializer`` callables,
so the two messages are encoded and decoded here directly. The decoder skips
unknown fields the way any protobuf implementation must, so a gateway that
starts sending new fields does not break an older client.

**Flagged for the owner, and now more sharply than when this module was
written:** the codec has grown a ``google.protobuf.Struct`` decoder, because
``set_budget`` and ``inject`` carry their whole meaning in ``parameters`` and a
client that skips that field cannot enact either. That is a well-specified,
closed piece of the protobuf JSON mapping rather than a third ad-hoc message,
and it is bounded on depth and entry count -- but it is the point at which
"generate the stubs instead" stops being a preference and becomes the right
answer for the next addition.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
import struct as _struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .errors import ApexError, ConfigurationError

__all__ = [
    "AgentControlCredentials",
    "ControlPollError",
    "ControlPoller",
    "GrpcControlTransport",
    "PendingControlCommand",
    "PollResult",
]

#: Bound on any credential file this module reads. A workload certificate,
#: key, CA bundle or bearer token that is larger than this is a
#: misconfiguration, and reading it unbounded would let a mounted file decide
#: how much memory the agent process allocates.
MAX_CREDENTIAL_BYTES = 1024 * 1024

#: Bound on a single ``PollCommands`` response. Matches the gateway's own
#: request ceiling; a response larger than this is not something a cooperative
#: gateway produces.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

#: Fully-qualified method name. Must match ``contracts/proto/apex/v1/control.proto``.
POLL_COMMANDS_METHOD = "/apex.v1.ControlGateway/PollCommands"

#: Wire values of ``apex.v1.ControlAction``.
_ACTION_NAMES = {
    0: "unspecified",
    1: "stop",
    2: "pause",
    3: "resume",
    4: "inject",
    5: "set_budget",
}

_WIRE_VARINT = 0
_WIRE_FIXED64 = 1
_WIRE_LENGTH = 2
_WIRE_FIXED32 = 5


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


@dataclass(frozen=True)
class PendingControlCommand:
    """One command the gateway is delivering to this agent."""

    command_id: str
    workspace_id: str
    namespace_id: str
    agent_id: str
    run_id: str
    trace_id: str
    action: str
    reason_code: str | None
    issued_at: str
    delivery_attempt: int
    #: The operator-submitted action parameters, decoded from
    #: ``google.protobuf.Struct``. Empty for actions that take none.
    #:
    #: **This is data, never instructions.** ``inject.content`` in particular
    #: is explicitly untrusted operator-supplied text (ADR-0005), and nothing
    #: in this SDK parses it, dispatches on it, or lets it influence a control
    #: decision. Defaulted last so existing positional construction is
    #: unaffected.
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PollResult:
    commands: tuple[PendingControlCommand, ...]
    #: The agent identity the *gateway* resolved from the presented credential.
    #: Never taken from local configuration: comparing it against the identity
    #: this process believes it has is how a mis-issued credential becomes a
    #: loud mismatch instead of a silent stream of another agent's commands.
    agent_id: str
    min_poll_interval_seconds: int

    def first_stop(self) -> PendingControlCommand | None:
        """The oldest pending ``stop``, if any."""
        for command in self.commands:
            if command.action == "stop":
                return command
        return None


class ControlPoller(Protocol):
    """What a runtime needs from a control channel to enact a ``stop``.

    Narrow on purpose. A runtime should be able to accept the real transport,
    an in-process fake, or a future subscription-based implementation without
    any of them having to grow the others' surface.
    """

    def poll(self, *, max_commands: int = 0) -> PollResult: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------
# Minimal protobuf wire codec (see the module docstring for why).
# --------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ControlPollError(
            "The poll request could not be encoded.",
            code="CONTROL_POLL_ENCODE_FAILED",
            retryable=False,
            cause="A negative value cannot be encoded as a protobuf varint.",
        )
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


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


def _decode_struct(buffer: bytes, depth: int = 0) -> dict[str, Any]:
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


def encode_poll_request(max_commands: int = 0) -> bytes:
    """Encodes ``apex.v1.PollCommandsRequest``.

    The only field is ``max_commands``, and proto3 omits it when zero. There is
    no target selector to encode, by design: the gateway derives which agent is
    calling from the presented credential.
    """
    if not isinstance(max_commands, int) or isinstance(max_commands, bool) or max_commands < 0:
        raise ConfigurationError("max_commands must be a non-negative integer")
    if max_commands == 0:
        return b""
    return bytes([0x08]) + _encode_varint(max_commands)


def _decode_pending_command(buffer: bytes) -> PendingControlCommand:
    fields: dict[int, Any] = {}
    parameters: dict[str, Any] = {}
    offset = 0
    while offset < len(buffer):
        field_number, _wire_type, value, offset = _read_field(buffer, offset)
        # Field 9 is `parameters` (google.protobuf.Struct), where `set_budget`
        # and `inject` carry their entire meaning. A client that skipped it --
        # as the first-pass client did, when only `stop` was enacted -- cannot
        # enact either.
        if field_number == 9:
            if not isinstance(value, (bytes, bytearray)):
                raise _malformed("parameters was not length-delimited")
            parameters = _decode_struct(bytes(value))
            continue
        fields[field_number] = value
    action_value = fields.get(7, 0)
    if not isinstance(action_value, int):
        raise _malformed("action was not a varint")
    return PendingControlCommand(
        command_id=_decode_text(fields.get(1, b""), "command_id"),
        workspace_id=_decode_text(fields.get(2, b""), "workspace_id"),
        namespace_id=_decode_text(fields.get(3, b""), "namespace_id"),
        agent_id=_decode_text(fields.get(4, b""), "agent_id"),
        run_id=_decode_text(fields.get(5, b""), "run_id"),
        trace_id=_decode_text(fields.get(6, b""), "trace_id"),
        # An action this client does not know is reported as "unspecified"
        # rather than guessed at. A runtime only enacts actions it recognises,
        # so an unknown one is inert instead of dangerous.
        action=_ACTION_NAMES.get(action_value, "unspecified"),
        reason_code=_decode_text(fields[8], "reason_code") if 8 in fields else None,
        issued_at=_decode_text(fields.get(10, b""), "issued_at"),
        delivery_attempt=fields.get(11, 0) if isinstance(fields.get(11, 0), int) else 0,
        parameters=parameters,
    )


def decode_poll_response(buffer: bytes) -> PollResult:
    """Decodes ``apex.v1.PollCommandsResponse``."""
    if not isinstance(buffer, (bytes, bytearray)):
        raise _malformed("the response body was not bytes")
    buffer = bytes(buffer)
    if len(buffer) > MAX_RESPONSE_BYTES:
        raise ControlPollError(
            "The control gateway's response was larger than this client accepts.",
            code="CONTROL_POLL_RESPONSE_TOO_LARGE",
            retryable=False,
            cause="The response exceeded the client's bounded read ceiling.",
        )
    commands: list[PendingControlCommand] = []
    agent_id = ""
    min_poll_interval_seconds = 0
    offset = 0
    while offset < len(buffer):
        field_number, _wire_type, value, offset = _read_field(buffer, offset)
        if field_number == 1:
            if not isinstance(value, (bytes, bytearray)):
                raise _malformed("commands was not length-delimited")
            commands.append(_decode_pending_command(bytes(value)))
        elif field_number == 2:
            agent_id = _decode_text(value, "agent_id")
        elif field_number == 3:
            min_poll_interval_seconds = value if isinstance(value, int) else 0
        # Anything else is a field this client does not know about; skipping is
        # required protobuf behaviour, not leniency.
    return PollResult(
        commands=tuple(commands),
        agent_id=agent_id,
        min_poll_interval_seconds=min_poll_interval_seconds,
    )


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------


def _read_credential_file(path: Path, label: str, *, private: bool) -> bytes:
    """Reads one credential file under the SDK's usual path discipline.

    Symlinks are refused, size is bounded, and private material is refused if
    it is readable beyond its owner -- the same rules the Rust services apply
    to the same files, so a deployment cannot end up with an agent that happily
    reads key material its own gateway would reject.
    """
    try:
        if path.is_symlink():
            raise ConfigurationError(f"{label} must not be a symbolic link")
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise ConfigurationError(f"{label} is not available at the configured path") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{label} must be a regular file")
    if info.st_size == 0 or info.st_size > MAX_CREDENTIAL_BYTES:
        raise ConfigurationError(f"{label} has an invalid size")
    # Windows ACLs do not map onto POSIX mode bits; enforce where they mean
    # something, exactly as bundle.py already does for trust directories.
    if private and os.name == "posix" and info.st_mode & 0o077:
        raise ConfigurationError(f"{label} permissions are too broad; it must be readable only by its owner")
    try:
        return resolved.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"{label} could not be read") from exc


@dataclass(frozen=True)
class AgentControlCredentials:
    """The agent workload's own mTLS identity and bearer credential.

    Both halves are required. The bearer credential alone is not sufficient at
    the gateway -- it is pinned to this certificate -- which is what makes a
    leaked token unusable from anywhere else.
    """

    ca_certificate: bytes
    client_certificate: bytes
    #: Private material, excluded from ``repr``. A dataclass prints every field
    #: by default, so ``logging.debug("%r", credentials)``, a pytest
    #: ``--showlocals`` traceback, or any exception rendering local variables
    #: would otherwise put the workload private key and the bearer token into a
    #: log. Neither is ever needed to identify a credential object.
    client_key: bytes = field(repr=False)
    token: str = field(repr=False)

    @classmethod
    def from_files(
        cls,
        *,
        ca_file: str | Path,
        client_certificate_file: str | Path,
        client_key_file: str | Path,
        token: str | None = None,
        token_file: str | Path | None = None,
    ) -> "AgentControlCredentials":
        if (token is None) == (token_file is None):
            raise ConfigurationError("supply exactly one of token or token_file")
        if token_file is not None:
            raw = _read_credential_file(Path(token_file), "agent control token", private=True)
            token = raw.decode("utf-8", errors="strict").strip()
        if not token or any(character.isspace() for character in token) or not token.isascii():
            raise ConfigurationError("the agent control token must be non-empty printable ASCII with no whitespace")
        return cls(
            ca_certificate=_read_credential_file(Path(ca_file), "control gateway CA certificate", private=False),
            client_certificate=_read_credential_file(
                Path(client_certificate_file), "agent workload certificate", private=False
            ),
            client_key=_read_credential_file(Path(client_key_file), "agent workload private key", private=True),
            token=token,
        )


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


def _grpc_module() -> Any:
    """Imports ``grpc`` lazily.

    Lazy so that importing ``apex_sdk`` never requires ``grpcio``: the SDK's
    event-building, validation and bundle surfaces are useful without a control
    channel, and making every consumer install a gRPC stack to use them would
    be a real cost for a narrow feature.
    """
    try:
        import grpc  # noqa: PLC0415 -- deliberately deferred; see the docstring.
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ConfigurationError(
            "the control transport requires the grpc extra: pip install 'apex-sdk[control]'"
        ) from exc
    return grpc


#: gRPC status codes worth retrying. Everything else is a decision the gateway
#: made about this caller, and retrying it just produces the same answer more
#: often -- which on an authentication failure is also how a workload burns
#: through the gateway's per-identity failure budget.
_RETRYABLE_STATUSES = frozenset({"UNAVAILABLE", "DEADLINE_EXCEEDED", "RESOURCE_EXHAUSTED"})


class GrpcControlTransport:
    """Calls ``PollCommands`` over mTLS with the agent's workload identity."""

    def __init__(
        self,
        endpoint: str,
        credentials: AgentControlCredentials,
        *,
        server_hostname: str | None = None,
        timeout_seconds: float = 5.0,
        channel_factory: Any | None = None,
    ) -> None:
        if not isinstance(endpoint, str) or not endpoint or any(character.isspace() for character in endpoint):
            raise ConfigurationError("the control gateway endpoint must be a host:port string")
        # A scheme is refused rather than stripped. `grpc.secure_channel`
        # takes a bare authority, and quietly accepting "https://host:port"
        # here would mean the SDK and the gateway disagree about what the
        # configured value means.
        if "://" in endpoint:
            raise ConfigurationError("the control gateway endpoint must be host:port with no URL scheme")
        if not isinstance(credentials, AgentControlCredentials):
            raise ConfigurationError("control credentials must be an AgentControlCredentials")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 300:
            raise ConfigurationError("the control poll timeout must be a positive number of seconds up to 300")
        self._endpoint = endpoint
        self._credentials = credentials
        self._timeout = float(timeout_seconds)
        self._closed = False
        grpc = _grpc_module()
        channel_credentials = grpc.ssl_channel_credentials(
            root_certificates=credentials.ca_certificate,
            private_key=credentials.client_key,
            certificate_chain=credentials.client_certificate,
        )
        options: list[tuple[str, Any]] = [
            ("grpc.max_receive_message_length", MAX_RESPONSE_BYTES),
        ]
        if server_hostname is not None:
            # Only ever *narrows* what the client will accept: it selects which
            # name the server certificate must match, it does not disable the
            # check. There is no option here that turns verification off.
            options.append(("grpc.ssl_target_name_override", server_hostname))
        factory = channel_factory or grpc.secure_channel
        self._channel = factory(endpoint, channel_credentials, options=tuple(options))
        self._invoke = self._channel.unary_unary(
            POLL_COMMANDS_METHOD,
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def poll(self, *, max_commands: int = 0) -> PollResult:
        if self._closed:
            raise ControlPollError(
                "The control transport is closed.",
                code="CONTROL_POLL_TRANSPORT_CLOSED",
                retryable=False,
                cause="poll() was called after close().",
            )
        payload = encode_poll_request(max_commands)
        grpc = _grpc_module()
        try:
            raw = self._invoke(
                payload,
                timeout=self._timeout,
                # The bearer credential travels in metadata; the mTLS client
                # certificate is what binds it. Never logged, never placed in
                # an error message or diagnostic.
                metadata=(("authorization", f"Bearer {self._credentials.token}"),),
            )
        except grpc.RpcError as exc:
            raise self._classify(exc) from None
        except ControlPollError:
            raise
        except Exception as exc:  # noqa: BLE001 - any transport fault must surface typed
            raise ControlPollError(cause="The control transport raised an untyped error.") from exc
        return decode_poll_response(raw)

    def close(self) -> None:
        self._closed = True
        try:
            self._channel.close()
        except Exception as exc:  # noqa: BLE001 - a close fault must still be typed
            raise ControlPollError(
                "The control transport could not be closed cleanly.",
                code="CONTROL_TRANSPORT_CLOSE_FAILED",
                retryable=True,
                cause="The gRPC channel raised an untyped error during close.",
                recommended_next_steps=("Retry shutdown after the control gateway recovers.",),
            ) from exc

    def __enter__(self) -> "GrpcControlTransport":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @staticmethod
    def _status_name(error: Any) -> str:
        """Extracts the gRPC status name without ever touching ``details()``.

        Server-supplied detail strings are attacker-influenced text from this
        client's point of view, and this SDK's errors are deliberately built
        from static, review-approved messages. So only the enumerated status
        code crosses the boundary.
        """
        code = getattr(error, "code", None)
        value = code() if callable(code) else code
        name = getattr(value, "name", None)
        return name if isinstance(name, str) else "UNKNOWN"

    @classmethod
    def _classify(cls, error: Any) -> ControlPollError:
        status = cls._status_name(error)
        if status == "UNAUTHENTICATED":
            return ControlPollError(
                "The control gateway rejected this agent's workload credential.",
                code="CONTROL_POLL_AUTHENTICATION_FAILED",
                category="authentication",
                retryable=False,
                cause="The control gateway returned UNAUTHENTICATED.",
                recommended_next_steps=(
                    "Confirm the agent workload certificate and bearer credential are the pair the gateway registered.",
                    "Confirm the credential has not been rotated out from under this process.",
                ),
                context={"grpc_status": status},
            )
        if status == "PERMISSION_DENIED":
            return ControlPollError(
                "The control gateway denied this agent identity.",
                code="CONTROL_POLL_AUTHORIZATION_FAILED",
                category="authorization",
                retryable=False,
                cause="The control gateway returned PERMISSION_DENIED.",
                recommended_next_steps=(
                    "Confirm the agent credential is scoped to the workspace and namespace it runs in.",
                ),
                context={"grpc_status": status},
            )
        if status == "RESOURCE_EXHAUSTED":
            return ControlPollError(
                "The control gateway is rate-limiting this agent's polls.",
                code="CONTROL_POLL_RATE_LIMITED",
                retryable=True,
                cause="The control gateway returned RESOURCE_EXHAUSTED.",
                recommended_next_steps=(
                    "Honour min_poll_interval_seconds from the last successful poll.",
                ),
                context={"grpc_status": status},
            )
        if status in _RETRYABLE_STATUSES:
            return ControlPollError(
                "The control gateway is temporarily unavailable.",
                code="CONTROL_POLL_UNAVAILABLE",
                retryable=True,
                cause=f"The control gateway returned {status}.",
                context={"grpc_status": status},
            )
        if status == "UNIMPLEMENTED":
            return ControlPollError(
                "The control gateway does not implement PollCommands.",
                code="CONTROL_POLL_UNSUPPORTED",
                retryable=False,
                cause="The control gateway returned UNIMPLEMENTED.",
                recommended_next_steps=(
                    "Upgrade the control gateway to a build that serves PollCommands.",
                ),
                context={"grpc_status": status},
            )
        return ControlPollError(
            "The control gateway rejected the poll.",
            code="CONTROL_POLL_REJECTED",
            retryable=False,
            cause="The control gateway returned an unrecognized status.",
            recommended_next_steps=(
                "Verify the SDK and the control gateway are on the same contract version.",
            ),
            context={"grpc_status": status if status in _KNOWN_STATUS_NAMES else "UNRECOGNIZED"},
        )


_KNOWN_STATUS_NAMES = frozenset(
    {
        "ABORTED",
        "ALREADY_EXISTS",
        "CANCELLED",
        "DATA_LOSS",
        "DEADLINE_EXCEEDED",
        "FAILED_PRECONDITION",
        "INTERNAL",
        "INVALID_ARGUMENT",
        "NOT_FOUND",
        "OUT_OF_RANGE",
        "PERMISSION_DENIED",
        "RESOURCE_EXHAUSTED",
        "UNAUTHENTICATED",
        "UNAVAILABLE",
        "UNIMPLEMENTED",
        "UNKNOWN",
    }
)


class InMemoryControlPoller:
    """Deterministic ``ControlPoller`` for tests and offline runtime harnesses.

    The runtime-side counterpart of ``exporter.InMemoryIdempotentIngest``: it
    exists so an enactment path can be exercised without a live gateway, and it
    is explicitly *not* evidence that the live path works. That is what the
    end-to-end proof is for.
    """

    def __init__(self, commands: Sequence[PendingControlCommand] = (), *, agent_id: str = "agent") -> None:
        self._commands = list(commands)
        self._agent_id = agent_id
        self.polls = 0
        self.closed = False

    def poll(self, *, max_commands: int = 0) -> PollResult:
        self.polls += 1
        limit = len(self._commands) if max_commands <= 0 else max_commands
        delivered, self._commands = self._commands[:limit], self._commands[limit:]
        return PollResult(
            commands=tuple(delivered),
            agent_id=self._agent_id,
            min_poll_interval_seconds=1,
        )

    def close(self) -> None:
        self.closed = True
