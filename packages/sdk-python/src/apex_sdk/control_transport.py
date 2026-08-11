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

The message classes are generated from ``contracts/proto/apex/v1/control.proto`` and checked in under ``apex_sdk._generated``.
--------------------------------------
The generated runtime is optional and imported lazily. A bounded wire-shape
preflight keeps known fields with the wrong wire type fail-closed while the
generated classes perform message encoding and decoding; unknown fields remain
skippable as protobuf requires.

Two pieces of this module now live elsewhere, re-imported below so every
``apex_sdk.control_transport.X`` path -- including "private" names a few
tests reach into directly -- resolves exactly as before either split: the
self-contained Struct wire decoder ``decode_poll_response`` relies on
(``_struct_wire.py``, which ``ControlPollError`` moved into, see its
docstring for why), and the credential-file reading discipline
``ingest_transport`` also uses (``_credential_files.py``).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ._credential_files import MAX_CREDENTIAL_BYTES, _read_credential_file
from ._struct_wire import *  # noqa: F401,F403 -- re-exports that module's whole surface, see above
from .errors import ConfigurationError

__all__ = [
    "AgentControlCredentials",
    "ControlPollError",
    "ControlPoller",
    "GrpcControlTransport",
    "PendingControlCommand",
    "PollResult",
]

#: Bound on a single ``PollCommands`` response. Matches the gateway's own
#: request ceiling; a response larger than this is not something a cooperative
#: gateway produces.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

#: Fully-qualified method name. Must match ``contracts/proto/apex/v1/control.proto``.
POLL_COMMANDS_METHOD = "/apex.v1.ControlGateway/PollCommands"
ACK_COMMAND_METHOD = "/apex.v1.ControlGateway/AckCommand"

#: Wire values of ``apex.v1.ControlAction``.
_ACTION_NAMES = {
    0: "unspecified",
    1: "stop",
    2: "pause",
    3: "resume",
    4: "inject",
    5: "set_budget",
    6: "resolve_hold",
}


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

    def acknowledge(self, command: PendingControlCommand) -> bool: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------
# Generated protobuf adapters.
#
# The generated modules are imported lazily so importing ``apex_sdk`` still
# works without the optional protobuf/gRPC stack.  They are generated from
# ``contracts/proto/apex/v1/control.proto`` and are the only implementation of
# the message wire format used by this transport.
# --------------------------------------------------------------------------


def _generated_control_pb2() -> Any:
    try:
        from ._generated.apex.v1 import control_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise ControlPollError(
            "The control transport is missing its protobuf runtime.",
            code="CONTROL_POLL_CONFIGURATION_FAILED",
            retryable=False,
            cause="Install the control extra before using PollCommands.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[control]'",),
        ) from exc
    return control_pb2


def encode_poll_request(max_commands: int = 0) -> bytes:
    if not isinstance(max_commands, int) or isinstance(max_commands, bool) or max_commands < 0:
        raise ConfigurationError("max_commands must be a non-negative integer")
    return _generated_control_pb2().PollCommandsRequest(max_commands=max_commands).SerializeToString(
        deterministic=True
    )


def decode_poll_response(buffer: bytes) -> PollResult:
    response_object = buffer if hasattr(buffer, "commands") and hasattr(buffer, "agent_id") else None
    if response_object is None and not isinstance(buffer, (bytes, bytearray)):
        raise _malformed("the response body was not bytes")
    buffer = bytes(buffer) if response_object is None else response_object.SerializeToString(deterministic=True)
    if len(buffer) > MAX_RESPONSE_BYTES:
        raise ControlPollError(
            "The control gateway's response was larger than this client accepts.",
            code="CONTROL_POLL_RESPONSE_TOO_LARGE",
            retryable=False,
            cause="The response exceeded the client's bounded read ceiling.",
        )
    raw_commands: list[bytes] = []
    offset = 0
    while offset < len(buffer):
        field, wire, raw, offset = _read_field(buffer, offset)
        if field == 1:
            _require_wire(wire, _WIRE_LENGTH, "commands")
            raw_commands.append(bytes(raw))
            command_offset = 0
            while command_offset < len(raw):
                command_field, command_wire, command_raw, command_offset = _read_field(bytes(raw), command_offset)
                expected = {1: _WIRE_LENGTH, 2: _WIRE_LENGTH, 3: _WIRE_LENGTH, 4: _WIRE_LENGTH, 5: _WIRE_LENGTH, 6: _WIRE_LENGTH, 7: _WIRE_VARINT, 8: _WIRE_LENGTH, 9: _WIRE_LENGTH, 10: _WIRE_LENGTH, 11: _WIRE_VARINT}.get(command_field)
                if expected is None:
                    continue
                _require_wire(command_wire, expected, "a pending control command field")
                if command_field == 9:
                    _validate_struct_wire(bytes(command_raw))
        elif field == 2:
            _require_wire(wire, _WIRE_LENGTH, "agent_id")
        elif field == 3:
            _require_wire(wire, _WIRE_VARINT, "min_poll_interval_seconds")
    try:
        response = response_object or _generated_control_pb2().PollCommandsResponse.FromString(buffer)
        commands = []
        for index, command in enumerate(response.commands):
            # Preserve the original field bytes for Struct parameters. Some
            # protobuf runtimes drop unknown fields inside a map entry while
            # constructing the generated message; the bounded adapter keeps
            # those fields skippable as the protobuf contract requires.
            raw_parameters: bytes | None = None
            command_bytes = raw_commands[index]
            command_offset = 0
            while command_offset < len(command_bytes):
                command_field, command_wire, command_raw, command_offset = _read_field(command_bytes, command_offset)
                if command_field == 9 and command_wire == _WIRE_LENGTH:
                    raw_parameters = bytes(command_raw)
            parameters = _decode_struct(raw_parameters) if raw_parameters is not None else {}
            commands.append(
                PendingControlCommand(
                    command_id=command.command_id,
                    workspace_id=command.workspace_id,
                    namespace_id=command.namespace_id,
                    agent_id=command.agent_id,
                    run_id=command.run_id,
                    trace_id=command.trace_id,
                    action=_ACTION_NAMES.get(command.action, "unspecified"),
                    reason_code=command.reason_code if command.HasField("reason_code") else None,
                    issued_at=command.issued_at,
                    delivery_attempt=command.delivery_attempt,
                    parameters=parameters,
                )
            )
        return PollResult(
            commands=tuple(commands),
            agent_id=response.agent_id,
            min_poll_interval_seconds=response.min_poll_interval_seconds,
        )
    except ControlPollError:
        raise
    except Exception as exc:  # protobuf DecodeError is version-dependent
        raise _malformed("the response was not well-formed protobuf") from exc


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------


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
        from ._generated.apex.v1 import control_pb2_grpc

        stub = control_pb2_grpc.ControlGatewayStub(self._channel)
        self._invoke = stub.PollCommands
        self._acknowledge = stub.AckCommand

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
            request = _generated_control_pb2().PollCommandsRequest.FromString(payload)
            raw = self._invoke(
                request,
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

    def acknowledge(self, command: PendingControlCommand) -> bool:
        """Acknowledge one successfully enacted command.

        The gateway keeps its redelivery fallback when this call is lost or
        unavailable, so callers must still enact commands idempotently.
        """
        if self._closed:
            raise ControlPollError(
                "The control transport is closed.",
                code="CONTROL_ACK_TRANSPORT_CLOSED",
                retryable=False,
                cause="acknowledge() was called after close().",
            )
        grpc = _grpc_module()
        request = _generated_control_pb2().AckCommandRequest(
            workspace_id=command.workspace_id,
            namespace_id=command.namespace_id,
            command_id=command.command_id,
            delivery_attempt=command.delivery_attempt,
        )
        try:
            response = self._acknowledge(
                request,
                timeout=self._timeout,
                metadata=(("authorization", f"Bearer {self._credentials.token}"),),
            )
        except grpc.RpcError as exc:
            raise self._classify(exc) from None
        except ControlPollError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ControlPollError(cause="The control gateway acknowledgement failed.") from exc
        return bool(response.acknowledged or response.already_acknowledged)

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
        "ABORTED", "ALREADY_EXISTS", "CANCELLED", "DATA_LOSS", "DEADLINE_EXCEEDED",
        "FAILED_PRECONDITION", "INTERNAL", "INVALID_ARGUMENT", "NOT_FOUND", "OUT_OF_RANGE",
        "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "UNAUTHENTICATED", "UNAVAILABLE",
        "UNIMPLEMENTED", "UNKNOWN",
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
        self.acknowledgements: list[str] = []
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

    def acknowledge(self, command: PendingControlCommand) -> bool:
        self.acknowledgements.append(command.command_id)
        return True

    def close(self) -> None:
        self.closed = True
