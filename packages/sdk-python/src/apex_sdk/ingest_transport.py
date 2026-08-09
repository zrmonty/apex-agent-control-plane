"""Real gRPC + mTLS client for ``event-ingest``'s ``Ingest`` RPC.

This is the SDK's actual event-submission path: the code that takes a built,
validated, hash-chained envelope from :class:`apex_sdk.EventBuilder` and puts it
on the wire as ``apex.v1.EventEnvelope`` for a running ``apex-event-ingest``.

Until this module existed, ``exporter.GrpcIngestTransport`` was a ``Protocol``
with no concrete implementation anywhere in the repository -- the only thing
satisfying it was ``exporter.InMemoryIdempotentIngest``, a test double -- and
every "live" exercise of the ingest admission boundary was a Rust stand-in
client rather than this product SDK. See ``docs/phase-0.5-progress.md``.

Relationship to ``control_transport``
-------------------------------------
Deliberately the same shape, not a fork. Credential loading reuses
``control_transport._read_credential_file`` outright so the SDK has exactly one
set of rules for reading key material; channel construction, the
``ssl_target_name_override`` narrowing, the "never read ``details()``" status
classification, and the generated protobuf/gRPC stubs all mirror that module
rather than inventing a second style. What is genuinely new here is a
``google.protobuf.Struct`` **encoder**: ``control_transport`` only ever needed
to decode one, and an event's ``data`` field is an arbitrary JSON-like object
that has to be serialized on the way out.

The message classes are generated from ``contracts/proto/apex/v1/event.proto`` and checked in under ``apex_sdk._generated``.
--------------------------------------------
The generated runtime is optional and imported lazily. The encoder still
applies the SDK's explicit JSON, size, and depth bounds before handing values
to the generated ``Struct`` message.

Integrity: why this module re-derives the hash before sending
-------------------------------------------------------------
The whole project rests on a hash chain over the RFC 8785 (JCS) canonical form
of an event. ``google.protobuf.Struct`` is not a lossless container for that
form: every JSON number becomes an IEEE-754 double, so an encoder bug -- or
simply a value that cannot survive the trip -- would produce an envelope that
means something different from the dict that was hashed. The gateway would
recompute the canonical hash from what it received, disagree, and reject the
event as an integrity failure with no clue where the drift came from.

So before anything reaches the network, :class:`GrpcEventIngestTransport`
decodes its own encoded ``data`` back with ``control_transport._decode_struct``
-- the decoder that was already in the SDK and already CI-proven -- rebuilds the
event around the decoded value, and recomputes ``event_hash``. If it differs
from the hash the caller computed, the event is refused locally and nothing is
sent. That turns "the encoder silently changed the meaning of an event" from a
class of bug into a loud, local, fail-closed refusal, and it is why the encoder
and the decoder are tested against *each other* rather than each against its own
idea of what the wire format is.

Authentication targeted
-----------------------
mTLS **and** a bearer credential, both required, with the bearer credential
pinned to the exact client certificate. This is not a choice among modes: it is
the only thing the shipped ``event-ingest`` binary accepts.
``apps/event-ingest/src/startup/service.rs`` builds exactly one verifier,
``BearerTokenVerifier::new_strict(FileBearerResolver::…)``; ``new_strict``
refuses any request whose TLS peer presented no certificate, and
``FileBearerResolver::resolve_with_peer`` additionally requires
``sha256(peer_leaf) == APEX_BEARER_CERT_SHA256``. ``BearerTokenResolver`` is a
public trait a deployment could implement differently -- a workload-identity-only
resolver would be a legal implementation -- but no such implementation exists in
this repository, and the trait's default ``resolve_with_peer`` **fails closed**
when a peer certificate is present. There is therefore no mTLS-only path to
target, and offering one here would be inventing a client for a server that does
not exist.

Note for anyone comparing this with ``control_transport``: the two services were
built to be independently authenticated, and their credentials differ in a way
that matters operationally. ``control-plane-api`` reads a *table* of
``token|cert_sha256|agent_id|scopes`` rows, so one file describes many agents.
``event-ingest``'s ``APEX_BEARER_TOKEN_FILE`` is the raw token and nothing else,
with agent id, scopes and pinned fingerprint supplied by separate environment
variables -- a deliberately single-agent staging credential, gated behind an
explicit ``APEX_FILE_BEARER_MODE=single-agent-staging`` acknowledgement. The
metadata header is ``authorization: Bearer …`` for both, which was verified
against ``apps/event-ingest/src/auth/verifier.rs`` rather than assumed from the
control gateway. Do not feed one service's credential file to the other's
loader.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .control_transport import (
    MAX_STRUCT_DEPTH,
    MAX_STRUCT_ENTRIES,
    _decode_struct,
    _read_credential_file,
    _read_field,
)
from .errors import ApexError, ConfigurationError
from .event import event_hash
from .exporter import GrpcStatusError

__all__ = [
    "ACTOR_TYPE_VALUES",
    "EVENT_TYPE_VALUES",
    "INGEST_METHOD",
    "MAX_ENVELOPE_BYTES",
    "AgentIngestCredentials",
    "EventEncodingError",
    "GrpcEventIngestTransport",
    "decode_ingest_response",
    "encode_event_envelope",
    "encode_struct",
]

#: Fully-qualified method name. Must match ``contracts/proto/apex/v1/event.proto``.
INGEST_METHOD = "/apex.v1.EventIngest/Ingest"

#: The gateway's own ceiling (``apex_event_ingest::MAX_ENVELOPE_BYTES``). An
#: envelope larger than this is refused by ``event-ingest`` before it is looked
#: at, and the attempt is recorded as an admission-abuse security signal -- so
#: refusing it locally turns a wasted round trip and a security finding into an
#: error the caller can act on.
MAX_ENVELOPE_BYTES = 256 * 1024

#: ``apex.v1.EventType``. Keys are the canonical JSON/JCS spellings the event
#: hash is computed over; values are the protobuf wire values. Checked against
#: ``contracts/proto/apex/v1/event.proto`` by the test suite, because a wrong
#: entry here would produce an envelope the gateway hashes differently -- a
#: rejection whose cause would be invisible from either side alone.
EVENT_TYPE_VALUES = {
    "turn_start": 1,
    "llm": 2,
    "tool": 3,
    "message": 4,
    "memory": 5,
    "decision": 6,
    "workflow": 7,
    "agent_spawn": 8,
    "control": 9,
    "score": 10,
    "turn_end": 11,
    "error": 12,
}

#: ``apex.v1.ActorType``, same reasoning as above.
ACTOR_TYPE_VALUES = {
    "user": 1,
    "agent": 2,
    "system": 3,
    "schedule": 4,
}

#: JSON numbers are IEEE-754 doubles, so only integers in this range survive a
#: ``google.protobuf.Struct`` round trip unchanged. ``rfc8785`` refuses anything
#: outside it while hashing, so an event that reached this module already
#: satisfies the bound; this constant is the encoder declining to be the place
#: where that invariant is first broken, not a new restriction.
MAX_EXACT_INTEGER = 2**53 - 1

_WIRE_VARINT = 0
_WIRE_FIXED64 = 1
_WIRE_LENGTH = 2


class EventEncodingError(ApexError):
    """An event could not be faithfully encoded for the ingest wire format.

    Never retryable: the input is the problem, and re-sending the same dict
    produces the same answer. Always raised *before* any network request, so an
    event that fails this has definitively not been submitted and has consumed
    no idempotency slot at the gateway.
    """

    code = "EVENT_ENCODE_FAILED"
    category = "contract"
    retryable = False
    safe_message = "The event could not be encoded for ingest."
    cause = "The event cannot be represented in the v1 wire format without changing its meaning."
    recommended_next_steps = (
        "Confirm the event was produced by EventBuilder and passes validate_event.",
        "Confirm event data holds only JSON values inside the JCS numeric domain.",
    )


# Kept as a private negative-input guard for existing callers/tests. Message
# serialization itself is performed only by the generated protobuf classes.
def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise EventEncodingError(cause="A negative value cannot be encoded as a protobuf varint.")
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


# --------------------------------------------------------------------------
# apex.v1.EventEnvelope
# --------------------------------------------------------------------------


def _require_mapping(event: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = event.get(name)
    if not isinstance(value, Mapping):
        raise EventEncodingError(cause=f"The event's {name} must be an object.")
    return value


def _validate_ingest_response_wire(buffer: bytes) -> None:
    offset = 0
    while offset < len(buffer):
        field, wire, _raw, offset = _read_field(buffer, offset)
        if field == 1 and wire != _WIRE_VARINT:
            raise GrpcStatusError("UNKNOWN", "ingest response duplicate flag used the wrong wire type")


def _generated_event_pb2() -> Any:
    try:
        from ._generated.apex.v1 import event_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise EventEncodingError(
            cause="Install the ingest transport's protobuf runtime before sending events.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[ingest]'",),
        ) from exc
    return event_pb2


def _generated_struct_pb2() -> Any:
    try:
        from google.protobuf import struct_pb2
    except ImportError as exc:  # pragma: no cover - exercised without the extra
        raise EventEncodingError(
            cause="Install the ingest transport's protobuf runtime before sending events.",
            recommended_next_steps=("Install with: pip install 'apex-sdk[ingest]'",),
        ) from exc
    return struct_pb2


def _generated_struct_value(value: Any, depth: int) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    struct_pb2 = _generated_struct_pb2()
    result = struct_pb2.Value()
    if value is None:
        result.null_value = 0
    elif isinstance(value, bool):
        result.bool_value = value
    elif isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER:
            raise EventEncodingError(cause="An integer in event data cannot survive the protobuf double conversion.")
        result.number_value = float(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise EventEncodingError(cause="Event data numbers must be finite.")
        result.number_value = value
    elif isinstance(value, str):
        result.string_value = value
    elif isinstance(value, Mapping):
        result.struct_value.CopyFrom(_generated_struct(value, depth + 1))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > MAX_STRUCT_ENTRIES:
            raise EventEncodingError(cause="An array in event data holds more entries than this client encodes.")
        result.list_value.values.extend(_generated_struct_value(item, depth + 1) for item in value)
    else:
        raise EventEncodingError(cause="A value in event data is not JSON-compatible.")
    return result


def _generated_struct(fields: Mapping[str, Any], depth: int = 0) -> Any:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    if not isinstance(fields, Mapping):
        raise EventEncodingError(cause="Event data must be an object.")
    if len(fields) > MAX_STRUCT_ENTRIES:
        raise EventEncodingError(cause="An object in event data holds more entries than this client encodes.")
    result = _generated_struct_pb2().Struct()
    for key, value in fields.items():
        if not isinstance(key, str):
            raise EventEncodingError(cause="Event data object keys must be strings.")
        result.fields[key].CopyFrom(_generated_struct_value(value, depth + 1))
    return result


def encode_struct(fields: Mapping[str, Any], depth: int = 0) -> bytes:
    """Encodes a JSON-like mapping with the generated Struct message."""
    return _generated_struct(fields, depth).SerializeToString(deterministic=True)


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise EventEncodingError(cause=f"{label} must be a string.")
    return value


def encode_event_envelope(event: Mapping[str, Any]) -> bytes:
    """Encodes a validated Apex v1 event with the generated message class."""
    if not isinstance(event, Mapping):
        raise EventEncodingError(cause="An event must be an object.")
    event_type = event.get("type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPE_VALUES:
        raise EventEncodingError(cause="The event type is not a member of the v1 EventType enum.")
    scope = _require_mapping(event, "scope")
    actor = _require_mapping(event, "actor")
    version = _require_mapping(event, "version")
    integrity = _require_mapping(event, "integrity")
    actor_type = actor.get("type")
    if not isinstance(actor_type, str) or actor_type not in ACTOR_TYPE_VALUES:
        raise EventEncodingError(cause="The event actor type is not a member of the v1 ActorType enum.")
    schema_version = event.get("schema_version")
    if not isinstance(schema_version, int) or isinstance(schema_version, bool) or not 0 <= schema_version <= 0xFFFFFFFF:
        raise EventEncodingError(cause="schema_version must be a uint32.")
    agent_group_ids = scope.get("agent_group_ids")
    if not isinstance(agent_group_ids, list):
        raise EventEncodingError(cause="scope.agent_group_ids must be an array.")

    event_pb2 = _generated_event_pb2()
    envelope = event_pb2.EventEnvelope(
        event_id=_required_string(event.get("event_id"), "event_id"),
        timestamp=_required_string(event.get("timestamp"), "timestamp"),
        type=EVENT_TYPE_VALUES[event_type],
        agent_id=_required_string(event.get("agent_id"), "agent_id"),
        run_id=_required_string(event.get("run_id"), "run_id"),
        trace_id=_required_string(event.get("trace_id"), "trace_id"),
        schema_version=schema_version,
    )
    parent_run_id = event.get("parent_run_id")
    if parent_run_id is not None:
        envelope.parent_run_id = _required_string(parent_run_id, "parent_run_id")
    envelope.scope.workspace_id = _required_string(scope.get("workspace_id"), "scope.workspace_id")
    envelope.scope.namespace_id = _required_string(scope.get("namespace_id"), "scope.namespace_id")
    for group in agent_group_ids:
        envelope.scope.agent_group_ids.append(_required_string(group, "scope.agent_group_ids[]"))
    envelope.actor.type = ACTOR_TYPE_VALUES[actor_type]
    envelope.actor.id = _required_string(actor.get("id"), "actor.id")
    envelope.version.agent_code = _required_string(version.get("agent_code"), "version.agent_code")
    envelope.version.prompt = _required_string(version.get("prompt"), "version.prompt")
    envelope.version.model = _required_string(version.get("model"), "version.model")
    prev_hash = integrity.get("prev_hash")
    if prev_hash is not None:
        envelope.integrity.prev_hash = _required_string(prev_hash, "integrity.prev_hash")
    envelope.integrity.event_hash = _required_string(integrity.get("event_hash"), "integrity.event_hash")
    data = event.get("data")
    if not isinstance(data, Mapping):
        raise EventEncodingError(cause="The event's data must be an object.")
    # event_pb2 uses a private descriptor pool because event.proto and
    # control.proto currently declare the same apex.v1.ControlAction enum.
    # The wire contract for google.protobuf.Struct is identical; crossing the
    # pool boundary through serialized bytes keeps the generated message type
    # authoritative without importing a second Struct class into the SDK.
    envelope.data.ParseFromString(_generated_struct(data).SerializeToString(deterministic=True))
    payload = envelope.SerializeToString(deterministic=True)
    if len(payload) > MAX_ENVELOPE_BYTES:
        raise EventEncodingError(
            "The encoded event is larger than ingest accepts.",
            correlation={"event_id": str(event.get("event_id", ""))},
            cause="The encoded envelope exceeded the gateway's 256 KiB admission ceiling.",
            recommended_next_steps=("Reduce the size of the event's data payload before exporting it.",),
        )
    return payload


def decode_ingest_response(buffer: bytes) -> bool:
    if hasattr(buffer, "duplicate"):
        return bool(buffer.duplicate)
    if not isinstance(buffer, (bytes, bytearray)):
        raise GrpcStatusError("UNKNOWN", "ingest response was not bytes")
    buffer = bytes(buffer)
    if len(buffer) > MAX_ENVELOPE_BYTES:
        raise GrpcStatusError("UNKNOWN", "ingest response exceeded the client's read ceiling")
    try:
        _validate_ingest_response_wire(buffer)
        return _generated_event_pb2().IngestResponse.FromString(buffer).duplicate
    except Exception as exc:  # protobuf DecodeError is version-dependent
        raise GrpcStatusError("UNKNOWN", "ingest response was not well-formed protobuf") from exc


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentIngestCredentials:
    """The agent workload's mTLS identity and its ingest bearer credential.

    Both halves are required, and the bearer credential alone is useless: the
    gateway pins it to the SHA-256 of this exact client certificate
    (``APEX_BEARER_CERT_SHA256``), so a leaked token cannot be replayed from
    anywhere else.
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
    ) -> "AgentIngestCredentials":
        """Loads credentials under the SDK's single credential-file discipline.

        ``token_file`` holds the raw ingest bearer token and nothing else. It is
        deliberately *not* the control gateway's
        ``token|cert_sha256|agent_id|scopes`` table: the two services
        authenticate independently and their credential files are different
        formats, and handing this loader a control table would silently
        authenticate as that whole first row.
        """
        if (token is None) == (token_file is None):
            raise ConfigurationError("supply exactly one of token or token_file")
        if token_file is not None:
            raw = _read_credential_file(Path(token_file), "ingest bearer token", private=True)
            token = raw.decode("utf-8", errors="strict").strip()
        # The gateway requires every byte to be ASCII-graphic and the token to
        # be at most 4096 bytes (auth/verifier.rs). Applying the same rule here
        # turns a malformed credential into a configuration error at startup
        # rather than an opaque UNAUTHENTICATED at first export -- and it is
        # stricter than `control_transport`'s equivalent, which admits
        # non-printable ASCII, rather than looser.
        if not token or len(token) > 4096 or not all(0x21 <= ord(character) <= 0x7E for character in token):
            raise ConfigurationError(
                "the ingest bearer token must be 1-4096 printable ASCII characters with no whitespace"
            )
        return cls(
            ca_certificate=_read_credential_file(Path(ca_file), "ingest gateway CA certificate", private=False),
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
    """Imports ``grpc`` lazily, for the reason ``control_transport`` does.

    Importing ``apex_sdk`` must never require a gRPC stack: event building,
    validation and the bundle surfaces are useful without one.
    """
    try:
        import grpc  # noqa: PLC0415 -- deliberately deferred; see the docstring.
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise ConfigurationError(
            "the ingest transport requires the grpc extra: pip install 'apex-sdk[control]'"
        ) from exc
    return grpc


class GrpcEventIngestTransport:
    """Submits ``apex.v1.EventEnvelope`` over mTLS with the workload identity.

    Satisfies ``exporter.GrpcIngestTransport``, so this is what a consumer
    constructs in place of ``InMemoryIdempotentIngest`` for real use::

        exporter = BoundedGrpcExporter(
            GrpcEventIngestTransport("ingest.internal:8443", credentials)
        )

    Retry, backoff, circuit breaking and failure classification live in
    ``BoundedGrpcExporter`` and are deliberately not duplicated here: this
    object makes exactly one attempt per call and reports what happened in the
    vocabulary the exporter already classifies.
    """

    def __init__(
        self,
        endpoint: str,
        credentials: AgentIngestCredentials,
        *,
        server_hostname: str | None = None,
        timeout_seconds: float = 10.0,
        verify_canonical_round_trip: bool = True,
        channel_factory: Any | None = None,
    ) -> None:
        if not isinstance(endpoint, str) or not endpoint or any(character.isspace() for character in endpoint):
            raise ConfigurationError("the ingest endpoint must be a host:port string")
        # Refused rather than stripped, exactly as in control_transport: a
        # quietly-accepted "https://host:port" would mean the SDK and the
        # deployment disagree about what the configured value means.
        if "://" in endpoint:
            raise ConfigurationError("the ingest endpoint must be host:port with no URL scheme")
        if not isinstance(credentials, AgentIngestCredentials):
            raise ConfigurationError("ingest credentials must be an AgentIngestCredentials")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 300
        ):
            raise ConfigurationError("the ingest timeout must be a positive number of seconds up to 300")
        self._endpoint = endpoint
        self._credentials = credentials
        self._timeout = float(timeout_seconds)
        self._verify_round_trip = bool(verify_canonical_round_trip)
        self._closed = False
        grpc = _grpc_module()
        channel_credentials = grpc.ssl_channel_credentials(
            root_certificates=credentials.ca_certificate,
            private_key=credentials.client_key,
            certificate_chain=credentials.client_certificate,
        )
        options: list[tuple[str, Any]] = [
            ("grpc.max_send_message_length", MAX_ENVELOPE_BYTES),
            ("grpc.max_receive_message_length", MAX_ENVELOPE_BYTES),
        ]
        if server_hostname is not None:
            # Only ever *narrows* what this client accepts: it selects which
            # name the server certificate must match. There is no option here
            # that turns verification off, and none is offered.
            options.append(("grpc.ssl_target_name_override", server_hostname))
        factory = channel_factory or grpc.secure_channel
        self._channel = factory(endpoint, channel_credentials, options=tuple(options))
        from ._generated.apex.v1 import event_pb2_grpc

        self._invoke = event_pb2_grpc.EventIngestStub(self._channel).Ingest

    @property
    def endpoint(self) -> str:
        return self._endpoint

    def ingest(self, event: dict[str, Any], *, event_id: str) -> bool:
        """Submits one event. Returns ``True`` when ingest stored it anew.

        ``False`` means the gateway answered ``duplicate: true`` -- this
        ``event_id`` was already durably accepted for this scope, which is a
        success and not a failure. That inverts ``IngestResponse.duplicate`` to
        match the ``GrpcIngestTransport`` contract that
        ``InMemoryIdempotentIngest`` already implements.
        """
        if self._closed:
            raise EventEncodingError(
                "The ingest transport is closed.",
                cause="ingest() was called after close().",
            )
        if not isinstance(event, Mapping):
            raise EventEncodingError(cause="An event must be an object.")
        if not isinstance(event_id, str) or event_id != event.get("event_id"):
            # The exporter passes the event's own id. A mismatch means the
            # caller is asking for an idempotency key that does not describe the
            # payload, which is exactly how a poisoned idempotency entry gets
            # created at the gateway -- and the gateway would answer
            # IdempotencyConflict, having already recorded a telemetry-integrity
            # signal against this workload.
            raise EventEncodingError(
                cause="The supplied event_id does not match the event's own event_id.",
            )
        payload = encode_event_envelope(event)
        if self._verify_round_trip:
            self._assert_canonical_round_trip(event, payload)
        grpc = _grpc_module()
        try:
            request = _generated_event_pb2().EventEnvelope.FromString(payload)
            raw = self._invoke(
                request,
                timeout=self._timeout,
                # The bearer credential travels in metadata; the mTLS client
                # certificate is what binds it. Never logged, never placed in an
                # error message, never in a diagnostic.
                metadata=(("authorization", f"Bearer {self._credentials.token}"),),
            )
        except grpc.RpcError as exc:
            raise GrpcStatusError(self._status_name(exc)) from None
        except GrpcStatusError:
            raise
        except Exception as exc:  # noqa: BLE001 - any transport fault must surface typed
            raise GrpcStatusError("UNKNOWN", "the ingest transport raised an untyped error") from exc
        return not decode_ingest_response(raw)

    def _assert_canonical_round_trip(self, event: Mapping[str, Any], payload: bytes) -> None:
        """Refuses to send an envelope that means something other than what was hashed.

        Decodes the ``data`` Struct back out of the bytes about to go on the
        wire -- with the SDK's existing decoder, not a second copy of the
        encoder's assumptions -- and recomputes the canonical event hash around
        it. ``data`` is the only lossy part of this envelope: every other field
        is a string, a bounded integer, or an enum with an exact name/value
        mapping.

        A mismatch here is precisely the ``InvalidIntegrity`` rejection the
        gateway would return, caught locally while the offending value is still
        in hand. Nothing is sent and no idempotency slot is consumed.
        """
        decoded_data = _decode_struct(_extract_data_field(payload))
        recomputed = event_hash({**dict(event), "data": decoded_data})
        integrity = event.get("integrity")
        declared = integrity.get("event_hash") if isinstance(integrity, Mapping) else None
        if recomputed != declared:
            raise EventEncodingError(
                "The encoded event does not match the hash the event carries.",
                correlation={"event_id": str(event.get("event_id", ""))},
                cause="Encoding the event's data to google.protobuf.Struct changed its canonical form.",
                recommended_next_steps=(
                    "Check event data for numbers outside the JSON-safe integer range or for non-JSON types.",
                    "Rebuild the event with EventBuilder so its hash covers the value actually sent.",
                ),
            )

    def close(self) -> None:
        self._closed = True
        try:
            self._channel.close()
        except Exception as exc:  # noqa: BLE001 - a close fault must still be typed
            raise GrpcStatusError("UNKNOWN", "the ingest channel raised an untyped error during close") from exc

    def __enter__(self) -> "GrpcEventIngestTransport":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    @staticmethod
    def _status_name(error: Any) -> str:
        """Extracts the gRPC status name without ever touching ``details()``.

        Server-supplied detail strings are attacker-influenced text from this
        client's point of view, and this SDK's errors are built from static,
        review-approved messages. Only the enumerated status code crosses the
        boundary, which is also all ``BoundedGrpcExporter._classify_failure``
        reads.
        """
        code = getattr(error, "code", None)
        value = code() if callable(code) else code
        name = getattr(value, "name", None)
        return name if isinstance(name, str) else "UNKNOWN"


def _extract_data_field(payload: bytes) -> bytes:
    """Returns the bytes of field 11 (``data``) from an encoded envelope.

    Reads the encoded form rather than trusting the value that was passed to the
    encoder: the point of the check this feeds is to inspect what is actually
    about to be transmitted.
    """
    offset = 0
    body = b""
    while offset < len(payload):
        field_number, wire_type, value, offset = _read_field(payload, offset)
        if field_number == 11 and wire_type == _WIRE_LENGTH:
            body = bytes(value)
    return body
