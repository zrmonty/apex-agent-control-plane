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
classification, and the hand-rolled protobuf codec all mirror that module
rather than inventing a second style. What is genuinely new here is a
``google.protobuf.Struct`` **encoder**: ``control_transport`` only ever needed
to decode one, and an event's ``data`` field is an arbitrary JSON-like object
that has to be serialized on the way out.

Why the wire format is still encoded by hand
--------------------------------------------
Same reason as ``control_transport``: this package has no protobuf
code-generation step and no ``protobuf`` runtime dependency, and ``grpcio``
accepts arbitrary ``request_serializer``/``response_deserializer`` callables.
Adding ``protoc``/``grpcio-tools`` to the SDK's install surface for two messages
would be a larger change than the messages. **This is now the second module
doing it, which is the point at which the owner should weigh generating stubs
instead** -- flagged, not silently accepted.

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
import struct as _struct
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


# --------------------------------------------------------------------------
# Minimal protobuf wire encoder (see the module docstring for why).
# --------------------------------------------------------------------------


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


def _tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _length_delimited(field_number: int, body: bytes) -> bytes:
    return _tag(field_number, _WIRE_LENGTH) + _encode_varint(len(body)) + body


def _string_field(field_number: int, value: Any, label: str) -> bytes:
    """Encodes one proto3 ``string`` field.

    proto3 omits a scalar field holding its default, and the empty string is the
    default, so an empty value emits nothing. That is what a generated encoder
    does and no decoder can tell the two apart, so it is faithful rather than
    lossy.
    """
    if not isinstance(value, str):
        raise EventEncodingError(cause=f"{label} must be a string.")
    body = value.encode("utf-8")
    if not body:
        return b""
    return _length_delimited(field_number, body)


def _varint_field(field_number: int, value: int) -> bytes:
    """Encodes one proto3 varint field, omitting it when it holds the default."""
    if value == 0:
        return b""
    return _tag(field_number, _WIRE_VARINT) + _encode_varint(value)


# --------------------------------------------------------------------------
# google.protobuf.Struct encoder
# --------------------------------------------------------------------------
#
# The mirror image of control_transport's decoder. `Value` is a `oneof kind`,
# and the wire type per kind is fixed by google/protobuf/struct.proto:
#
#   1 null_value   NullValue enum   varint
#   2 number_value double           fixed64
#   3 string_value string           length-delimited
#   4 bool_value   bool             varint
#   5 struct_value Struct           length-delimited
#   6 list_value   ListValue        length-delimited
#
# A member of a oneof is *always* emitted, even when it holds its type's default
# value: presence is the entire meaning of a oneof. Omitting `null_value`
# because the enum is zero, or `bool_value` because it is false, would produce a
# `Value` with no `kind` set -- which prost decodes as `None` and the gateway
# rejects as InvalidStructure. This is the easiest thing to get wrong in this
# encoder, so it is stated here and asserted directly in the tests.


def _encode_struct_value(value: Any, depth: int) -> bytes:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    if value is None:
        # null_value is an enum whose only member NULL_VALUE is 0, emitted
        # explicitly precisely because it is the default.
        return _tag(1, _WIRE_VARINT) + _encode_varint(0)
    # bool is a subclass of int in Python, so it must be tested first or every
    # True would go out as the number 1.0.
    if isinstance(value, bool):
        return _tag(4, _WIRE_VARINT) + _encode_varint(1 if value else 0)
    if isinstance(value, int):
        if abs(value) > MAX_EXACT_INTEGER:
            raise EventEncodingError(
                cause="An integer outside the exactly-representable JSON range cannot be encoded without changing its value.",
            )
        return _tag(2, _WIRE_FIXED64) + _struct.pack("<d", float(value))
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EventEncodingError(
                cause="Infinity and NaN have no JSON or canonical-JSON representation.",
            )
        return _tag(2, _WIRE_FIXED64) + _struct.pack("<d", value)
    if isinstance(value, str):
        return _length_delimited(3, value.encode("utf-8"))
    if isinstance(value, Mapping):
        return _length_delimited(5, encode_struct(value, depth + 1))
    # str and bytes are Sequences too; both are already handled or refused
    # above, so only genuine arrays reach here.
    if isinstance(value, (list, tuple)):
        return _length_delimited(6, _encode_struct_list(value, depth + 1))
    raise EventEncodingError(
        cause="Event data may hold only objects, arrays, strings, numbers, booleans and null.",
    )


def _encode_struct_list(values: Sequence[Any], depth: int) -> bytes:
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    if len(values) > MAX_STRUCT_ENTRIES:
        raise EventEncodingError(cause="An array in event data holds more entries than this client encodes.")
    out = bytearray()
    for value in values:
        out += _length_delimited(1, _encode_struct_value(value, depth))
    return bytes(out)


def encode_struct(fields: Mapping[str, Any], depth: int = 0) -> bytes:
    """Encodes a JSON-like mapping as ``google.protobuf.Struct``.

    The exact inverse of ``control_transport._decode_struct``, and tested
    against it rather than against a second opinion about the wire format. The
    depth and entry ceilings are the decoder's own, so anything this encoder
    produces is something the SDK can also read back -- which the transport's
    pre-send integrity check depends on.
    """
    if depth > MAX_STRUCT_DEPTH:
        raise EventEncodingError(cause="Event data nested deeper than the wire format accepts.")
    if not isinstance(fields, Mapping):
        raise EventEncodingError(cause="Event data must be an object.")
    if len(fields) > MAX_STRUCT_ENTRIES:
        raise EventEncodingError(cause="An object in event data holds more entries than this client encodes.")
    out = bytearray()
    for key, value in fields.items():
        if not isinstance(key, str):
            raise EventEncodingError(cause="Event data object keys must be strings.")
        # `fields` is map<string, Value>, which on the wire is a repeated
        # FieldsEntry message with key = 1 and value = 2. The empty string is a
        # legal key and, being the default, is simply omitted from the entry --
        # both this encoder and the SDK's decoder read a missing key as "".
        entry = _string_field(1, key, "a Struct field key") + _length_delimited(
            2, _encode_struct_value(value, depth + 1)
        )
        out += _length_delimited(1, entry)
    return bytes(out)


# --------------------------------------------------------------------------
# apex.v1.EventEnvelope
# --------------------------------------------------------------------------


def _require_mapping(event: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = event.get(name)
    if not isinstance(value, Mapping):
        raise EventEncodingError(cause=f"The event's {name} must be an object.")
    return value


def encode_event_envelope(event: Mapping[str, Any]) -> bytes:
    """Encodes a validated Apex v1 event dict as ``apex.v1.EventEnvelope``.

    Serialization only. Business rules -- identifier shapes, timestamp format,
    the secret-material policy, the hash chain -- belong to ``validation.py``,
    and ``BoundedGrpcExporter.write`` has already applied them by the time an
    event reaches a transport. What is enforced here is exactly what
    serialization owns: that each field is the *type* the contract declares, and
    that nothing is encoded in a way that changes what it means.
    """
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
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or not 0 <= schema_version <= 0xFFFFFFFF
    ):
        raise EventEncodingError(cause="schema_version must be a uint32.")

    agent_group_ids = scope.get("agent_group_ids")
    if not isinstance(agent_group_ids, list):
        raise EventEncodingError(cause="scope.agent_group_ids must be an array.")

    scope_body = (
        _string_field(1, scope.get("workspace_id"), "scope.workspace_id")
        + _string_field(2, scope.get("namespace_id"), "scope.namespace_id")
        + b"".join(_string_field(3, group, "scope.agent_group_ids[]") for group in agent_group_ids)
    )
    actor_body = _varint_field(1, ACTOR_TYPE_VALUES[actor_type]) + _string_field(
        2, actor.get("id"), "actor.id"
    )
    version_body = (
        _string_field(1, version.get("agent_code"), "version.agent_code")
        + _string_field(2, version.get("prompt"), "version.prompt")
        + _string_field(3, version.get("model"), "version.model")
    )
    # `prev_hash` is `optional string`, so absence is meaningful: the chain root
    # has no predecessor and JCS represents that as `prev_hash: null`. Emitting
    # an empty string instead would be a different message that the gateway
    # canonicalizes -- and therefore hashes -- differently.
    prev_hash = integrity.get("prev_hash")
    if prev_hash is None:
        integrity_body = b""
    elif isinstance(prev_hash, str):
        integrity_body = _length_delimited(1, prev_hash.encode("utf-8"))
    else:
        raise EventEncodingError(cause="integrity.prev_hash must be a string or null.")
    integrity_body += _string_field(2, integrity.get("event_hash"), "integrity.event_hash")

    data = event.get("data")
    if not isinstance(data, Mapping):
        raise EventEncodingError(cause="The event's data must be an object.")

    parent_run_id = event.get("parent_run_id")
    if parent_run_id is None:
        parent_body = b""
    elif isinstance(parent_run_id, str):
        # `optional string`, so an explicitly-set empty value is still present
        # on the wire -- unlike the non-optional string fields above.
        parent_body = _length_delimited(6, parent_run_id.encode("utf-8"))
    else:
        raise EventEncodingError(cause="parent_run_id must be a string or null.")

    envelope = (
        _string_field(1, event.get("event_id"), "event_id")
        + _string_field(2, event.get("timestamp"), "timestamp")
        + _varint_field(3, EVENT_TYPE_VALUES[event_type])
        + _string_field(4, event.get("agent_id"), "agent_id")
        + _string_field(5, event.get("run_id"), "run_id")
        + parent_body
        + _string_field(7, event.get("trace_id"), "trace_id")
        + _length_delimited(8, scope_body)
        + _length_delimited(9, actor_body)
        + _length_delimited(10, version_body)
        # Always emitted, even when empty: `data` is a message field, so its
        # absence is distinguishable from an empty object, and the gateway
        # rejects an envelope carrying no `data` at all.
        + _length_delimited(11, encode_struct(data))
        + _length_delimited(12, integrity_body)
        + _varint_field(13, schema_version)
    )
    if len(envelope) > MAX_ENVELOPE_BYTES:
        raise EventEncodingError(
            "The encoded event is larger than ingest accepts.",
            correlation={"event_id": str(event.get("event_id", ""))},
            cause="The encoded envelope exceeded the gateway's 256 KiB admission ceiling.",
            recommended_next_steps=("Reduce the size of the event's data payload before exporting it.",),
        )
    return envelope


def decode_ingest_response(buffer: bytes) -> bool:
    """Decodes ``apex.v1.IngestResponse`` and returns its ``duplicate`` flag.

    A malformed response surfaces as ``GrpcStatusError("UNKNOWN")`` rather than
    a new error type, because that is the vocabulary
    ``BoundedGrpcExporter._classify_failure`` already speaks -- and an
    unrecognized status there is correctly non-retryable.
    """
    if not isinstance(buffer, (bytes, bytearray)):
        raise GrpcStatusError("UNKNOWN", "ingest response was not bytes")
    buffer = bytes(buffer)
    if len(buffer) > MAX_ENVELOPE_BYTES:
        raise GrpcStatusError("UNKNOWN", "ingest response exceeded the client's read ceiling")
    duplicate = False
    offset = 0
    while offset < len(buffer):
        try:
            field_number, wire_type, value, offset = _read_field(buffer, offset)
        except Exception as exc:  # noqa: BLE001 - a malformed response is a protocol fault
            raise GrpcStatusError("UNKNOWN", "ingest response was not well-formed protobuf") from exc
        if field_number == 1:
            if wire_type != _WIRE_VARINT:
                raise GrpcStatusError("UNKNOWN", "ingest response duplicate flag used the wrong wire type")
            duplicate = value != 0
        # Anything else is a field this client does not know about; skipping is
        # required protobuf behaviour, not leniency.
    return duplicate


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
        self._invoke = self._channel.unary_unary(
            INGEST_METHOD,
            request_serializer=lambda value: value,
            response_deserializer=lambda value: value,
        )

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
            raw = self._invoke(
                payload,
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
