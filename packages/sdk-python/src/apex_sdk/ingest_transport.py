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
``_credential_files._read_credential_file`` outright -- the same function
``control_transport`` uses for its own credentials -- so the SDK has exactly
one set of rules for reading key material; channel construction, the
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

Wire encoding of the envelope and its ``google.protobuf.Struct`` ``data``
field -- the pure, credential-free half of this module -- lives in
``_event_wire.py``. It was split out because it has no dependency on the
channel/credential machinery below; everything it exports (the enum tables,
``EventEncodingError``, ``encode_struct``, ``encode_event_envelope``,
``decode_ingest_response``, and the size ceilings) is re-imported here so
``apex_sdk.ingest_transport.X`` continues to resolve exactly as it did before
the split.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._event_wire import (
    ACTOR_TYPE_VALUES,
    EVENT_TYPE_VALUES,
    INGEST_METHOD,
    MAX_ENVELOPE_BYTES,
    MAX_EXACT_INTEGER,
    EventEncodingError,
    _encode_varint,
    _extract_data_field,
    _generated_event_pb2,
    decode_ingest_response,
    encode_event_envelope,
    encode_struct,
)
from ._credential_files import _read_credential_file
from .control_transport import _decode_struct
from .errors import ConfigurationError
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
