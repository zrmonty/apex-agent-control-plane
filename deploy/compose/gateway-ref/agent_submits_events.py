#!/usr/bin/env python3
"""A real Python process submitting real events to a real ``event-ingest``.

This is the live end-to-end proof for ``apex_sdk.GrpcEventIngestTransport``.
Everything in the path is the product: ``EventBuilder`` builds and hash-chains
the envelope, ``BoundedGrpcExporter`` drives delivery, and the transport encodes
``apex.v1.EventEnvelope`` by hand and puts it on a real mTLS gRPC connection to a
running ``apex-event-ingest`` container. Nothing here is a mock, a stub, or
``InMemoryIdempotentIngest``.

It proves three things, in one causal sequence a reader can re-derive:

1. A first submission of a fresh ``event_id`` is **accepted** -- which means the
   gateway decoded this client's hand-rolled protobuf, recomputed the RFC 8785
   canonical hash from the bytes it received, and got the same value the SDK
   computed locally. That single fact is the whole contract between the Struct
   encoder and the service; nothing else tests it.
2. Resubmitting the **byte-identical** event answers ``duplicate: true``.
3. A **different** event id is accepted rather than also called a duplicate --
   without this, "duplicate" could be a constant and step 2 would prove nothing.

Stdout is a machine-readable transcript so an orchestrating gate can assert on
real ids and real timestamps rather than on this script's opinion::

    READY <iso8601>
    EVENT <n> <event_id> <event_hash> <timestamp>
    ACCEPTED <n> <event_id> <iso8601>
    DUPLICATE <n> <event_id> <iso8601>
    REJECTED <n> <event_id> <code> <iso8601>
    STATS attempted=<n> delivered=<n> duplicates=<n> failed=<n>
    PROOF_COMPLETE <iso8601>

Exit codes: 0 proof complete, 2 a submission was rejected, 3 the gateway's
answer did not match what the proof requires.

Nothing here is production code. It is the harness that makes "the SDK can
actually submit an event" checkable.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SDK_SRC = REPO_ROOT / "packages" / "sdk-python" / "src"
if SDK_SRC.is_dir():
    sys.path.insert(0, str(SDK_SRC))

from apex_sdk import (  # noqa: E402
    AgentIngestCredentials,
    BoundedGrpcExporter,
    EventBuilder,
    ExportDeliveryError,
    GrpcEventIngestTransport,
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _say(line: str) -> None:
    print(line, flush=True)


def _uuid7() -> str:
    """A UUIDv7, which is what the v1 contract requires of an ``event_id``.

    Written out rather than taken from a library so this harness needs nothing
    the SDK itself does not already need. Timestamp-ordered by construction, so
    the ids in the transcript are also a record of when they were minted.
    """
    milliseconds = int(datetime.now(UTC).timestamp() * 1000)
    raw = bytearray(uuid.uuid4().bytes)
    raw[0:6] = milliseconds.to_bytes(6, "big")
    raw[6] = 0x70 | (raw[6] & 0x0F)
    raw[8] = 0x80 | (raw[8] & 0x3F)
    return str(uuid.UUID(bytes=bytes(raw)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="ingest gateway host:port")
    parser.add_argument("--secrets", required=True, type=Path, help="host-side live-mTLS fixture directory")
    parser.add_argument("--agent-id", default="reference-agent")
    parser.add_argument(
        "--certificate-basename",
        default="ingest-http-client",
        help="the client leaf whose SHA-256 the gateway pins via APEX_BEARER_CERT_SHA256",
    )
    parser.add_argument("--token-file", default="ingest-bearer-token")
    parser.add_argument("--server-hostname", default="localhost")
    parser.add_argument("--workspace-id", default="acme")
    parser.add_argument("--namespace-id", default="prod")
    args = parser.parse_args()

    secrets: Path = args.secrets
    credentials = AgentIngestCredentials.from_files(
        ca_file=secrets / "ca.pem",
        client_certificate_file=secrets / f"{args.certificate_basename}.pem",
        client_key_file=secrets / f"{args.certificate_basename}.key",
        # The ingest bearer credential is the raw token, not the control
        # gateway's `token|cert_sha256|agent_id|scopes` table. Two independently
        # authenticated services, two credential formats.
        token_file=secrets / args.token_file,
    )
    transport = GrpcEventIngestTransport(
        args.endpoint,
        credentials,
        server_hostname=args.server_hostname,
        timeout_seconds=15.0,
    )
    exporter = BoundedGrpcExporter(transport, max_attempts=3)

    # `agent_id`, the actor id, and the actor type are all constrained by the
    # gateway: it requires an AGENT actor whose id equals the agent id bound to
    # the presented credential, so a shared credential cannot mint arbitrary
    # actor identities. A mismatch here is ScopeDenied, not a silent accept.
    builder = EventBuilder(
        agent_id=args.agent_id,
        run_id=f"live-proof-{uuid.uuid4().hex[:8]}",
        trace_id=f"trace-{uuid.uuid4().hex[:8]}",
        scope={
            "workspace_id": args.workspace_id,
            "namespace_id": args.namespace_id,
            "agent_group_ids": [],
        },
        actor={"type": "agent", "id": args.agent_id},
        version={"agent_code": "live-ingest-proof", "prompt": "p1", "model": "reference"},
    )

    _say(f"READY {_now()}")
    exit_code = 0
    try:
        # A payload that exercises every Struct kind the encoder can emit, so
        # the gateway's own canonicalization has to agree with this client's on
        # each of them -- not merely on a flat map of strings.
        first = builder.build(
            "llm",
            {
                "provider": "reference",
                "model": "reference",
                "input_tokens": 12,
                "output_tokens": 34,
                "temperature": 0.25,
                "streamed": False,
                "stop_reason": None,
                "tags": ["live", "proof"],
                "nested": {"depth": 2, "ok": True},
            },
            event_id=_uuid7(),
        )
        outcome = _submit(exporter, first, 1)
        if outcome != "ACCEPTED":
            return 3

        # The identical event again, same id and same bytes. This is the
        # idempotency claim, and it is the only one an operator replaying a
        # buffered event actually depends on.
        outcome = _submit(exporter, first, 2)
        if outcome != "DUPLICATE":
            _say(f"UNEXPECTED expected DUPLICATE got {outcome} {_now()}")
            return 3

        # A different event id, so "duplicate" is demonstrably a property of the
        # id rather than a constant the gateway returns for everything after the
        # first request. This one is chained to the first: its prev_hash is the
        # first event's hash, which the builder tracks.
        second = builder.build(
            "turn_end",
            {"status": "completed", "turns": 1},
            event_id=_uuid7(),
        )
        outcome = _submit(exporter, second, 3)
        if outcome != "ACCEPTED":
            _say(f"UNEXPECTED expected ACCEPTED got {outcome} {_now()}")
            return 3

        stats = exporter.stats
        _say(
            "STATS attempted={attempted} delivered={delivered} "
            "duplicates={duplicates} failed={failed}".format(**stats)
        )
        if stats["delivered"] != 2 or stats["duplicates"] != 1 or stats["failed"] != 0:
            _say(f"UNEXPECTED exporter stats {stats} {_now()}")
            return 3
        _say(f"PROOF_COMPLETE {_now()}")
    except ExportDeliveryError as error:
        # Typed, safe diagnostics only: the SDK never puts the bearer credential
        # or a server-supplied detail string into an error, and this transcript
        # lands in a public CI log.
        _say(f"REJECTED - - {error.code} {_now()}")
        _say(f"DIAGNOSTIC {error.to_diagnostic()}")
        exit_code = 2
    finally:
        try:
            exporter.close()
        except Exception:  # noqa: BLE001 - shutdown must not mask the outcome
            pass
    return exit_code


def _submit(exporter: BoundedGrpcExporter, event: dict, index: int) -> str:
    """Submits one event and reports what the gateway said, by observation.

    ``BoundedGrpcExporter.write`` returns nothing; whether ingest stored the
    event or recognised it as a replay shows up as a counter change. Reading the
    delta rather than asking the transport directly keeps this proof honest
    about which layer it is observing: the product's own accounting, the thing a
    consumer would actually see.
    """
    before = exporter.stats
    _say(
        f"EVENT {index} {event['event_id']} {event['integrity']['event_hash']} "
        f"{event['timestamp']}"
    )
    exporter.write(event)
    after = exporter.stats
    if after["delivered"] > before["delivered"]:
        _say(f"ACCEPTED {index} {event['event_id']} {_now()}")
        return "ACCEPTED"
    if after["duplicates"] > before["duplicates"]:
        _say(f"DUPLICATE {index} {event['event_id']} {_now()}")
        return "DUPLICATE"
    _say(f"REJECTED {index} {event['event_id']} NO_ACKNOWLEDGEMENT {_now()}")
    return "REJECTED"


if __name__ == "__main__":
    raise SystemExit(main())
