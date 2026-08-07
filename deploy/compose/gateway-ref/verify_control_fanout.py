#!/usr/bin/env python3
"""Prove a submitted control command actually reached JetStream.

`ControlCommandResponse.delivered` is the service reporting on itself, and
this repository has already shipped one bug in exactly that shape (a reused
`event_id` reported as a duplicate when it had in fact been freshly accepted).
So the fanout gate does not read that flag: it asks the broker.

This fetches the last message on the control command's own
`apex.events.<workspace>.<namespace>` subject via
`$JS.API.STREAM.MSG.GET`, decodes it, and requires the expected markers to be
present in the stored envelope bytes. If the fanout worker were never spawned,
or connected as the wrong principal, or published to the wrong subject, there
is simply no message here and this exits 1.

Subjects are `apex.events.x<hex>.x<hex>`, matching
`apps/event-ingest/src/publisher/jetstream.rs::encode_subject_component` --
the `x` prefix plus lowercase hex of each byte, so an arbitrary scope
identifier can never inject a `.` or `>` into a subject token.

The NATS wire protocol is spoken directly, and the connection helpers are
imported from `provision_jetstream.py` rather than copied, for the same reason
that script gives: the reference-provider image already carries a Python with
`ssl`, and the stack is otherwise digest-pinned.

Exit codes: 0 the expected message is in the stream, 1 anything else.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time

from provision_jetstream import _connect, _read, _readline

INBOX = "_INBOX.apex-fanout-verify"


def encode_subject_component(value: str) -> str:
    """Mirror of the Rust publisher's subject encoder."""
    return "x" + "".join(f"{byte:02x}" for byte in value.encode("utf-8"))


def _fetch_last_message(args: argparse.Namespace, subject: str) -> bytes:
    sock = _connect(args)
    buffer = bytearray()
    try:
        info = _readline(sock, buffer)
        if not info.startswith(b"INFO "):
            raise RuntimeError(f"expected INFO, got {info[:60]!r}")
        connect = {
            "verbose": False,
            "pedantic": False,
            "tls_required": True,
            "name": "apex-control-fanout-verify",
            "lang": "python",
            "version": "0",
            "protocol": 1,
            "headers": True,
        }
        if args.username_file and args.password_file:
            connect["user"] = _read(args.username_file)
            connect["pass"] = _read(args.password_file)
        sock.sendall(b"CONNECT " + json.dumps(connect).encode() + b"\r\nPING\r\n")
        while True:
            line = _readline(sock, buffer)
            if line == b"PONG":
                break
            if line.startswith(b"-ERR"):
                raise RuntimeError(f"NATS refused the connection: {line!r}")

        sock.sendall(f"SUB {INBOX} 1\r\n".encode())
        request = json.dumps({"last_by_subj": subject}).encode()
        api = f"$JS.API.STREAM.MSG.GET.{args.stream}"
        sock.sendall(
            f"PUB {api} {INBOX} {len(request)}\r\n".encode() + request + b"\r\n"
        )

        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            line = _readline(sock, buffer)
            if line.startswith(b"PING"):
                sock.sendall(b"PONG\r\n")
                continue
            if line.startswith(b"-ERR"):
                raise RuntimeError(f"NATS error: {line!r}")
            if not line.startswith(b"MSG "):
                continue
            size = int(line.split()[-1])
            while len(buffer) < size + 2:
                chunk = sock.recv(4096)
                if not chunk:
                    raise RuntimeError("NATS connection closed mid-payload")
                buffer.extend(chunk)
            payload = json.loads(bytes(buffer[:size]).decode())
            del buffer[: size + 2]
            error = payload.get("error")
            if error:
                # 10037 = no message found for that subject yet. That is the
                # normal "the worker has not ticked yet" answer, so it is a
                # retry rather than a failure.
                raise LookupError(json.dumps(error))
            message = payload.get("message", {})
            return base64.b64decode(message.get("data", ""))
        raise RuntimeError("timed out waiting for the JetStream API response")
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("APEX_NATS_HOST", "jetstream"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("APEX_NATS_PORT", "4222"))
    )
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--username-file")
    parser.add_argument("--password-file")
    parser.add_argument("--stream", default="APEX_EVENTS")
    parser.add_argument("--workspace", default="acme")
    parser.add_argument("--namespace", default="prod")
    # Markers that must appear in the stored envelope bytes. Defaults match
    # `live_control_mtls.rs::stop_command`. Substring checks against the
    # serialized protobuf are deliberate: this script must not grow a
    # dependency on the generated Python bindings just to assert presence.
    parser.add_argument("--expect", action="append")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--sleep", type=float, default=2.0)
    args = parser.parse_args()
    expected = args.expect or ["control", "live-mtls-agent"]
    subject = (
        f"apex.events.{encode_subject_component(args.workspace)}"
        f".{encode_subject_component(args.namespace)}"
    )
    print(f"verify_control_fanout: waiting for a control event on {subject}")

    last = ""
    for attempt in range(1, args.attempts + 1):
        try:
            envelope = _fetch_last_message(args, subject)
        except LookupError as exc:
            last = f"no message yet: {exc}"
        except (OSError, RuntimeError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        else:
            missing = [
                marker
                for marker in expected
                if marker.encode("utf-8") not in envelope
            ]
            if missing:
                print(
                    f"verify_control_fanout: a message is on {subject} but is missing "
                    f"{missing}; {len(envelope)} envelope bytes",
                    file=sys.stderr,
                )
                return 1
            print(
                f"verify_control_fanout: control event confirmed in stream "
                f"{args.stream} on {subject} ({len(envelope)} envelope bytes, "
                f"markers {expected})"
            )
            return 0
        print(f"verify_control_fanout: attempt {attempt}: {last}")
        time.sleep(args.sleep)
    print(
        f"verify_control_fanout: no control event reached {subject} after "
        f"{args.attempts} attempts: {last}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
