#!/usr/bin/env python3
"""Create the JetStream stream the ingest gateway publishes into.

Nothing in `deploy/compose` provisioned a stream. `apex.events.>` had no
stream bound to it, so every `DurableFanoutPublisher` publish failed and the
gateway answered `PUBLISH_FAILED` / `Unavailable` to every valid event. Only
`apps/event-ingest/tests/live_mtls.rs::ensure_events_stream` ever created one,
as a side effect of running that test, which is why a gateway driven straight
from Compose could never accept anything.

This speaks the NATS wire protocol directly rather than adding a NATS CLI image
to the stack: the reference-provider image already carries a Python with `ssl`,
and the stack is otherwise digest-pinned.

The lab NATS credential is granted `publish: $JS.API.>` and
`subscribe: _INBOX.>` by `live-mtls/render_configs.py`, which is exactly what a
JetStream stream create needs.

Exit codes: 0 stream present, 1 anything else.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time

DEFAULT_STREAM = "APEX_EVENTS"
DEFAULT_SUBJECTS = ["apex.events.>"]
INBOX = "_INBOX.apex-provision"
# The gateway's async-nats client uses ConnectOptions::tls_first(), and the
# rendered nats.conf sets `handshake_first: true` to match. TLS therefore starts
# immediately on connect, before any INFO line is exchanged in the clear.
HANDSHAKE_FIRST = True


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def _connect(args: argparse.Namespace) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=args.ca)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    # Keep verification on: this provisioner authenticates the broker exactly
    # the way the gateway does, so a misissued server certificate fails here
    # too rather than being papered over by the init step.
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection((args.host, args.port), timeout=args.timeout)
    if not HANDSHAKE_FIRST:  # pragma: no cover - lab config always sets it
        raw.recv(4096)
    return context.wrap_socket(raw, server_hostname=args.host)


def _readline(sock: ssl.SSLSocket, buffer: bytearray) -> bytes:
    while b"\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("NATS connection closed while waiting for a line")
        buffer.extend(chunk)
    line, _, rest = bytes(buffer).partition(b"\r\n")
    buffer.clear()
    buffer.extend(rest)
    return line


def _provision(args: argparse.Namespace) -> None:
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
            "name": "apex-gateway-ref-provisioner",
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

        request = json.dumps(
            {
                "name": args.stream,
                "subjects": args.subjects,
                "retention": "limits",
                "storage": args.storage,
                "discard": "old",
                "num_replicas": 1,
            }
        ).encode()
        subject = f"$JS.API.STREAM.CREATE.{args.stream}"
        sock.sendall(
            f"PUB {subject} {INBOX} {len(request)}\r\n".encode() + request + b"\r\n"
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
            # 10058 = stream name already in use with an identical config.
            if error and error.get("err_code") != 10058:
                raise RuntimeError(f"stream create rejected: {error}")
            if error:
                print(f"provision_jetstream: stream {args.stream} already exists")
            else:
                created = payload.get("config", {}).get("subjects")
                print(f"provision_jetstream: stream {args.stream} bound to {created}")
            return
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
    parser.add_argument("--stream", default=DEFAULT_STREAM)
    parser.add_argument("--subject", dest="subjects", action="append")
    parser.add_argument("--storage", default="file", choices=["file", "memory"])
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--attempts", type=int, default=30)
    args = parser.parse_args()
    if not args.subjects:
        args.subjects = list(DEFAULT_SUBJECTS)

    last = ""
    for attempt in range(1, args.attempts + 1):
        try:
            _provision(args)
            return 0
        except (OSError, ssl.SSLError, RuntimeError, ValueError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            print(f"provision_jetstream: attempt {attempt} failed: {last}")
            time.sleep(2)
    print(f"provision_jetstream: giving up after {args.attempts} attempts: {last}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
