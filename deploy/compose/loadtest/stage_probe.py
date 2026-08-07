#!/usr/bin/env python3
"""Service time of each downstream ingest dependency, measured from inside the stack.

`apps/event-ingest` emits no per-stage timing, and adding instrumentation to a
pen-test-hardened request path is remediation, not measurement. The
`apex-load-baseline` harness therefore attributes cost by *where a request
stops*, which isolates admission from the fanout band but cannot split the band
itself. This script splits it: it runs as a peer container on the stack's own
network, presents the same `ingest-http-client` certificate the gateway
presents, reuses one connection per dependency the way the gateway's `reqwest`
and `async-nats` clients do, and times:

  - the ClickHouse projection write  (POST /v1/events)
  - the archive PUT + read-back verify (PUT /v1/events/{id}.pb, If-None-Match: *)
  - the JetStream publish + PubAck   (HPUB apex.events.<ws>.<ns>, wait for ack)

This is the dependency's service time as seen from a peer, not a trace taken
inside the gateway process. It excludes whatever the gateway's own client
libraries add on top, and the numbers should be read as a floor for each stage.

Neither reference provider parses the protobuf body (see
`apps/reference-providers/apex_reference_providers/{clickhouse_projection,archive_provider}.py`),
so the payload here is filler of a realistic size rather than a signed envelope.
Storage cost depends on the byte count, not the field layout.

Run through the Compose profile that mounts the right secrets:

    docker compose -p <project> -f compose.gateway-ref.yaml \
      run --rm --no-deps loadtest-stage-probe
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import statistics
import sys
import time

SECRETS = "/run/secrets"
HASH_HEX = "a" * 64


def _percentiles(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"count": 0}
    ordered = sorted(samples)

    def at(fraction: float) -> float:
        rank = round((len(ordered) - 1) * fraction)
        return round(ordered[rank], 3)

    return {
        "count": len(ordered),
        "mean_ms": round(statistics.fmean(ordered), 3),
        "p50_ms": at(0.50),
        "p90_ms": at(0.90),
        "p99_ms": at(0.99),
        "max_ms": at(1.0),
    }


def _event_id(index: int) -> str:
    """A distinct lowercase UUIDv7 per iteration. Both providers key on the id,
    so reusing one would measure a duplicate/412 path instead of a real write."""
    nonce = int(time.time()) & 0xFFFF
    return f"018f5c91-2d88-7c00-8000-{(nonce << 32) | (index & 0xFFFFFFFF):012x}"


def _client_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=f"{SECRETS}/ca")
    context.load_cert_chain(
        certfile=f"{SECRETS}/ingest_http_client_cert",
        keyfile=f"{SECRETS}/ingest_http_client_key",
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def probe_http(host: str, method: str, path_for, iterations: int, body: bytes) -> dict:
    """Times `iterations` requests over one kept-alive TLS connection."""
    connection = http.client.HTTPSConnection(host, 8443, context=_client_context(), timeout=30)
    samples: list[float] = []
    statuses: dict[str, int] = {}
    try:
        for index in range(iterations):
            event_id = _event_id(index)
            headers = {
                "Content-Type": "application/x-protobuf",
                "Content-Length": str(len(body)),
                "X-Apex-Event-Id": event_id,
                "X-Apex-Event-Hash": HASH_HEX,
            }
            if method == "PUT":
                headers["If-None-Match"] = "*"
            started = time.perf_counter()
            connection.request(method, path_for(event_id), body=body, headers=headers)
            response = connection.getresponse()
            response.read()
            elapsed = (time.perf_counter() - started) * 1000.0
            key = str(response.status)
            statuses[key] = statuses.get(key, 0) + 1
            # Discard the first few: they carry the TLS handshake the gateway
            # pays once at startup, not once per event.
            if index >= 5:
                samples.append(elapsed)
    finally:
        connection.close()
    return {**_percentiles(samples), "statuses": statuses}


# ---------------------------------------------------------------------------
# JetStream publish + PubAck over the raw NATS protocol
#
# Same approach and the same reasons as gateway-ref/provision_jetstream.py: the
# stack is digest-pinned and the reference-provider image already carries a
# Python with `ssl`, so this speaks the wire protocol rather than adding a NATS
# client image.
# ---------------------------------------------------------------------------

INBOX = "_INBOX.apex-loadprobe"


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read().strip()


def _readline(sock: ssl.SSLSocket, buffer: bytearray) -> bytes:
    while b"\r\n" not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            raise RuntimeError("NATS connection closed while waiting for a line")
        buffer.extend(chunk)
    line, _, rest = bytes(buffer).partition(b"\r\n")
    buffer.clear()
    buffer.extend(rest)
    return line


def probe_jetstream(host: str, subject: str, iterations: int, body: bytes) -> dict:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=f"{SECRETS}/ca")
    context.load_cert_chain(
        certfile=f"{SECRETS}/ingest_nats_client_cert",
        keyfile=f"{SECRETS}/ingest_nats_client_key",
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    raw = socket.create_connection((host, 4222), timeout=20)
    # The rendered nats.conf sets `handshake_first: true`, matching the
    # gateway's `ConnectOptions::tls_first()`.
    sock = context.wrap_socket(raw, server_hostname=host)
    buffer = bytearray()
    samples: list[float] = []
    errors = 0
    try:
        info = _readline(sock, buffer)
        if not info.startswith(b"INFO "):
            raise RuntimeError(f"expected INFO, got {info[:60]!r}")
        connect = {
            "verbose": False,
            "pedantic": False,
            "tls_required": True,
            "name": "apex-load-stage-probe",
            "lang": "python",
            "version": "0",
            "protocol": 1,
            "headers": True,
            "user": _read(f"{SECRETS}/nats_username"),
            "pass": _read(f"{SECRETS}/nats_password"),
        }
        sock.sendall(b"CONNECT " + json.dumps(connect).encode() + b"\r\nPING\r\n")
        while True:
            line = _readline(sock, buffer)
            if line == b"PONG":
                break
            if line.startswith(b"-ERR"):
                raise RuntimeError(f"NATS refused the connection: {line!r}")
        sock.sendall(f"SUB {INBOX} 1\r\n".encode())

        for index in range(iterations):
            message_id = _event_id(index)
            headers = f"NATS/1.0\r\nNats-Msg-Id: {message_id}\r\n\r\n".encode()
            frame = (
                f"HPUB {subject} {INBOX} {len(headers)} {len(headers) + len(body)}\r\n".encode()
                + headers
                + body
                + b"\r\n"
            )
            started = time.perf_counter()
            sock.sendall(frame)
            while True:
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
                    chunk = sock.recv(65536)
                    if not chunk:
                        raise RuntimeError("NATS connection closed mid-payload")
                    buffer.extend(chunk)
                payload = bytes(buffer[:size])
                del buffer[: size + 2]
                elapsed = (time.perf_counter() - started) * 1000.0
                if b'"error"' in payload:
                    errors += 1
                elif index >= 5:
                    samples.append(elapsed)
                break
    finally:
        sock.close()
    return {**_percentiles(samples), "ack_errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=int(os.environ.get("APEX_PROBE_ITERATIONS", "300")))
    parser.add_argument("--bytes", type=int, default=int(os.environ.get("APEX_PROBE_BYTES", "560")))
    parser.add_argument("--clickhouse-host", default="clickhouse-projection")
    parser.add_argument("--archive-host", default="archive-provider")
    parser.add_argument("--nats-host", default="jetstream")
    parser.add_argument("--subject", default="apex.events.acme.prod")
    args = parser.parse_args()

    body = b"\x00" * args.bytes
    report: dict[str, object] = {
        "payload_bytes": args.bytes,
        "iterations": args.iterations,
        "warmup_discarded": 5,
    }
    failures = 0

    for name, call in (
        (
            "jetstream_publish_ack",
            lambda: probe_jetstream(args.nats_host, args.subject, args.iterations, body),
        ),
        (
            "clickhouse_write",
            lambda: probe_http(
                args.clickhouse_host, "POST", lambda _id: "/v1/events", args.iterations, body
            ),
        ),
        (
            "archive_put_verify",
            lambda: probe_http(
                args.archive_host,
                "PUT",
                lambda event_id: f"/v1/events/{event_id}.pb",
                args.iterations,
                body,
            ),
        ),
    ):
        try:
            report[name] = call()
        except Exception as exc:  # noqa: BLE001 - a probe failure must be reported, not raised
            report[name] = {"error": f"{type(exc).__name__}: {exc}"}
            failures += 1

    for name, values in report.items():
        if isinstance(values, dict):
            print(f"{name}: {values}", flush=True)
    print("STAGE_PROBE_JSON " + json.dumps(report), flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
