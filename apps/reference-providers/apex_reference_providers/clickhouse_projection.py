#!/usr/bin/env python3
"""Reference ClickHouse projection API implementing contracts/clickhouse/v1.md HTTP write."""

from __future__ import annotations

import argparse
import json
import sqlite3
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from .common import HASH, MAX_EVENT_BYTES, UUID_V7, DiagnosticHandler, build_tls_context


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_hash TEXT NOT NULL,
                envelope BLOB NOT NULL,
                workspace_id TEXT,
                namespace_id TEXT
            )
            """
        )
        self._db.commit()

    def put(self, event_id: str, event_hash: str, body: bytes) -> str:
        """Return 'created', 'duplicate', or 'conflict'."""
        with self._lock:
            row = self._db.execute(
                "SELECT event_hash FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO events(event_id, event_hash, envelope) VALUES (?,?,?)",
                    (event_id, event_hash, body),
                )
                self._db.commit()
                return "created"
            if row[0] == event_hash:
                return "duplicate"
            return "conflict"


class Handler(DiagnosticHandler):
    store: Store

    def do_POST(self) -> None:  # noqa: N802
        if not self.require_authorized_client():
            return
        if self.path.rstrip("/") != "/v1/events":
            self.send_error(404)
            return
        event_id = self.headers.get("X-Apex-Event-Id", "")
        event_hash = self.headers.get("X-Apex-Event-Hash", "")
        if not UUID_V7.fullmatch(event_id) or not HASH.fullmatch(event_hash):
            self.send_diagnostic(400, "INVALID_ENVELOPE", "Invalid event identity headers.")
            return
        body = self.read_body(MAX_EVENT_BYTES)
        if body is None:
            return
        if not body:
            self.send_diagnostic(400, "INVALID_ENVELOPE", "Missing event body.")
            return
        # X-Apex-Event-Hash is the Apex integrity.event_hash (RFC 8785 canonical
        # digest), not SHA-256 of the raw protobuf body. Gateway clients already
        # recompute that hash; this reference service stores the header fingerprint
        # for idempotency and does not re-hash the wire bytes.
        result = self.store.put(event_id, event_hash, body)
        if result == "conflict":
            self.send_diagnostic(
                409,
                "IDEMPOTENCY_CONFLICT",
                "The event ID is already bound to different content.",
            )
            return
        self.send_response(204)
        # The gateway acknowledges only an exact status plus this single
        # matching receipt. Without the echo, a proxy-generated 204 would
        # falsely look like a durable projection.
        self.send_header("X-Apex-Event-Hash", event_hash)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/health":
            payload = json.dumps({"status": "ok", "service": "clickhouse-projection"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_error(404)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--client-ca", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, default=Path("/var/lib/apex/ch"))
    args = parser.parse_args(argv)
    Handler.store = Store(args.data_dir / "events.sqlite3")
    context = build_tls_context(cert=args.cert, key=args.key, client_ca=args.client_ca)
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"clickhouse-projection ready on https://{args.bind}:{args.port}/v1/events",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
