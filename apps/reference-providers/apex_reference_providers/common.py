"""Shared mTLS server helpers and redacted diagnostic bodies."""

from __future__ import annotations

import json
import re
import ssl
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

MAX_EVENT_BYTES = 256 * 1024
UUID_V7 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
HASH = re.compile(r"^[0-9a-f]{64}$")


def build_tls_context(*, cert: Path, key: Path, client_ca: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.load_verify_locations(cafile=str(client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def diagnostic(
    code: str,
    summary: str,
    *,
    cause: str | None = None,
    retryable: bool = False,
    next_steps: list[str] | None = None,
) -> bytes:
    body = {
        "code": code,
        "summary": summary,
        "cause": cause or summary,
        "retryable": retryable,
        "next_steps": next_steps
        or ["Correct the request configuration and retry if appropriate."],
    }
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


class DiagnosticHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        # Never log bodies or headers that may contain event material.
        sys_stderr_write = __import__("sys").stderr.write
        sys_stderr_write(f"{self.server.server_name}: {fmt % args}\n")

    def send_diagnostic(
        self,
        status: int,
        code: str,
        summary: str,
        *,
        cause: str | None = None,
        retryable: bool = False,
    ) -> None:
        payload = diagnostic(code, summary, cause=cause, retryable=retryable)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_body(self, max_bytes: int = MAX_EVENT_BYTES) -> bytes | None:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return b""
        if length > max_bytes:
            self.send_diagnostic(
                413, "PAYLOAD_TOO_LARGE", "Envelope exceeds the 256 KiB limit."
            )
            return None
        return self.rfile.read(length)
