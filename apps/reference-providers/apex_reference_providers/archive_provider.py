#!/usr/bin/env python3
"""Reference archive-provider HTTP API — cloud-agnostic via pluggable backends.

Backends (select with --backend / APEX_ARCHIVE_BACKEND):
  local  — SQLite (default, no cloud credentials)
  azure  — Azure Blob (immutable storage / legal hold)
  gcs    — Google Cloud Storage (retention / temporary hold)
  s3     — AWS S3 or MinIO (Object Lock)

The ingest gateway never imports cloud SDKs; only this adapter process does.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from .backends import build_backend
from .common import HASH, MAX_EVENT_BYTES, UUID_V7, DiagnosticHandler, build_tls_context


def _env_file(name: str) -> str | None:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    value = os.environ.get(name)
    return value.strip() if value else None


class Handler(DiagnosticHandler):
    backend = None  # type: ignore[assignment]

    def do_PUT(self) -> None:  # noqa: N802
        if not self.require_authorized_client():
            return
        path = unquote(self.path.split("?", 1)[0])
        prefix = "/v1/events/"
        if not path.startswith(prefix) or not path.endswith(".pb"):
            self.send_error(404)
            return
        object_name = path[len(prefix) : -3]
        header_id = self.headers.get("X-Apex-Event-Id", "")
        event_hash = self.headers.get("X-Apex-Event-Hash", "")
        if (
            object_name != header_id
            or not UUID_V7.fullmatch(header_id)
            or not HASH.fullmatch(event_hash)
        ):
            self.send_diagnostic(
                400, "ARCHIVE_CONFIGURATION", "Event path/header identity mismatch."
            )
            return
        body = self.read_body(MAX_EVENT_BYTES)
        if body is None:
            return
        if not body:
            self.send_diagnostic(400, "ARCHIVE_CONFIGURATION", "Missing event body.")
            return
        # X-Apex-Event-Hash is integrity.event_hash (canonical digest), not body SHA-256.
        try:
            result = self.backend.put(header_id, event_hash, body)
        except Exception:
            self.send_diagnostic(
                503,
                "ARCHIVE_TRANSIENT",
                "The archive backend could not complete the write.",
                retryable=True,
            )
            return
        if result.status == "conflict":
            self.send_diagnostic(
                409,
                "ARCHIVE_IDEMPOTENCY_CONFLICT",
                "The archive contains this event ID with different content.",
            )
            return
        status = 201 if result.status == "created" else 412
        self.send_response(status)
        self.send_header("X-Apex-Event-Hash", event_hash)
        if result.version_id:
            self.send_header("X-Apex-Archive-Version", result.version_id)
        self.send_header("X-Apex-Archive-Provider", result.provider)
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") == "/health":
            caps = self.backend.health()
            payload = json.dumps(
                {
                    "status": "ok",
                    "service": "archive-provider",
                    "provider": caps.provider,
                    "capabilities": {
                        "immutable_retention": caps.immutable_retention,
                        "legal_hold": caps.legal_hold,
                        "version_identifier": caps.version_identifier,
                        "read_after_write": caps.read_after_write,
                        "content_verification": caps.content_verification,
                    },
                }
            ).encode()
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
    parser.add_argument("--data-dir", type=Path, default=Path("/var/lib/apex/archive"))
    parser.add_argument(
        "--backend",
        default=os.environ.get("APEX_ARCHIVE_BACKEND", "local"),
        help="local | azure | gcs | s3",
    )
    args = parser.parse_args(argv)

    Handler.backend = build_backend(
        args.backend,
        data_dir=str(args.data_dir),
        azure_connection_string=_env_file("APEX_ARCHIVE_AZURE_CONNECTION_STRING"),
        azure_container=os.environ.get("APEX_ARCHIVE_AZURE_CONTAINER", "apex-events"),
        azure_account_url=os.environ.get("APEX_ARCHIVE_AZURE_ACCOUNT_URL"),
        azure_credential=_env_file("APEX_ARCHIVE_AZURE_ACCOUNT_KEY"),
        gcs_bucket=os.environ.get("APEX_ARCHIVE_GCS_BUCKET", "apex-events"),
        gcs_project=os.environ.get("APEX_ARCHIVE_GCS_PROJECT"),
        gcs_credentials_file=os.environ.get("APEX_ARCHIVE_GCS_CREDENTIALS_FILE"),
        s3_endpoint=os.environ.get("APEX_ARCHIVE_S3_ENDPOINT"),
        s3_bucket=os.environ.get("APEX_ARCHIVE_S3_BUCKET", "apex-events"),
        s3_access_key=_env_file("APEX_ARCHIVE_S3_ACCESS_KEY"),
        s3_secret_key=_env_file("APEX_ARCHIVE_S3_SECRET_KEY"),
        s3_region=os.environ.get("APEX_ARCHIVE_S3_REGION", "us-east-1"),
        s3_ca_file=os.environ.get("APEX_ARCHIVE_S3_CA_FILE"),
    )
    context = build_tls_context(cert=args.cert, key=args.key, client_ca=args.client_ca)
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"archive-provider backend={args.backend} "
        f"on https://{args.bind}:{args.port}/v1/events/",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
