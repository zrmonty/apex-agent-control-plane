#!/usr/bin/env python3
"""Wait until live-mTLS stack ports and mTLS /health endpoints are ready.

Used by GitHub Actions and local gate runs. Prints the last error each attempt
so CI logs show SSL/port failures instead of a bare timeout.
"""

from __future__ import annotations

import argparse
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _tcp_open(host: str, port: int, timeout: float = 2.0) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        pass


def _mtls_health(secrets: Path, host: str, port: int, timeout: float = 3.0) -> None:
    """GET https://host:port/health with client cert; trust local CA only.

    Use 127.0.0.1 (not localhost) on CI: many runners resolve localhost to ::1,
    and lab certs only include IPv4 127.0.0.1 in the SAN list.
    """
    ca = secrets / "ca.pem"
    cert = secrets / "ingest-http-client.pem"
    key = secrets / "ingest-http-client.key"
    for path in (ca, cert, key):
        if not path.is_file():
            raise FileNotFoundError(f"missing secret {path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Still verify the chain against the lab CA. Hostname checks are disabled for
    # readiness only: runner DNS (localhost → ::1) and SAN edge cases must not
    # block CI when TCP + mTLS client auth already succeed.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False
    context.load_verify_locations(cafile=str(ca))
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))

    url = f"https://{host}:{port}/health"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(url, headers={"Connection": "close"})
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"{url} returned HTTP {response.status}")
        body = response.read(256)
        if b"ok" not in body and b"status" not in body:
            raise RuntimeError(f"{url} unexpected body: {body[:80]!r}")


def wait(
    secrets: Path,
    *,
    attempts: int,
    sleep_s: float,
    tcp_ports: list[int],
    https_ports: list[int],
    require_https: bool,
) -> int:
    last_error = "no attempts yet"
    for attempt in range(1, attempts + 1):
        try:
            for port in tcp_ports:
                _tcp_open("127.0.0.1", port)
            if require_https:
                for port in https_ports:
                    # Force IPv4 loopback; do not use localhost (often ::1 on Ubuntu CI).
                    _mtls_health(secrets, "127.0.0.1", port)
            else:
                # TCP-only readiness: confirm providers accepted the host port mapping.
                for port in https_ports:
                    _tcp_open("127.0.0.1", port)
            print(
                f"Live mTLS services are ready (attempt {attempt}, https={require_https}).",
                flush=True,
            )
            return 0
        except Exception as exc:  # noqa: BLE001 — surface every readiness failure
            last_error = f"{type(exc).__name__}: {exc}"
            print(f"attempt {attempt}/{attempts}: {last_error}", flush=True)
            if attempt in {1, 5, 15, 30} or attempt == attempts:
                try:
                    import subprocess

                    subprocess.run(
                        ["docker", "compose", "-f", "compose.yaml", "ps", "-a"],
                        check=False,
                    )
                    subprocess.run(
                        ["docker", "compose", "-f", "compose.yaml", "logs", "--tail", "40"],
                        check=False,
                    )
                except Exception:
                    pass
            time.sleep(sleep_s)
    print(f"Timed out waiting for live mTLS services. Last error: {last_error}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--secrets",
        type=Path,
        default=Path(os.environ.get("APEX_LIVE_MTLS_SECRETS", "secrets")),
    )
    parser.add_argument("--attempts", type=int, default=90)
    parser.add_argument("--sleep", type=float, default=2.0)
    parser.add_argument(
        "--tcp-only",
        action="store_true",
        help="Only wait for TCP ports (skip mTLS /health). Use when CI TLS probe is flaky.",
    )
    args = parser.parse_args(argv)
    secrets = args.secrets.resolve()
    if not secrets.is_dir():
        print(f"secrets directory not found: {secrets}", file=sys.stderr)
        return 2
    return wait(
        secrets,
        attempts=args.attempts,
        sleep_s=args.sleep,
        tcp_ports=[14222, 16379],
        https_ports=[18443, 18444],
        require_https=not args.tcp_only,
    )


if __name__ == "__main__":
    raise SystemExit(main())
