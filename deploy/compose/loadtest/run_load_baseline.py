#!/usr/bin/env python3
"""Measure real ingest throughput and per-stage latency against a live gateway.

Phase 0.6 work item 1. Builds `apps/event-ingest/Dockerfile`, starts the
`compose.gateway-ref.yaml` stack under its own project name, drives real
gRPC-over-mTLS traffic at the running container with
`apps/event-ingest/src/bin/load_baseline.rs`, optionally probes the downstream
dependency containers directly, writes a JSON report, and tears the stack down.

Nothing here runs the gateway in-process. If the container does not build or
does not serve, this script fails and says so rather than falling back to a
library-mode measurement.

Usage (from the repository root):

    python deploy/compose/loadtest/run_load_baseline.py
    python deploy/compose/loadtest/run_load_baseline.py --keep-up --skip-build
    python deploy/compose/loadtest/run_load_baseline.py --quick

Docker safety: every container, network, and volume belongs to the
`apex-gateway-loadtest` Compose project (override with --project). Unrelated
projects on the same daemon are never named or touched.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "deploy" / "compose"
LIVE = COMPOSE / "live-mtls"
LOADTEST = COMPOSE / "loadtest"
INGEST = REPO / "apps" / "event-ingest"
DEFAULT_PROJECT = "apex-gateway-loadtest"
DEFAULT_REPORT = REPO / ".local" / "apex-lab" / "load-baseline.json"
DEFAULT_PORT = 18455


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 900,
    stream: bool = False,
) -> tuple[int, str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+ " + " ".join(cmd), flush=True)
    try:
        if stream:
            proc = subprocess.run(
                cmd, cwd=str(cwd) if cwd else None, env=merged, timeout=timeout
            )
            return proc.returncode, ""
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=merged,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except FileNotFoundError as exc:
        return 127, str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout: {exc}"


def client_cert_fingerprint(pem_path: Path) -> str | None:
    if not pem_path.is_file():
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        return None


def ensure_pki(regenerate: bool) -> str:
    """Generates the live-mTLS PKI when it is missing, and returns the
    authorized client certificate fingerprint the gateway pins its bearer
    credential to."""
    secrets = LIVE / "secrets"
    if regenerate or not (secrets / "ca.pem").is_file():
        code, out = run([sys.executable, str(LIVE / "generate_pki.py"), "--out", str(secrets)], cwd=LIVE)
        if code != 0:
            raise SystemExit(f"generate_pki.py failed:\n{out}")
        code, out = run([sys.executable, str(LIVE / "render_configs.py")], cwd=LIVE)
        if code != 0:
            raise SystemExit(f"render_configs.py failed:\n{out}")
    bearer = secrets / "ingest-bearer-token"
    if not bearer.is_file():
        bearer.write_text("gateway-ref-token", encoding="utf-8")
    fingerprint = client_cert_fingerprint(secrets / "ingest-http-client.pem")
    if not fingerprint:
        raise SystemExit(
            "could not fingerprint deploy/compose/live-mtls/secrets/ingest-http-client.pem "
            "(is `cryptography` installed?)"
        )
    (secrets / "ingest-http-client.sha256").write_text(fingerprint + "\n", encoding="ascii")

    host = LIVE / "secrets-host"
    if regenerate or not host.is_dir():
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "live_mtls_generate_pki", LIVE / "generate_pki.py"
        )
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.write_host_secrets(secrets, host)
    return fingerprint


def wait_for_gateway(project: list[str], env: dict[str, str], port: int, attempts: int = 90) -> str:
    """Waits until the gateway container is serving TLS on its published port.

    Checks container state too: a crash-looping container can leave a bound
    port behind, and an exited container has to be reported as a failure rather
    than as a timeout.
    """
    last = ""
    for attempt in range(1, attempts + 1):
        code, out = run(
            ["docker", "compose", *project, "ps", "-a", "--format", "{{.Name}} {{.State}}"],
            cwd=COMPOSE,
            env=env,
            timeout=60,
        )
        last = out
        for line in out.splitlines():
            if "ingest-gateway" in line and "exited" in line.lower():
                _, logs = run(
                    ["docker", "compose", *project, "logs", "--no-color", "ingest-gateway"],
                    cwd=COMPOSE,
                    env=env,
                    timeout=60,
                )
                raise SystemExit(f"gateway container exited:\n{out}\n{logs}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return f"serving on 127.0.0.1:{port} after {attempt} attempt(s)"
        except OSError as exc:
            last = f"{out}\nconnect: {exc}"
        time.sleep(2)
    _, logs = run(
        ["docker", "compose", *project, "logs", "--no-color", "--tail", "120"],
        cwd=COMPOSE,
        env=env,
        timeout=60,
    )
    raise SystemExit(f"gateway never served on 127.0.0.1:{port}:\n{last}\n{logs}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", default=DEFAULT_PROJECT, help="Compose project name to create and tear down")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="host port for the gateway")
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--namespaces", default="prod,ns1,ns2,ns3,ns4,ns5,ns6,ns7", help="comma-separated namespaces to spread events across")
    parser.add_argument("--workspace", default="acme")
    parser.add_argument("--scenario", default="all", help="stages | concurrency | sustained | burst | all")
    parser.add_argument("--sustained-rate", default="116")
    parser.add_argument("--sustained-secs", default="60")
    parser.add_argument("--burst-secs", default="10")
    parser.add_argument("--burst-multipliers", default="1.5,2,3,5,10")
    parser.add_argument("--concurrency-levels", default="1,2,4,8,16,32,64")
    parser.add_argument("--concurrency-requests", default="600")
    parser.add_argument("--stage-iterations", default="200")
    parser.add_argument("--clients", default="8")
    parser.add_argument(
        "--min-accepted-per-sec",
        default="0",
        help="fail when the sustained accepted rate falls below this (0 = report only)",
    )
    parser.add_argument("--idempotency-capacity", default="50000", help="APEX_IDEMPOTENCY_CAPACITY for the gateway")
    parser.add_argument("--skip-build", action="store_true", help="reuse the existing apex-event-ingest-ref image")
    parser.add_argument("--regenerate-pki", action="store_true")
    parser.add_argument("--keep-up", action="store_true", help="leave the stack running after measuring")
    parser.add_argument("--quick", action="store_true", help="short run, for a smoke check rather than a baseline")
    args = parser.parse_args()

    if args.quick:
        args.stage_iterations = "25"
        args.concurrency_levels = "1,8,32"
        args.concurrency_requests = "80"
        args.sustained_secs = "8"
        args.burst_secs = "4"
        args.burst_multipliers = "5"

    print("==> platform", platform.platform())
    code, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if code != 0:
        raise SystemExit(f"docker is not available:\n{out}")
    print("==> docker", out.strip())

    fingerprint = ensure_pki(args.regenerate_pki)
    print("==> client cert fingerprint", fingerprint)

    namespaces = [item.strip() for item in args.namespaces.split(",") if item.strip()]
    allowed_scopes = ",".join(f"{args.workspace}/{namespace}" for namespace in namespaces)

    env = {
        "APEX_BEARER_CERT_SHA256": fingerprint,
        "APEX_PROVIDER_CLIENT_CERT_SHA256": fingerprint,
        "APEX_ALLOWED_SCOPES": allowed_scopes,
        "APEX_INGEST_PORT": str(args.port),
        "APEX_IDEMPOTENCY_CAPACITY": args.idempotency_capacity,
        # The control gateway shares this Compose file but is not under test.
        # Keep its port off the default so a hand-run gateway-ref stack and this
        # one can coexist on the same daemon.
        "APEX_CONTROL_PORT": str(args.port + 1),
    }
    project = ["-p", args.project, "-f", "compose.gateway-ref.yaml"]

    # Always start from clean volumes: the file outbox and idempotency journals
    # are durable, so a previous run's rows would both skew latency (the
    # committed-key scan in FileIdempotencyStore::reserve is linear) and eat
    # into the capacity ceiling.
    run(["docker", "compose", *project, "down", "-v", "--remove-orphans"], cwd=COMPOSE, env=env, timeout=240)

    if not args.skip_build:
        code, _ = run(
            ["docker", "compose", *project, "build", "ingest-gateway"],
            cwd=COMPOSE,
            env=env,
            timeout=3600,
            stream=True,
        )
        if code != 0:
            raise SystemExit("gateway image build failed")

    code, out = run(
        ["docker", "compose", *project, "up", "-d", "--force-recreate"],
        cwd=COMPOSE,
        env=env,
        timeout=900,
    )
    if code != 0:
        raise SystemExit(f"compose up failed:\n{out}")

    exit_code = 0
    try:
        print("==>", wait_for_gateway(project, env, args.port))

        harness = INGEST / "target" / "release" / (
            "apex-load-baseline.exe" if os.name == "nt" else "apex-load-baseline"
        )
        code, _ = run(
            ["cargo", "build", "--release", "--bin", "apex-load-baseline", "--features", "test-support"],
            cwd=INGEST,
            timeout=1800,
            stream=True,
        )
        if code != 0 or not harness.is_file():
            raise SystemExit("could not build apex-load-baseline")

        secrets_host = LIVE / "secrets-host"
        secrets = str(secrets_host if secrets_host.is_dir() else LIVE / "secrets")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        code, _ = run(
            [
                str(harness),
                "--endpoint", f"https://localhost:{args.port}",
                "--secrets", secrets,
                "--scenario", args.scenario,
                "--workspace", args.workspace,
                "--namespaces", ",".join(namespaces),
                "--clients", args.clients,
                "--stage-iterations", args.stage_iterations,
                "--concurrency-levels", args.concurrency_levels,
                "--concurrency-requests", args.concurrency_requests,
                "--sustained-rate", args.sustained_rate,
                "--sustained-secs", args.sustained_secs,
                "--burst-multipliers", args.burst_multipliers,
                "--burst-secs", args.burst_secs,
                "--min-accepted-per-sec", args.min_accepted_per_sec,
                "--json", str(args.report),
            ],
            timeout=3600,
            stream=True,
        )
        exit_code = code

        # Downstream dependency service times, measured from a peer container on
        # the stack's own network with the same client certificate. This is the
        # only way to split the fanout band without instrumenting the gateway.
        stage_probe = LOADTEST / "stage_probe.py"
        if stage_probe.is_file():
            probe_code, probe_out = run(
                ["docker", "compose", *project, "run", "--rm", "--no-deps", "loadtest-stage-probe"],
                cwd=COMPOSE,
                env=env,
                timeout=900,
            )
            print(probe_out)
            if probe_code == 0:
                _merge_stage_probe(args.report, probe_out)
            else:
                print("stage probe did not complete; the fanout band stays unsplit", file=sys.stderr)
    finally:
        if args.keep_up:
            print(f"==> stack left running as project {args.project}")
            print(f"    tear down: docker compose -p {args.project} -f compose.gateway-ref.yaml down -v")
        else:
            run(
                ["docker", "compose", *project, "down", "-v", "--remove-orphans"],
                cwd=COMPOSE,
                env=env,
                timeout=300,
            )

    print(f"==> report {args.report}")
    return exit_code


def _merge_stage_probe(report: Path, output: str) -> None:
    """Folds the peer-probe JSON (one line, prefixed) into the harness report."""
    marker = "STAGE_PROBE_JSON "
    payload = None
    for line in output.splitlines():
        if line.startswith(marker):
            payload = line[len(marker) :]
    if not payload or not report.is_file():
        return
    try:
        merged = json.loads(report.read_text(encoding="utf-8"))
        merged["downstream_stage_probe"] = json.loads(payload)
        report.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    except (json.JSONDecodeError, OSError) as exc:
        print(f"could not merge the stage probe into {report}: {exc}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
