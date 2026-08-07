#!/usr/bin/env python3
"""Run Phase 0 deploy-time / environment gates (Windows, Linux, macOS).

Proves what this machine can prove:
  - Docker available
  - live-mTLS PKI generation
  - compose.e2e stack (Postgres, MinIO, reference providers, NATS)
  - live-mTLS client tests (if cargo present)
  - Postgres unit/integration smoke (if cargo present)
  - MinIO Object-Lock acceptance
  - Azure/GCS acceptance (optional skip without credentials)

Writes a JSON report under .local/apex-lab/gate-report.json by default.
"""

from __future__ import annotations

import json
import os
import platform
import secrets as secure_secrets
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "deploy" / "compose"
LIVE = COMPOSE / "live-mtls"
INGEST = REPO / "apps" / "event-ingest"
DEFAULT_REPORT = REPO / ".local" / "apex-lab" / "gate-report.json"
# Distinct from the compose file's own `name:` so the gate never tears down a
# gateway stack an operator is running by hand.
GATEWAY_PROJECT = "apex-gateway-ref-gate"


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 600,
) -> tuple[int, str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=merged,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode, out
    except FileNotFoundError as exc:
        return 127, str(exc)
    except subprocess.TimeoutExpired as exc:
        return 124, f"timeout: {exc}"


def main() -> int:
    report_path = Path(os.environ.get("APEX_GATE_REPORT", str(DEFAULT_REPORT)))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    overall_ok = True

    def gate(name: str, ok: bool, detail: str = "", required: bool = True) -> None:
        nonlocal overall_ok
        status = "pass" if ok else ("fail" if required else "skip")
        if required and not ok:
            overall_ok = False
        results.append(
            {
                "name": name,
                "status": status,
                "required": required,
                "detail": detail[-4000:] if detail else "",
            }
        )
        mark = "PASS" if ok else ("FAIL" if required else "SKIP")
        print(f"[{mark}] {name}")
        if detail and not ok:
            print(detail[-1500:])

    print("==> Platform", platform.platform())
    print("==> Repo", REPO)

    # Docker
    code, out = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    gate("docker_daemon", code == 0, out.strip() or out, required=True)
    if code != 0:
        _write(report_path, results, False)
        return 1

    # Python deps
    code, out = run([sys.executable, "-m", "pip", "install", "--user", "-q", "cryptography", "boto3"])
    gate("python_deps_cryptography_boto3", code == 0, out, required=True)

    # PKI (always regenerate then recreate containers so certs match mounts)
    code, out = run(
        [sys.executable, str(LIVE / "generate_pki.py"), "--out", str(LIVE / "secrets")],
        cwd=LIVE,
    )
    gate("live_mtls_pki", code == 0, out, required=True)
    code, out = run([sys.executable, str(LIVE / "render_configs.py")], cwd=LIVE)
    gate("live_mtls_render_configs", code == 0, out, required=True)

    bearer = LIVE / "secrets" / "ingest-bearer-token"
    if not bearer.is_file():
        bearer.write_text(secure_secrets.token_urlsafe(32), encoding="utf-8")

    client_fp = _client_cert_fingerprint(LIVE / "secrets" / "ingest-http-client.pem")
    if client_fp:
        (LIVE / "secrets" / "ingest-http-client.sha256").write_text(client_fp + "\n", encoding="ascii")
        gate("client_cert_fingerprint", True, client_fp, required=True)
    else:
        gate("client_cert_fingerprint", False, "could not hash ingest-http-client.pem", required=True)

    # Recreate stacks after PKI so containers load current secrets (stale mounts break TLS).
    run(["docker", "compose", "-f", "compose.e2e.yaml", "down", "--remove-orphans"], cwd=COMPOSE)
    run(["docker", "compose", "-f", "compose.yaml", "down", "--remove-orphans"], cwd=LIVE)

    code, out = run(
        [
            "docker",
            "compose",
            "-f",
            "compose.e2e.yaml",
            "up",
            "-d",
            "--force-recreate",
            "--remove-orphans",
        ],
        cwd=COMPOSE,
        env={"APEX_BEARER_CERT_SHA256": client_fp or "0" * 64},
        timeout=300,
    )
    gate("compose_e2e_up", code == 0, out, required=True)

    code, out = run(
        [
            "docker",
            "compose",
            "-f",
            "compose.yaml",
            "up",
            "-d",
            "--force-recreate",
            "--remove-orphans",
        ],
        cwd=LIVE,
        env={"APEX_PROVIDER_CLIENT_CERT_SHA256": client_fp or "0" * 64},
        timeout=300,
    )
    gate("live_mtls_compose_up", code == 0, out, required=True)

    code, out = run(
        [
            sys.executable,
            str(COMPOSE / "e2e" / "wait_live_mtls.py"),
            "--secrets",
            str(LIVE / "secrets"),
            "--attempts",
            "90",
            "--sleep",
            "2",
        ],
        cwd=LIVE,
        timeout=240,
    )
    gate("live_mtls_ready", code == 0, out, required=True)

    cargo_ok = run(["cargo", "--version"])[0] == 0
    gate("cargo_available", cargo_ok, required=False)

    # Host-restricted tree (0600 private material) for Rust secret policy on Linux.
    # Docker services keep mounting LIVE/secrets (0644 keys for non-root images).
    host_secrets = LIVE / "secrets-host"
    if not host_secrets.is_dir() and (LIVE / "secrets").is_dir():
        import importlib.util

        gen_path = LIVE / "generate_pki.py"
        spec = importlib.util.spec_from_file_location("live_mtls_generate_pki", gen_path)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.write_host_secrets(LIVE / "secrets", host_secrets)
    secrets = str(host_secrets if host_secrets.is_dir() else LIVE / "secrets")
    test_env = {
        "APEX_LIVE_MTLS": "1",
        "APEX_LIVE_MTLS_SECRETS": secrets,
        "APEX_ALLOW_LOOPBACK_SINKS": "1",
        "APEX_POSTGRES_URL": "postgres://apex:apex_e2e_local_only@127.0.0.1:15432/apex?sslmode=disable",
        "APEX_ALLOW_POSTGRES_PLAINTEXT": "1",
    }

    if cargo_ok:
        code, out = run(
            [
                "cargo",
                "test",
                "--test",
                "live_mtls",
                "--features",
                "test-support,valkey",
                "--",
                "--nocapture",
            ],
            cwd=INGEST,
            env=test_env,
            timeout=900,
        )
        gate("live_mtls_rust_tests", code == 0, out, required=True)

        # Each postgres_* test opens its own connection via connect(); any
        # transport-level failure (including a transient one under
        # concurrent connection load) is deliberately mapped to the same
        # generic InvalidIdempotencyConfiguration/InvalidOutboxConfiguration
        # error as a real config problem, so these must run one at a time
        # rather than risk the default multi-threaded test runner opening
        # many connections to the loopback Postgres at once.
        postgres_test_env = {**test_env, "RUST_TEST_THREADS": "1"}
        code, out = run(
            [
                "cargo",
                "test",
                "--lib",
                "--features",
                "postgres,test-support",
                "postgres_",
                "--",
                "--nocapture",
            ],
            cwd=INGEST,
            env=postgres_test_env,
            timeout=600,
        )
        if code != 0:
            code2, out2 = run(
                [
                    "cargo",
                    "test",
                    "--lib",
                    "--features",
                    "postgres,test-support",
                    "--",
                    "--nocapture",
                ],
                cwd=INGEST,
                env=postgres_test_env,
                timeout=600,
            )
            gate("postgres_durability", code2 == 0, out + "\n" + out2, required=True)
        else:
            gate("postgres_durability", True, out, required=True)
    else:
        gate("live_mtls_rust_tests", False, "cargo not on PATH", required=False)
        gate("postgres_durability", False, "cargo not on PATH", required=False)

    # ------------------------------------------------------------------
    # Gateway image: build it, start it, and drive a real request through it.
    #
    # Everything above validates the gateway profile with `docker compose
    # config`, which parses YAML and never builds or starts anything. That is
    # why a Dockerfile that could not produce an image, a binary that panicked
    # before binding a listener, a data volume the runtime uid could not write,
    # secret material the gateway refuses by policy, and a missing JetStream
    # stream all survived: every other test drives the gateway in-process as a
    # library. These gates exercise the real image end to end.
    # ------------------------------------------------------------------
    gateway_env = {
        "APEX_BEARER_CERT_SHA256": client_fp or ("0" * 64),
        "APEX_PROVIDER_CLIENT_CERT_SHA256": client_fp or ("0" * 64),
    }
    gateway_project = ["-p", GATEWAY_PROJECT, "-f", "compose.gateway-ref.yaml"]
    run(
        ["docker", "compose", *gateway_project, "down", "-v", "--remove-orphans"],
        cwd=COMPOSE,
        env=gateway_env,
        timeout=180,
    )
    code, out = run(
        ["docker", "compose", *gateway_project, "build", "ingest-gateway"],
        cwd=COMPOSE,
        env=gateway_env,
        timeout=2400,
    )
    gate("gateway_image_build", code == 0, out, required=True)
    gateway_built = code == 0

    # The optional-feature build is a separate artifact and broke separately:
    # `--features postgres` compiles deploy/postgres/*.sql via include_str!, so
    # a build context that omits that directory fails outright and no image
    # with the Postgres backends could be produced at all.
    code, out = run(
        ["docker", "compose", *gateway_project, "build", "ingest-gateway"],
        cwd=COMPOSE,
        env={**gateway_env, "GATEWAY_CARGO_FEATURES": "valkey,postgres"},
        timeout=2400,
    )
    gate("gateway_image_build_optional_features", code == 0, out, required=True)

    gateway_up = False
    if gateway_built:
        code, out = run(
            ["docker", "compose", *gateway_project, "up", "-d", "--force-recreate"],
            cwd=COMPOSE,
            env=gateway_env,
            timeout=600,
        )
        if code == 0:
            ready, detail = _wait_for_gateway(COMPOSE, gateway_project, gateway_env)
            gateway_up = ready
            gate("gateway_container_starts", ready, out + "\n" + detail, required=True)
        else:
            gate("gateway_container_starts", False, out, required=True)
    else:
        gate("gateway_container_starts", False, "image build failed", required=True)

    # A serving listener is not proof that the service works. Drive the
    # committed adversarial corpus against the container: it sends real gRPC
    # over real mTLS and then queries ClickHouse and the archive directly, so
    # the happy path must actually land exactly once and every adversarial
    # input must land nowhere.
    if gateway_up and cargo_ok:
        run(
            [
                sys.executable,
                str(COMPOSE / "e2e" / "generate_adversarial_pki.py"),
            ],
            cwd=LIVE,
            timeout=180,
        )
        adversarial_env = {
            "APEX_ADVERSARIAL_GATEWAY": "https://localhost:18445",
            "APEX_ADVERSARIAL_SECRETS": secrets,
            "APEX_ADVERSARIAL_PKI": str(LIVE / "adversarial"),
            "APEX_ADVERSARIAL_CH_CONTAINER": f"{GATEWAY_PROJECT}-clickhouse-projection-1",
            "APEX_ADVERSARIAL_ARCHIVE_CONTAINER": f"{GATEWAY_PROJECT}-archive-provider-1",
        }
        code, out = run(
            [
                "cargo",
                "test",
                "--test",
                "adversarial_ingest",
                "--features",
                "test-support",
                "--",
                "--test-threads=1",
            ],
            cwd=INGEST,
            env=adversarial_env,
            timeout=1200,
        )
        gate("gateway_adversarial_corpus", code == 0, out, required=True)
    else:
        gate(
            "gateway_adversarial_corpus",
            False,
            "gateway container not serving" if not gateway_up else "cargo not on PATH",
            required=gateway_up,
        )

    run(
        ["docker", "compose", *gateway_project, "down", "-v", "--remove-orphans"],
        cwd=COMPOSE,
        env=gateway_env,
        timeout=180,
    )

    # Object-Lock MinIO
    minio_env = {
        "MINIO_ENDPOINT": "http://127.0.0.1:19000",
        "MINIO_ACCESS_KEY": "apexminio",
        "MINIO_SECRET_KEY": "apexminio_e2e_local_only",
        "MINIO_BUCKET": "apex-events",
    }
    code, out = run(
        [sys.executable, str(COMPOSE / "object_lock_acceptance.py")],
        cwd=COMPOSE,
        env=minio_env,
        timeout=120,
    )
    gate("object_lock_minio", code == 0, out, required=True)

    # Azure / GCS optional
    cloud_env = {"APEX_CLOUD_ACCEPTANCE_OPTIONAL": "1"}
    code, out = run(
        [sys.executable, str(COMPOSE / "object_lock_acceptance_azure.py")],
        cwd=COMPOSE,
        env=cloud_env,
        timeout=120,
    )
    # optional skip is pass when exit 0
    gate("archive_azure_acceptance", code == 0, out, required=False)
    code, out = run(
        [sys.executable, str(COMPOSE / "object_lock_acceptance_gcs.py")],
        cwd=COMPOSE,
        env=cloud_env,
        timeout=120,
    )
    gate("archive_gcs_acceptance", code == 0, out, required=False)

    # Compose config validation for overlays (needs bearer cert fingerprint)
    tmp = report_path.parent / "overlay-secrets"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "azure-connection-string").write_text("", encoding="utf-8")
    (tmp / "azure-account-key").write_text("", encoding="utf-8")
    (tmp / "gcs-sa.json").write_text("{}", encoding="utf-8")
    fp_env = {"APEX_BEARER_CERT_SHA256": client_fp or ("0" * 64)}
    code, out = run(
        ["docker", "compose", "-f", "compose.gateway-ref.yaml", "config"],
        cwd=COMPOSE,
        env=fp_env,
    )
    gate("compose_gateway_ref_config", code == 0, out, required=True)

    code, out = run(
        [
            "docker",
            "compose",
            "-f",
            "compose.gateway-ref.yaml",
            "-f",
            "compose.azure.yaml",
            "config",
        ],
        cwd=COMPOSE,
        env={
            **fp_env,
            "AZURE_CONNECTION_STRING_FILE": str(tmp / "azure-connection-string"),
            "AZURE_ACCOUNT_KEY_FILE": str(tmp / "azure-account-key"),
        },
    )
    gate("compose_azure_overlay_config", code == 0, out, required=True)

    code, out = run(
        [
            "docker",
            "compose",
            "-f",
            "compose.gateway-ref.yaml",
            "-f",
            "compose.gcs.yaml",
            "config",
        ],
        cwd=COMPOSE,
        env={
            **fp_env,
            "GCS_CREDENTIALS_FILE": str(tmp / "gcs-sa.json"),
            "APEX_ARCHIVE_GCS_BUCKET": "apex-ci-bucket",
        },
    )
    gate("compose_gcs_overlay_config", code == 0, out, required=True)

    _write(report_path, results, overall_ok)
    print()
    print("GATE_REPORT", report_path)
    print("OVERALL", "PASS" if overall_ok else "FAIL")
    return 0 if overall_ok else 1


def _wait_for_gateway(
    compose_dir: Path,
    project: list[str],
    env: dict[str, str],
    attempts: int = 60,
) -> tuple[bool, str]:
    """Waits until the gateway container is serving TLS on its published port.

    Checks the container state as well as the socket: a crash-looping container
    can still leave a bound port from a previous incarnation, and an exited
    container must be reported as a failure rather than a timeout.
    """
    import socket

    last = ""
    for attempt in range(1, attempts + 1):
        code, out = run(
            ["docker", "compose", *project, "ps", "-a", "--format", "{{.Name}} {{.State}}"],
            cwd=compose_dir,
            env=env,
            timeout=60,
        )
        last = out
        for line in out.splitlines():
            if "ingest-gateway" in line and "exited" in line.lower():
                _, logs = run(
                    ["docker", "compose", *project, "logs", "--no-color", "ingest-gateway"],
                    cwd=compose_dir,
                    env=env,
                    timeout=60,
                )
                return False, f"gateway container exited:\n{out}\n{logs}"
        try:
            with socket.create_connection(("127.0.0.1", 18445), timeout=2):
                return True, f"gateway serving on 127.0.0.1:18445 after {attempt} attempt(s)"
        except OSError as exc:
            last = f"{out}\nconnect: {exc}"
        time.sleep(2)
    _, logs = run(
        ["docker", "compose", *project, "logs", "--no-color", "--tail", "80"],
        cwd=compose_dir,
        env=env,
        timeout=60,
    )
    return False, f"{last}\n{logs}"


def _write(path: Path, results: list[dict], overall_ok: bool) -> None:
    payload = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform.platform(),
        "overall": "pass" if overall_ok else "fail",
        "gates": results,
        "notes": {
            "object_lock_minio": "Required for local archive gate. Passed when MinIO Object Lock retention and read-after-write succeed.",
            "archive_azure_gcs": "Optional without cloud credentials (APEX_CLOUD_ACCEPTANCE_OPTIONAL=1). Set real credentials to prove production cloud archive.",
            "production_compose": "Digest-pinned production images remain operator-owned. This suite proves reference stacks and local Object-Lock.",
        },
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    md = path.with_suffix(".md")
    lines = [
        "# Environment gate report",
        "",
        f"- Generated: `{payload['generated_at']}`",
        f"- Platform: `{payload['platform']}`",
        f"- Overall: **{payload['overall'].upper()}**",
        "",
        "| Gate | Status | Required |",
        "|------|--------|----------|",
    ]
    for g in results:
        lines.append(f"| `{g['name']}` | {g['status']} | {'yes' if g['required'] else 'no'} |")
    lines.extend(
        [
            "",
            "## Residual (operator environment)",
            "",
            "1. Set real Azure/GCS credentials and re-run cloud acceptance without optional skip.",
            "2. Replace floating images with digest-pinned production images in `deploy/compose/.env`.",
            "3. Run `preflight.ps1` / `preflight.sh` after secrets and digests are filled.",
            "",
            "Writing style: [ASD-STE100](../../docs/writing-style-ste100.md).",
            "",
        ]
    )
    md.write_text("\n".join(lines), encoding="utf-8")


def _client_cert_fingerprint(pem_path: Path) -> str | None:
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


if __name__ == "__main__":
    raise SystemExit(main())
