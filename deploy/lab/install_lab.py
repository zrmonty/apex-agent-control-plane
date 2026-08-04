#!/usr/bin/env python3
"""Apex lab control-plane installer (Windows, Linux, macOS).

Generates installation trust material so agents can enroll without inventing crypto:

  - Ed25519 bundle signing key (private on control plane only)
  - Public trust pack + trust.pins (safe to copy to agent hosts)
  - Live-mTLS service PKI (local/lab only)
  - Optional demo signed apex-agent.yaml
  - Optional Docker stack start (live-mTLS and/or gateway-ref)

NEVER use lab keys or this install profile for regulated production.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

# Repo root: deploy/lab/install_lab.py -> parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / ".local" / "apex-lab"
LIVE_MTLS = REPO_ROOT / "deploy" / "compose" / "live-mtls"
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
SDK_SRC = REPO_ROOT / "packages" / "sdk-python" / "src"


def _die(message: str, code: int = 1) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(code)


def _info(message: str) -> None:
    print(f"==> {message}")


def _ensure_sdk_path() -> None:
    path = str(SDK_SRC)
    if path not in sys.path:
        sys.path.insert(0, path)


def _chmod_private(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass


def _chmod_private_dir(path: Path) -> None:
    try:
        path.chmod(stat.S_IRWXU)  # 0o700
    except OSError:
        pass


def _write_text(path: Path, text: str, *, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if private:
        _chmod_private(path)


def _run(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    display = " ".join(cmd)
    _info(f"run: {display}")
    merged = os.environ.copy()
    if env:
        merged.update(env)
    try:
        subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=merged, check=True)
    except FileNotFoundError as exc:
        _die(f"command not found: {cmd[0]} ({exc})")
    except subprocess.CalledProcessError as exc:
        _die(f"command failed ({exc.returncode}): {display}")


def _require_python_deps() -> None:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        _die(
            "Python package 'cryptography' is required. "
            "Install with: python -m pip install cryptography"
        )


def _platform_tag() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "linux"


def generate_bundle_authority(out: Path, *, key_id: str, force: bool) -> dict[str, str]:
    _ensure_sdk_path()
    from apex_sdk.bundle import generate_bundle_signing_key

    secrets = out / "secrets" / "bundle-signing"
    secrets.mkdir(parents=True, exist_ok=True)
    _chmod_private_dir(secrets)
    private_path = secrets / f"{key_id}.private.pem"
    public_path = secrets / f"{key_id}.public.pem"
    meta_path = secrets / f"{key_id}.json"

    if private_path.exists() and not force:
        _info(f"reusing existing bundle signing key {key_id}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        return {
            "key_id": key_id,
            "private_pem": private_path.read_text(encoding="ascii"),
            "public_pem": public_path.read_text(encoding="ascii"),
            "fingerprint": meta["fingerprint"],
        }

    keys = generate_bundle_signing_key(key_id=key_id)
    _write_text(private_path, keys["private_pem"], private=True)
    _write_text(public_path, keys["public_pem"])
    _write_text(
        meta_path,
        json.dumps(
            {
                "key_id": key_id,
                "fingerprint": keys["fingerprint"],
                "algorithm": "ed25519",
                "profile": "lab",
            },
            indent=2,
        )
        + "\n",
        private=True,
    )
    _info(f"created bundle signing key {key_id} fingerprint={keys['fingerprint'][:16]}…")
    return keys


def write_agent_trust_pack(
    out: Path,
    keys: dict[str, str],
    *,
    ca_pem_src: Path | None,
    ingest_endpoint: str,
) -> Path:
    pack = out / "agent-trust-pack"
    trust = pack / "trust"
    trust.mkdir(parents=True, exist_ok=True)
    key_id = keys["key_id"]
    _write_text(trust / f"{key_id}.pem", keys["public_pem"])
    _write_text(trust / "trust.pins", f"{key_id} {keys['fingerprint']}\n")

    if ca_pem_src is not None and ca_pem_src.is_file():
        _write_text(pack / "ca.pem", ca_pem_src.read_text(encoding="utf-8"))

    env_unix = f"""# Source on Linux/macOS agent hosts (lab only).
# export APEX_BUNDLE_TRUST_KEYS_DIR="{trust.resolve().as_posix()}"
# export APEX_BUNDLE_REQUIRE_TRUST_PINS=true
# Optional explicit pins:
# export APEX_BUNDLE_TRUST_PINS="{key_id}:{keys['fingerprint']}"
APEX_BUNDLE_TRUST_KEYS_DIR={trust.resolve().as_posix()}
APEX_BUNDLE_REQUIRE_TRUST_PINS=true
APEX_BUNDLE_TRUST_PINS={key_id}:{keys['fingerprint']}
APEX_INGEST_ENDPOINT={ingest_endpoint}
"""
    env_ps = f"""# Dot-source on Windows PowerShell agent hosts (lab only).
# . .\\agent.env.ps1
$env:APEX_BUNDLE_TRUST_KEYS_DIR = "{trust.resolve()}"
$env:APEX_BUNDLE_REQUIRE_TRUST_PINS = "true"
$env:APEX_BUNDLE_TRUST_PINS = "{key_id}:{keys['fingerprint']}"
$env:APEX_INGEST_ENDPOINT = "{ingest_endpoint}"
"""
    _write_text(pack / "agent.env", env_unix)
    _write_text(pack / "agent.env.ps1", env_ps)

    readme = f"""# Apex lab agent trust pack

This directory is **public-only** material for agent hosts.

## Contents

| Path | Purpose |
|------|---------|
| `trust/{key_id}.pem` | Operator Ed25519 public key |
| `trust/trust.pins` | key_id → fingerprint (blocks dropped PEMs) |
| `ca.pem` | Lab service CA (when live-mTLS PKI was generated) |
| `agent.env` / `agent.env.ps1` | Environment for SDK verify |

## Connect (Python)

```python
from pathlib import Path
from apex_sdk import Apex

pack = Path(r"{pack.resolve()}")
apex = Apex.connect(
    bundle_path=pack.parent / "agents" / "lab-demo" / "apex-agent.yaml",  # after enroll
    base_dir=pack.parent / "agents" / "lab-demo",
    bundle_trust_keys_dir=pack / "trust",
    allow_local_profile=False,
)
```

Or set env from `agent.env` / `agent.env.ps1` and point `Apex.connect` at the signed bundle.

## Security

- Never place `*.private.pem` from the install secrets tree on agent hosts.
- Lab keys are not for production.
- Prefer `APEX_BUNDLE_REQUIRE_TRUST_PINS=true` always in non-local profiles.
"""
    _write_text(pack / "README.md", readme)
    return pack


def generate_service_pki(*, force: bool) -> Path:
    secrets = LIVE_MTLS / "secrets"
    if secrets.is_dir() and (secrets / "ca.pem").is_file() and not force:
        _info("reusing existing live-mTLS PKI")
        return secrets

    _info("generating live-mTLS service PKI (lab only)")
    gen = LIVE_MTLS / "generate_pki.py"
    render = LIVE_MTLS / "render_configs.py"
    if not gen.is_file():
        _die(f"missing {gen}")
    _run([sys.executable, str(gen), "--out", str(secrets)])
    if render.is_file():
        _run([sys.executable, str(render)], cwd=LIVE_MTLS)
    return secrets


def enroll_agent(
    out: Path,
    keys: dict[str, str],
    *,
    agent_code: str,
    workspace_id: str,
    namespace_id: str,
    profile: str,
    ingest_endpoint: str,
    trust_bundle_path: str | None,
    validity_days: int,
    force: bool,
) -> Path:
    _ensure_sdk_path()
    from apex_sdk.bundle import write_signed_bundle
    from apex_sdk.template import gold_standard_manifest

    agent_dir = out / "agents" / agent_code
    agent_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = agent_dir / "apex-agent.yaml"
    if bundle_path.exists() and not force:
        _info(f"reusing signed bundle at {bundle_path}")
        return bundle_path

    document: dict[str, Any] = {
        "bundle_version": "apex-agent-bundle.v1",
        "profile": profile,
        "agent_code": agent_code,
        "scope": {"workspace_id": workspace_id, "namespace_id": namespace_id},
        "ingest_endpoint": ingest_endpoint,
        "tool_allowlist": ["reference_tool"],
        "egress_allowlist": [],
        "template": gold_standard_manifest(agent_code),
        "policy_revision": "lab-1",
        "identity_ref": "lab-enrollment",
    }
    if trust_bundle_path:
        document["trust_bundle_path"] = trust_bundle_path
    elif profile == "production":
        # Lab production profile still needs a trust_bundle_path reference for preflight.
        ca = out / "agent-trust-pack" / "ca.pem"
        if ca.is_file():
            document["trust_bundle_path"] = str(ca.resolve())

    write_signed_bundle(
        bundle_path,
        document,
        private_key_pem=keys["private_pem"],
        key_id=keys["key_id"],
        issuer="apex-lab-install",
        validity=timedelta(days=validity_days),
    )
    _chmod_private(bundle_path)  # signed non-secret, but keep host-local by default
    # Bundles are non-secret; make readable for the installing user only is fine.
    try:
        bundle_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass

    connect_py = '''"""Connect using lab install materials (generated)."""
from pathlib import Path
from apex_sdk import Apex

ROOT = Path(__file__).resolve().parent
# .../agents/<code> → install root is parent of agents/
INSTALL = ROOT.parent.parent
pack_trust = INSTALL / "agent-trust-pack" / "trust"

apex = Apex.connect(
    bundle_path=ROOT / "apex-agent.yaml",
    base_dir=ROOT,
    bundle_trust_keys_dir=pack_trust,
    allow_local_profile=False,
    trace_dir=ROOT / "trace",
)
print("preflight:", apex.preflight.status, apex.preflight.profile, apex.preflight.agent_code)
'''
    _write_text(agent_dir / "connect_example.py", connect_py)
    _info(f"enrolled agent {agent_code} → {bundle_path}")
    return bundle_path


def write_install_manifest(out: Path, payload: dict[str, Any]) -> None:
    _write_text(out / "install-manifest.json", json.dumps(payload, indent=2) + "\n")


def write_install_readme(out: Path, manifest: dict[str, Any]) -> None:
    text = f"""# Apex lab install

Generated by `deploy/lab/install_lab.py` on **{manifest.get('platform')}**.

## Layout

| Path | Sensitivity | Purpose |
|------|-------------|---------|
| `secrets/bundle-signing/` | **Private** | Ed25519 private key for signing agent bundles |
| `agent-trust-pack/` | Public | PEMs + pins + env for agent hosts |
| `agents/<code>/apex-agent.yaml` | Non-secret signed config | Per-agent integration bundle |
| `install-manifest.json` | Non-secret | Install metadata |

## Next steps

### 1. Verify demo agent (no Docker)

```bash
# Linux / macOS
export PYTHONPATH="{SDK_SRC.as_posix()}"
python agents/lab-demo/connect_example.py
```

```powershell
# Windows
$env:PYTHONPATH = "{SDK_SRC}"
python agents\\lab-demo\\connect_example.py
```

### 2. Start live mTLS stack (optional)

```bash
# Linux / macOS
./deploy/lab/install.sh --start-live-mtls
# or after install:
docker compose -f deploy/compose/live-mtls/compose.yaml up -d
```

```powershell
# Windows
.\\deploy\\lab\\install.ps1 -StartLiveMtls
```

### 3. Enroll another agent

```bash
python deploy/lab/install_lab.py enroll --agent my-bot --workspace acme --namespace lab
```

### 4. Gateway + reference providers (optional, builds Rust image)

```bash
python deploy/lab/install_lab.py install --start-gateway-ref
```

## Security

- Lab only. Regenerate keys with `--force` when disposing a lab.
- Do not commit `.local/apex-lab/` (gitignored).
- Do not copy `secrets/bundle-signing/*.private.pem` to agent machines.
"""
    _write_text(out / "README.md", text)


def cmd_install(args: argparse.Namespace) -> int:
    _require_python_deps()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    _info(f"Apex lab install → {out}")
    _info(f"platform={_platform_tag()} python={sys.version.split()[0]}")
    (out / "secrets").mkdir(parents=True, exist_ok=True)
    _chmod_private_dir(out / "secrets")

    keys = generate_bundle_authority(out, key_id=args.key_id, force=args.force)

    ca_src: Path | None = None
    if not args.skip_service_pki:
        secrets = generate_service_pki(force=args.force)
        ca_src = secrets / "ca.pem"
        # Ensure bearer token for gateway-ref parity
        bearer = secrets / "ingest-bearer-token"
        if not bearer.is_file():
            _write_text(bearer, "lab-gateway-ref-token", private=True)

    ingest = args.ingest_endpoint
    pack = write_agent_trust_pack(out, keys, ca_pem_src=ca_src, ingest_endpoint=ingest)

    demo_bundle = None
    if not args.skip_demo_enroll:
        demo_bundle = enroll_agent(
            out,
            keys,
            agent_code=args.demo_agent,
            workspace_id=args.workspace,
            namespace_id=args.namespace,
            profile=args.profile,
            ingest_endpoint=ingest,
            trust_bundle_path=str((pack / "ca.pem").resolve()) if (pack / "ca.pem").is_file() else None,
            validity_days=args.validity_days,
            force=args.force,
        )

    if args.start_live_mtls:
        _require_docker()
        _run(["docker", "compose", "-f", "compose.yaml", "up", "-d"], cwd=LIVE_MTLS)

    if args.start_gateway_ref:
        _require_docker()
        # bearer already ensured
        _run(
            ["docker", "compose", "-f", "compose.gateway-ref.yaml", "up", "-d", "--build"],
            cwd=COMPOSE_DIR,
        )

    manifest = {
        "profile": "lab",
        "platform": _platform_tag(),
        "platform_detail": platform.platform(),
        "python": sys.version.split()[0],
        "out": str(out),
        "key_id": keys["key_id"],
        "fingerprint": keys["fingerprint"],
        "ingest_endpoint": ingest,
        "agent_trust_pack": str(pack),
        "demo_bundle": str(demo_bundle) if demo_bundle else None,
        "service_pki": str(LIVE_MTLS / "secrets") if not args.skip_service_pki else None,
        "require_trust_pins": True,
    }
    write_install_manifest(out, manifest)
    write_install_readme(out, manifest)

    print()
    print("LAB_INSTALL_OK")
    print(f"  out:              {out}")
    print(f"  signing key_id:   {keys['key_id']}")
    print(f"  fingerprint:      {keys['fingerprint']}")
    print(f"  agent trust pack: {pack}")
    if demo_bundle:
        print(f"  demo bundle:      {demo_bundle}")
    print(f"  verify:           python {out / 'agents' / args.demo_agent / 'connect_example.py'}")
    print("  docs:             ", out / "README.md")
    return 0


def _require_docker() -> None:
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        _die("Docker is required for --start-live-mtls / --start-gateway-ref but is not available")


def cmd_enroll(args: argparse.Namespace) -> int:
    _require_python_deps()
    out = Path(args.out).resolve()
    if not out.is_dir():
        _die(f"install directory not found: {out} (run install first)")
    key_id = args.key_id
    private_path = out / "secrets" / "bundle-signing" / f"{key_id}.private.pem"
    public_path = out / "secrets" / "bundle-signing" / f"{key_id}.public.pem"
    meta_path = out / "secrets" / "bundle-signing" / f"{key_id}.json"
    if not private_path.is_file():
        _die(f"missing signing key {private_path}")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.is_file() else {}
    keys = {
        "key_id": key_id,
        "private_pem": private_path.read_text(encoding="ascii"),
        "public_pem": public_path.read_text(encoding="ascii"),
        "fingerprint": meta.get("fingerprint", ""),
    }
    pack = out / "agent-trust-pack"
    trust_ca = pack / "ca.pem"
    path = enroll_agent(
        out,
        keys,
        agent_code=args.agent,
        workspace_id=args.workspace,
        namespace_id=args.namespace,
        profile=args.profile,
        ingest_endpoint=args.ingest_endpoint,
        trust_bundle_path=str(trust_ca.resolve()) if trust_ca.is_file() else None,
        validity_days=args.validity_days,
        force=args.force,
    )
    print("LAB_ENROLL_OK")
    print(f"  bundle: {path}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    out = Path(args.out).resolve()
    manifest_path = out / "install-manifest.json"
    if not manifest_path.is_file():
        print("LAB_NOT_INSTALLED")
        print(f"  expected: {manifest_path}")
        return 1
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    print("LAB_INSTALLED")
    print(json.dumps(data, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Apex lab control-plane installer (Windows, Linux, macOS)",
    )
    parser.add_argument(
        "--out",
        default=str(DEFAULT_OUT),
        help=f"install output directory (default: {DEFAULT_OUT})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    install = sub.add_parser("install", help="Generate lab install materials")
    install.add_argument("--key-id", default="operator-1", help="bundle signing key id")
    install.add_argument("--force", action="store_true", help="regenerate keys and bundles")
    install.add_argument("--skip-service-pki", action="store_true", help="skip live-mTLS PKI")
    install.add_argument("--skip-demo-enroll", action="store_true", help="skip lab-demo agent")
    install.add_argument("--demo-agent", default="lab-demo")
    install.add_argument("--workspace", default="lab")
    install.add_argument("--namespace", default="demo")
    install.add_argument(
        "--profile",
        default="staging",
        choices=("staging", "production", "local-development"),
    )
    install.add_argument(
        "--ingest-endpoint",
        default="https://127.0.0.1:18445",
        help="ingest endpoint written into demo bundle",
    )
    install.add_argument("--validity-days", type=int, default=90)
    install.add_argument(
        "--start-live-mtls",
        action="store_true",
        help="docker compose up live-mTLS stack",
    )
    install.add_argument(
        "--start-gateway-ref",
        action="store_true",
        help="docker compose up gateway-ref (builds ingest image)",
    )
    install.set_defaults(func=cmd_install)

    enroll = sub.add_parser("enroll", help="Sign a new agent bundle with install key")
    enroll.add_argument("--agent", required=True, help="agent_code")
    enroll.add_argument("--workspace", default="lab")
    enroll.add_argument("--namespace", default="demo")
    enroll.add_argument("--key-id", default="operator-1")
    enroll.add_argument(
        "--profile",
        default="staging",
        choices=("staging", "production", "local-development"),
    )
    enroll.add_argument("--ingest-endpoint", default="https://127.0.0.1:18445")
    enroll.add_argument("--validity-days", type=int, default=90)
    enroll.add_argument("--force", action="store_true")
    enroll.set_defaults(func=cmd_enroll)

    status = sub.add_parser("status", help="Show install manifest if present")
    status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
