"""Material-generation helpers for ``install_lab.py``.

Split out of ``install_lab.py`` because it is a standalone script (not part
of the ``apex_sdk`` package) that grew past a comfortable single-file size.
This module holds the pieces that actually *generate* lab install material --
the bundle signing key, the agent trust pack, the live-mTLS service PKI, a
signed agent bundle, and the install manifest/README -- plus the small
generic utilities (``_die``, ``_info``, path/permission helpers, ``_run``)
those functions and ``install_lab.py``'s own CLI command handlers both use.

``install_lab.py`` keeps the CLI wiring (argument parsing and the
``cmd_install``/``cmd_enroll``/``cmd_status`` command handlers) and imports
everything it needs from here. This module has no dependency on
``install_lab.py`` in the other direction, so the two can be read (and
imported) independently.

Conservative on purpose: this script has no automated test coverage, so the
split is pure code motion with no behavior changes -- every function below is
unchanged from its original body, just relocated.
"""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

# Repo root: deploy/lab/_lab_materials.py -> parents[2]
REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_MTLS = REPO_ROOT / "deploy" / "compose" / "live-mtls"
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
