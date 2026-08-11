#!/usr/bin/env python3
"""Apex lab control-plane installer (Windows, Linux, macOS).

Generates installation trust material so agents can enroll without inventing crypto:

  - Ed25519 bundle signing key (private on control plane only)
  - Public trust pack + trust.pins (safe to copy to agent hosts)
  - Live-mTLS service PKI (local/lab only)
  - Optional demo signed apex-agent.yaml
  - Optional Docker stack start (live-mTLS and/or gateway-ref)

NEVER use lab keys or this install profile for regulated production.

The functions that actually generate this material (the bundle signing key,
the agent trust pack, the live-mTLS PKI, a signed agent bundle, and the
install manifest/README), plus the small generic utilities they and the
command handlers below share, live in ``_lab_materials.py`` -- this file
keeps the CLI wiring: argument parsing and the ``install``/``enroll``/
``status`` command handlers.
"""

from __future__ import annotations

import argparse
import json
import platform
import secrets as secure_secrets
import subprocess
import sys
from pathlib import Path

from _lab_materials import (
    REPO_ROOT,
    LIVE_MTLS,
    _die,
    _info,
    _chmod_private_dir,
    _platform_tag,
    _require_python_deps,
    _run,
    _write_text,
    enroll_agent,
    generate_bundle_authority,
    generate_service_pki,
    write_agent_trust_pack,
    write_install_manifest,
    write_install_readme,
)

DEFAULT_OUT = REPO_ROOT / ".local" / "apex-lab"
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"


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
            _write_text(bearer, secure_secrets.token_urlsafe(32), private=True)

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
