# Apex lab installer

> **New users:** read [Getting started](../../docs/getting-started.md) (track B). Then use this page for installer flags and file layout.

This installer bootstraps a **lab** control plane on Windows, Linux, and macOS.

## What the installer does

1. Creates an Ed25519 bundle signing key. The private key stays on the install host.
2. Creates an agent trust pack. The pack holds public PEMs, `trust.pins`, and env samples.
3. Creates live-mTLS service PKI under `deploy/compose/live-mtls/secrets/` (default on).
4. Enrolls a demo agent with a signed `apex-agent.yaml`.
5. Can start Docker stacks (`live-mTLS`, `gateway-ref`) when you set the flags.

This installer is for lab use only. Do not use lab keys for regulated production.

## Requirements

| Tool | Notes |
|------|--------|
| Python 3.11 or higher | `python`, `python3`, or Windows `py -3` |
| Package `cryptography` | Shell wrappers install it when needed |
| Docker | Only for `--start-live-mtls` or `--start-gateway-ref` |

## Quick start

### Windows (PowerShell)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\lab\install.ps1
```

### Linux and macOS

```bash
chmod +x deploy/lab/install.sh
./deploy/lab/install.sh
```

### Any OS (Python)

```bash
python3 -m pip install 'cryptography>=42'
python3 deploy/lab/install_lab.py install
```

Default output directory: `.local/apex-lab/` (git ignores this path).

## Output layout

```text
.local/apex-lab/
  secrets/bundle-signing/     # PRIVATE: operator-1.private.pem
  agent-trust-pack/           # PUBLIC: trust/*.pem, trust.pins, agent.env*
  agents/lab-demo/
    apex-agent.yaml           # signed integration bundle
    connect_example.py
  install-manifest.json
  README.md
```

## Verify without Docker

**Linux and macOS**

```bash
export PYTHONPATH=packages/sdk-python/src
python3 .local/apex-lab/agents/lab-demo/connect_example.py
```

**Windows**

```powershell
$env:PYTHONPATH = "packages\sdk-python\src"
python .local\apex-lab\agents\lab-demo\connect_example.py
```

Expected output: `preflight: ready staging lab-demo`.

## Enroll another agent

**Linux and macOS**

```bash
./deploy/lab/install.sh enroll --agent my-bot --workspace acme --namespace lab
```

**Windows**

```powershell
.\deploy\lab\install.ps1 enroll -Agent my-bot -Workspace acme -Namespace lab
```

## Optional Docker

```bash
./deploy/lab/install.sh install --start-live-mtls
./deploy/lab/install.sh install --start-gateway-ref
```

```powershell
.\deploy\lab\install.ps1 -StartLiveMtls
.\deploy\lab\install.ps1 -StartGatewayRef
```

## Commands

| Command | Purpose |
|---------|---------|
| `install` | Full lab bootstrap (default) |
| `enroll` | Sign a new agent bundle with the install key |
| `status` | Print `install-manifest.json` |

### Common flags (Python and `install.sh`)

| Flag | Meaning |
|------|---------|
| `--out PATH` | Install directory (default `.local/apex-lab`) |
| `--force` | Create new keys and a new demo bundle |
| `--skip-service-pki` | Skip live-mTLS certificate generation |
| `--skip-demo-enroll` | Skip the `lab-demo` agent |
| `--profile staging\|production` | Bundle profile |
| `--start-live-mtls` | Start live-mTLS with Docker Compose |
| `--start-gateway-ref` | Build and run gateway with reference providers |

PowerShell maps the same options as `-Force`, `-SkipServicePki`, `-StartLiveMtls`, and related switches.

## Security rules

1. Do not put the private signing key in the agent trust pack.
2. Trust pins block extra PEMs that someone drops into the trust directory.
3. Service PKI under `deploy/compose/live-mtls/secrets/` is lab only (30-day CA).
4. For production, use digest-pinned images, external CA or HSM, and full Compose preflight.

## Related scripts

| Script | Role |
|--------|------|
| `deploy/lab/install_*` | Install, trust pack, and enroll |
| `deploy/compose/live-mtls/run.ps1` | PKI, stack, and Rust handshake tests |
| `deploy/compose/gateway-ref/run.ps1` | Gateway against reference providers |
| `deploy/compose/e2e/run.ps1` | Broader end-to-end path |

Writing style: [ASD-STE100](../../docs/writing-style-ste100.md).
