# Getting started with Apex

This guide helps you go from a repository clone to a working setup.

You do not need the full architecture on day one. Select the track that matches your goal.

---

## Select your track

| Goal | Time | Docker required | Track |
|------|------|-----------------|--------|
| Write agent events to disk. No crypto. No servers. | About 5 min | No | [A — Local first trace](#a--local-first-trace) |
| Install lab trust. Sign agent bundles. Create a trust pack. | About 10–15 min | No (optional later) | [B — Lab install](#b--lab-install) |
| Test real mTLS with NATS and providers. | About 20–40 min | Yes | [C — Live mTLS stack](#c--live-mtls-stack) |
| Run the gateway with reference providers. | About 30–60 min (build) | Yes | [D — Gateway and reference providers](#d--gateway-and-reference-providers) |
| Deploy hardened Compose with pinned images. | Hours (operations) | Yes | [E — Hardened Compose](#e--hardened-compose) |

Do track A. Then do track B. This path is enough for development and lab enrollment.

---

## What operational means

Phase 0 builds the foundation. Operational has a different meaning for each role.

| Role | You are operational when |
|------|--------------------------|
| Agent developer | `Apex.connect()` succeeds. Events write to JSONL or toward ingest. Preflight status is `ready`. Local profile can be `degraded` on purpose. |
| Lab platform owner | Lab install created signing keys and a trust pack. At least one signed `apex-agent.yaml` verifies. Optional Docker stacks can start. |
| Production operator | Digest-pinned images, mTLS secrets, archive backend, and preflight all pass. See Compose docs. This is not a day-one task. |

Day-one work does not need:

- Operator UI
- Full SPIFFE enrollment UI
- Cloud Object-Lock proof in your cloud account

---

## Prerequisites

| Tool | Local (A) | Lab (B) | Docker (C/D) |
|------|-----------|---------|--------------|
| Git and this repository | Yes | Yes | Yes |
| Python 3.11 or higher | Yes | Yes | Yes |
| `pip` | Yes | Yes | Yes |
| Python package `cryptography` | No* | Yes (installers install it) | Yes for PKI |
| Docker Engine and Compose v2 | No | Optional | Yes |
| Rust and `cargo` | No | No | Optional for live client tests |

\*Local demo needs only SDK dependencies (`rfc8785`).

---

## A — Local first trace

**Use this track** when you want proof that the SDK and event model work on your machine.

### Windows

1. Open a shell in the repository root.
2. Run:

```powershell
python -m pip install -e packages/sdk-python
python examples/reference-agent/run_demo.py
Get-Content .local/apex/events.jsonl -Wait
```

### Linux and macOS

1. Open a shell in the repository root.
2. Run:

```bash
python3 -m pip install -e packages/sdk-python
python3 examples/reference-agent/run_demo.py
# tail -f .local/apex/events.jsonl
```

### Success criteria

- The process completes without error (or continues if you keep a file watcher open).
- File `.local/apex/events.jsonl` contains hash-chained events.
- Events include turn, model, tool, and related types.
- Prompt and tool content are hashes. You can inspect the file safely.

### Limits of this track

- No control-plane servers.
- No mTLS.
- No signed staging or production bundles.
- Profile is `local-development` (offline JSONL).

**Next step:** [B — Lab install](#b--lab-install).

---

## B — Lab install

**Use this track** when you want install-time trust. Agents can enroll without custom crypto design.

### 1. Run the lab installer

**Windows**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\lab\install.ps1
```

**Linux and macOS**

```bash
chmod +x deploy/lab/install.sh
./deploy/lab/install.sh
```

**Any OS with Python**

```bash
python3 -m pip install 'cryptography>=42'
python3 deploy/lab/install_lab.py install
```

### 2. Install outputs

Default directory: `.local/apex-lab/` (git ignores this path).

| Path | Private | Purpose |
|------|---------|---------|
| `secrets/bundle-signing/*.private.pem` | Yes | Signs agent bundles. Do not copy this key to agent hosts. |
| `agent-trust-pack/` | No | Public PEMs, `trust.pins`, and env samples for agents. |
| `agents/lab-demo/apex-agent.yaml` | Non-secret | Signed integration bundle. |
| `agents/lab-demo/connect_example.py` | — | Connect smoke test. |
| `install-manifest.json` | No | Install metadata. |

Install also creates lab service PKI under `deploy/compose/live-mtls/secrets/` for Docker tracks.

### 3. Verify the demo agent

**Windows**

```powershell
$env:PYTHONPATH = "packages\sdk-python\src"
python .local\apex-lab\agents\lab-demo\connect_example.py
```

**Linux and macOS**

```bash
export PYTHONPATH=packages/sdk-python/src
python3 .local/apex-lab/agents/lab-demo/connect_example.py
```

### Success criteria

```text
preflight: ready staging lab-demo
```

This output means:

- The bundle signature matches the install trust pack (fingerprint pins).
- Gold-standard template controls passed.
- Staging profile includes an ingest endpoint reference.

This smoke test does not require a live gateway process.

### 4. Enroll your agent

**Windows**

```powershell
.\deploy\lab\install.ps1 enroll -Agent my-bot -Workspace acme -Namespace lab
```

**Linux and macOS**

```bash
./deploy/lab/install.sh enroll --agent my-bot --workspace acme --namespace lab
```

Use these paths in your app:

- Bundle: `.local/apex-lab/agents/my-bot/apex-agent.yaml`
- Trust directory: `.local/apex-lab/agent-trust-pack/trust`

You can also load env from `agent-trust-pack/agent.env` (Unix) or `agent.env.ps1` (Windows).

### 5. Example connect code

```python
from pathlib import Path
from apex_sdk import Apex

install = Path(".local/apex-lab")
apex = Apex.connect(
    bundle_path=install / "agents" / "my-bot" / "apex-agent.yaml",
    base_dir=install / "agents" / "my-bot",
    bundle_trust_keys_dir=install / "agent-trust-pack" / "trust",
    allow_local_profile=False,
    trace_dir=Path(".local/apex/my-bot"),
)
assert apex.preflight.ready
```

### Lab checklist

- [ ] Install prints `LAB_INSTALL_OK`.
- [ ] `connect_example.py` prints `preflight: ready`.
- [ ] Private signing key stays under `.local/apex-lab/secrets/`.
- [ ] Agents receive only the trust pack and signed YAML.
- [ ] You can enroll a second agent with `enroll`.

**More detail:** [deploy/lab/README.md](../deploy/lab/README.md)

---

## C — Live mTLS stack

**Use this track** when you need real TLS handshakes to Valkey, NATS, and reference HTTP providers.

**Windows**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\compose\live-mtls\run.ps1
```

After lab install (PKI already exists):

```bash
docker compose -f deploy/compose/live-mtls/compose.yaml up -d
```

Docker is required.

**More detail:** [deploy/compose/live-mtls/README.md](../deploy/compose/live-mtls/README.md)

---

## D — Gateway and reference providers

**Use this track** when you need the Rust ingest gateway to send events to JetStream and reference ClickHouse/archive over mTLS.

This path is for local and CI reference. It is not a production image set.

**Windows**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File deploy\compose\gateway-ref\run.ps1
```

**Any OS after lab install**

```bash
python3 deploy/lab/install_lab.py install --start-gateway-ref
```

First build can take several minutes. Ingest often binds to `https://127.0.0.1:18445`.

---

## Prove environment gates (recommended after C)

After Docker works, prove deploy-time gates on this machine:

```bash
python3 deploy/compose/e2e/run_gates.py
```

Success prints `OVERALL PASS` and writes `.local/apex-lab/gate-report.json`.

See [environment-gates.md](environment-gates.md).

## E — Hardened Compose

**Use this track** when you prepare a production-like environment.

Do tracks A and B first. Prefer C and D before E.

1. Copy `deploy/compose/.env.example` to `.env`.
2. Replace image placeholders with approved digests.
3. Create secret files.
4. Run `preflight.ps1` or `preflight.sh`.
5. Optional: add overlays for Valkey, Azure, or GCS.
6. Read [deploy/compose/README.md](../deploy/compose/README.md).

This path is strict on purpose. It is not a five-minute path.

---

## Decision flow

```text
Do you need events on disk only?
  Yes → Track A

Do you need signed bundles and a trust pack?
  Yes → Track B  (default for teams)

Do you need live TLS to NATS or providers?
  Yes → Track C

Do you need the gateway process and fan-out?
  Yes → Track D

Do you need a regulated or pinned production deploy?
  Yes → Track E
```

---

## Common problems and fixes

| Problem | Likely cause | Fix |
|---------|--------------|-----|
| Import error for `cryptography` | Package not installed | Run `python -m pip install cryptography`. Install wrappers try this. |
| Bundle signature or trust error | Wrong trust directory or missing pins | Use `agent-trust-pack/trust` from this install. Run install or enroll again. |
| Preflight blocked for staging | Bundle not signed or incomplete | Use lab `enroll`. Do not edit signature fields by hand. |
| Docker command fails | Docker not running | Start Docker. Install Compose v2. |
| `LAB_NOT_INSTALLED` | Install not run or wrong `--out` | Run install. Default out is `.local/apex-lab`. |
| Need a clean install | Old keys | Run install with `--force` or `install.ps1 -Force`. |

---

## Security rules for lab

1. Do not copy `*.private.pem` from bundle-signing to agent machines.
2. Keep trust pins enabled (`trust.pins` or `APEX_BUNDLE_REQUIRE_TRUST_PINS=true`).
3. Treat lab CA and lab signing keys as disposable. Regenerate with `--force` when the lab ends.
4. Production needs pinned images, external CA or HSM, and full preflight. Do not copy `.local/apex-lab` as production.

---

## Related documents

| Topic | Document |
|-------|----------|
| Lab installer | [deploy/lab/README.md](../deploy/lab/README.md) |
| Phase 0 status | [phase-0-progress.md](phase-0-progress.md) |
| External agent to ingest | [how-to-external-event-ingestion.md](how-to-external-event-ingestion.md) |
| Secure integration design | [architecture/Frictionless Secure Agent Integration.md](architecture/Frictionless%20Secure%20Agent%20Integration.md) |
| Compose and overlays | [deploy/compose/README.md](../deploy/compose/README.md) |
| Multi-cloud archive | [architecture/Multi-Cloud Archive Adapters.md](architecture/Multi-Cloud%20Archive%20Adapters.md) |
| Product overview | [README.md](../README.md) |
| Writing style (STE) | [writing-style-ste100.md](writing-style-ste100.md) |

---

## Summary

| Your goal today | Do this track |
|-----------------|---------------|
| Solo developer, first look | A — local demo |
| Team lab and safe agent enroll | B — lab install |
| Platform validation of durable path | B, then C, then D. Do E when ready for pinned deploy. |

Lab operational means: install succeeds, preflight is ready, private keys stay private, and agents enroll from the install authority.
