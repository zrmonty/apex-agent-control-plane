# Gold-standard reference agent

This is the smallest local agent that follows the Apex Phase 0 contract.

The agent:

- Connects with `Apex.connect()` and a local-development preflight.
- Assesses the gold-standard agent template before work starts.
- Emits a validated, UUIDv7, hash-chained lifecycle trace with model execution attribution.
- Records only bounded references and hashes. It does not record prompts or tool output.
- Writes JSONL locally. ClickHouse and NATS are optional for this demo.

## Run from the repository root

```powershell
$env:PYTHONPATH = "packages/sdk-python/src"
python examples/reference-agent/run_demo.py
Get-Content .local/apex/events.jsonl -Wait
```

## Output files

- `.local/apex/agent-bundle.json` — non-secret local integration bundle
- `.local/apex/agent-template.json` — template assessment metadata
- `.local/apex/events.jsonl` — observable Apex event stream

## Production note

For production, replace the JSONL sink with an authenticated exporter only after workload identity, scope, TLS, redaction, and provider configuration pass preflight.

Template controls are implementation evidence. They do not certify SOC 2, HIPAA, SEC, or FedRAMP compliance.

Day-one paths: [Getting started](../../docs/getting-started.md).

Writing style: [ASD-STE100](../../docs/writing-style-ste100.md).
