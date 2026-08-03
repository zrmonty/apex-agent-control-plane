# Gold-standard reference agent

This is the smallest local agent that follows the Apex Phase 0 contract. It:

- declares the apex-agent-template.v1 controls;
- refuses to run if the manifest is noncompliant;
- emits a validated, UUIDv7, hash-chained lifecycle trace;
- records only bounded references and hashes, not prompts or tool output;
- writes JSONL locally, so ClickHouse and NATS are optional for this demo.

From the repository root:

    $env:PYTHONPATH = "packages/sdk-python/src"
    python examples/reference-agent/run_demo.py
    Get-Content .local/apex/events.jsonl -Wait

The demo writes:

- .local/apex/agent-template.json — non-secret capability manifest;
- .local/apex/events.jsonl — observable Apex event stream.

For production, replace the JSONL sink with an authenticated exporter only
after workload identity, scope, TLS, redaction, and provider configuration
have passed preflight. The template controls provide implementation evidence;
they do not by themselves certify SOC 2, HIPAA, SEC, or FedRAMP compliance.
