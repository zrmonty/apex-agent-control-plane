# Model Execution Attribution

**Status:** Accepted — Phase 0 FinOps contract  
**Date:** 2026-08-03

## Purpose

Every LLM execution must state:

1. What the agent requested.
2. What the provider executed.
3. What usage and cost evidence returned.

This makes fallback, reasoning-effort selection, routing, and billing explainable in Cost Lens. It does not collect prompt or completion content.

## LLM execution attribution

The canonical `llm` event data gains a versioned `execution` object.

The fields `provider`, `model`, `input_tokens`, and `output_tokens` stay supported during migration. The `execution` object is the FinOps source.

```text
execution:
  requested:
    provider
    model
    reasoning_effort?       # normalized safe enum or provider-safe identifier
    service_tier?           # standard | priority | batch | provider-safe identifier
    region?
    max_output_tokens?
  effective:
    provider
    model
    model_revision?
    reasoning_effort?
    service_tier?
    region?
    routing_reason?         # configured | fallback | capacity | policy | user_override
  usage:
    input_tokens?
    cached_input_tokens?
    cache_write_tokens?
    output_tokens?
    reasoning_tokens?
    image_units?
    audio_units?
    embedding_tokens?
    tool_units?
  evidence:
    source                 # provider_receipt | sdk_observed | configured | estimated
    receipt_id_hash?
    observed_at
    currency?
```

All identifiers must be bounded safe identifiers. Token and unit fields must be non-negative integers.

Map provider-specific values through one adapter. Keep them only when they are safe identifiers. Never store arbitrary provider response text.

## Truthfulness rules

1. `requested` is caller configuration. It is not proof of execution.
2. `effective` is the model, provider, or tier reported by the provider or trusted routing layer. If it is unavailable, omit it. Do not copy `requested` and label it as effective.
3. `provider_receipt` is the highest-confidence billing evidence. `sdk_observed` is next. `configured` and `estimated` are planning data only.
4. A fallback or reroute must be explicit through different requested and effective values and a `routing_reason`.
5. Actual billed usage is immutable. Reconciliation adds a linked adjustment. It never overwrites a historical event or ledger entry.
6. Reasoning effort and token categories are metadata only. Prompts, completions, chain-of-thought, and raw provider receipts stay excluded unless a separate content-capture policy allows them.

## Cost Lens outcomes

This contract enables per-run through yearly analysis of:

- Cost, latency, quality, and error rate by requested or effective model and reasoning effort
- Fallback and routing cost deltas
- Actual versus estimated or reconciled spend
- Cache effectiveness by model or tier
- Cost per successful task or evaluation gate
- Safe budget caps based on the effective provider, model, and tier rate card

## Phase 0 delivery

1. Extend Protobuf and JSON Schema and Python and Rust validators. Keep v1 compatibility through an optional `execution` object.
2. Add provider-adapter extraction for the reference runtime and the first supported providers. Unsupported providers emit only known, truthful fields.
3. Add typed SDK builders and OpenTelemetry mapping for normalized requested and effective model and usage categories.
4. Add ClickHouse projection fields and immutable cost-ledger linkage with evidence source and confidence.
5. Test fallback, partial provider receipts, absent reasoning effort, retry, cache tokens, malformed units, price-card change, and redaction paths.

## Acceptance criteria

- A model fallback is visible as a requested versus effective difference on the exact run.
- If a provider does not support reasoning effort or a token category, Apex shows it as unavailable. Apex does not invent zero or actual values.
- Cost Lens can filter and aggregate by effective model, effective effort, provider, evidence source, and confidence without reading content.
- Any provider receipt or SDK adapter change is traceable to its adapter and version. It cannot alter historic accounting.

Writing style: [ASD-STE100 Simplified Technical English](../writing-style-ste100.md).
