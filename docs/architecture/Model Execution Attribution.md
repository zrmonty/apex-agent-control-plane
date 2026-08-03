# Model Execution Attribution

**Status:** Accepted — Phase 0 FinOps contract  
**Date:** 2026-08-03

## Purpose

Every LLM execution must state what the agent requested, what the provider actually executed, and what usage/cost evidence was returned. This makes model fallback, reasoning-effort selection, routing, and billing explainable in Cost Lens without collecting prompt or completion content.

## LLM execution attribution

The canonical `llm` event data gains a versioned `execution` object. The existing `provider`, `model`, `input_tokens`, and `output_tokens` fields remain supported during migration, but the `execution` object becomes the FinOps source.

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

All identifiers are validated as bounded safe identifiers. Token/unit fields are non-negative integers. Provider-specific values are mapped through a single adapter and preserved only when they are safe identifiers; arbitrary provider response text is never stored.

## Truthfulness rules

1. `requested` means the caller configuration, never proof of execution.
2. `effective` means the model/provider/tier reported by the provider or trusted routing layer. If unavailable, it is absent—not copied from `requested` and mislabeled.
3. `provider_receipt` is the highest-confidence billing evidence. `sdk_observed` is next. `configured` and `estimated` are planning data only.
4. A fallback/reroute is always explicit through differing requested/effective values and a `routing_reason`.
5. Actual billed usage is immutable. Reconciliation adds a linked adjustment; it never overwrites a historical event or ledger entry.
6. Reasoning effort and token categories are metadata only. Prompts, completions, chain-of-thought, and provider raw receipts remain excluded unless separately allowed by content-capture policy.

## Cost Lens outcomes

This contract enables per-run through yearly analysis of:

- cost, latency, quality, and error rate by requested/effective model and reasoning effort;
- fallback and routing cost deltas;
- actual versus estimated/reconciled spend;
- cache effectiveness by model/tier;
- cost per successful task or evaluation gate; and
- safe budget caps based on the effective provider/model/tier's current rate card.

## Phase 0 delivery

1. Extend Protobuf/JSON Schema and Python/Rust validators while preserving v1 compatibility through an optional `execution` object.
2. Add provider-adapter extraction for the reference runtime and the first supported providers; unsupported providers emit only known, truthful fields.
3. Add typed SDK builders and OpenTelemetry mapping for normalized requested/effective model and usage categories.
4. Add ClickHouse projection fields and immutable cost-ledger linkage with evidence source/confidence.
5. Test fallback, partial provider receipts, absent reasoning effort, retry, cache tokens, malformed units, price-card change, and redaction paths.

## Acceptance criteria

- A model fallback is visible as a requested/effective difference on the exact run.
- A provider does not support reasoning effort or a token category: Apex shows it as unavailable, never zero or actual by assumption.
- Cost Lens can filter and aggregate by effective model, effective effort, provider, evidence source, and confidence without reading content.
- Any provider receipt or SDK adapter change is traceable to its adapter/version and cannot alter historic accounting.
