# Reconcile: Scale-First Architecture / Archive Provider Contract (vault docs)

This change cannot edit the Obsidian vault -- `Scale-First Architecture` and
`Archive Provider Contract` live outside this git repository. This note is
the handoff: what to change in those two vault documents, and why, so the
orchestrator (or the user) can apply it directly.

## The situation

The Phase 0.6 plan already flags that both vault docs describe the
compliance archive in a **batch-and-manifest** form: multiple events grouped
into one `ArchiveBatch`, written as one object with an accompanying
`manifest` (schema version, scope, event count, byte count, per-event
hashes), and acknowledged with one `ArchiveReceipt` per batch. The live pen
test (2026-08-11, referenced in the user's own notes as pentest #8)
superseded that design: the compliance archive now writes **one
Object-Lock-retained object per event**, not a batch-with-manifest.

This repository's own `contracts/archive-provider/v1.md` still carries the
pre-pentest batch-and-manifest vocabulary verbatim -- `ArchiveBatch`,
`batch_id`, `idempotency_key` "derived from the batch content hash",
`manifest` containing "event count, byte count, and event hashes", request
bounds of "at most 1,024 events" per batch. That file is evidence of exactly
the same stale description the plan flags in the vault docs; it was not in
scope to edit here (this change is additive deploy/config + docs only, and
`contracts/` is a frozen-contract surface, not something to alter as a side
effect of standing up an unrelated tier). Flag it alongside the vault docs if
whoever reconciles those also owns this file.

## What to change in the vault docs

In both `Scale-First Architecture` and `Archive Provider Contract`, wherever
you find language describing the archive as:

- grouping multiple events into one write ("batch", "manifest", "batch_id",
  "up to N events per object"),
- an idempotency key "derived from the batch content hash" rather than the
  per-event hash,
- one receipt/acknowledgment covering many events at once,
- retention or Object-Lock applied "per batch" or "per manifest" rather than
  per object per event,

that language **no longer describes the compliance archive**. Two possible
corrections, and you should pick per-passage which applies:

1. **It should be corrected to reflect the archive's real current
   behavior**: one Object-Lock-retained MinIO/S3/Azure/GCS object per event,
   keyed by event ID and event hash, acknowledged individually by
   `archive-provider` before the ingest gateway's outbox marks that event's
   fanout complete. See `deploy/compose/compose.yaml`'s `archive-store-init`
   (`mc mb --with-lock`) and `APEX_ARCHIVE_REQUIRE_OBJECT_LOCK` for the
   concrete, currently-true shape.

2. **It should be re-pointed at this new cold-storage tier**, if the
   original intent of the batch-and-manifest passage was actually describing
   a cheap, high-throughput, multi-event-per-object analytical write path --
   because that is precisely what this change built. Batching many events
   into one compressed object, keyed by a derived partition rather than a
   single event ID, with no per-event retention guarantee, is now accurate
   of `deploy/compose/compose.coldstore.yaml` (Vector -> gzip NDJSON ->
   `apex-coldstore`), not of the archive. Concretely:
   - "events grouped into one written object" -> the coldstore tier's
     `batch.max_bytes`/`batch.timeout_secs`-driven Vector sink batches,
     documented in `deploy/compose/templates/vector-coldstore.toml.template`.
   - "manifest with event count/byte count/hashes accompanying the batch" ->
     has no direct coldstore equivalent yet (Vector's `aws_s3` sink does not
     emit a manifest sidecar); if the vault doc's manifest description is
     load-bearing for some other system that reads it, that is a real gap in
     this deliverable, not a doc-only fix -- flag it back to the Phase 0.6
     backlog rather than inventing a manifest format here.
   - "idempotency key derived from batch content" -> the coldstore tier has
     no idempotency contract at all (see `deploy/compose/coldstore/README.md`
     "What this is, and what it is not" -- it is a mutable, best-effort
     analytical projection, not a durable/idempotent sink). Do not describe
     it as idempotent in the vault doc; say plainly that duplicate delivery
     on Vector restart is possible and acceptable for this tier.

## What should stay describing the archive, unchanged

Anything about the archive's authentication, per-request size bounds,
`ARCHIVE_*` error taxonomy, or provider adapter contract (S3/Azure/GCS
backends in `apps/reference-providers/.../backends/`) is unrelated to the
batch-vs-per-event question and should not move. Only the batching/manifest
/idempotency-key language is what this reconciliation is about.

## One line for whoever edits the vault

> Replace "the archive writes events in batches with an accompanying
> manifest" with "the archive writes one Object-Lock-retained object per
> event; batching multiple events into one manifest-accompanied object is
> what the separate cold-storage tier (Vector -> MinIO `apex-coldstore`,
> `deploy/compose/compose.coldstore.yaml`) now does, and that tier carries no
> retention or idempotency guarantee."
