# Owned sealed-stage bootstrap (Task 4G)

`startSealedStageBootstrap({env, onFatal})` is a dormant composition primitive.
It validates and copies the fixed agent ENV selection before I/O, owns the real
fixed-path `/apex/runtime` stage reader, then runs the actual ENV/document join.
There are no public path, filesystem, loader, parsed-stage or factory overrides.
The private loader/clock/gate seam exists only for deterministic tests.

The original monotonic five-second budget spans ENV selection, loading, document
interpretation and the final publication check. The reader receives a clock
guard against that same original entry deadline. The owner timer can cancel work;
it cannot manufacture physical closure or release capacity. Errors are static
`managed stage bootstrap rejected` values without underlying causes or secrets.

## Lifetime contract

The returned handle has `result`, `closed` and idempotent `cancel()`. Successful
`result` yields a frozen, WeakMap-authenticated owner with only immutable
`documents`. This metadata is consistency-checked, not proof of enrollment,
PKIX validity, provenance, launch authority or permission to serve.

Reader `closed` means actual outstanding OS work and handles have closed. It does
**not** end the consumer's material lifetime. Bootstrap `closed` requires both
actual reader closure and cleanup: either failure/cancellation cleanup (including
any late result), or explicit disposal of successfully published material. One
process bootstrap slot stays occupied until both conditions hold. Success without
disposal intentionally blocks another bootstrap, even after five seconds.

Cancel before dispatch prevents I/O. Cancel during loading rejects the result,
requests reader cancellation and contains late material. Cancel after success
revokes copying and wipes the originals; it cannot retract an already resolved
promise or wipe copies already transferred to consumers. Explicit
`disposeStageOwner(owner)` is idempotent for a genuine owner. Metadata remains
readable and immutable afterward. Unknown owners, copied objects and proxies are
not capabilities and are rejected without invoking their getters/traps.

Uncertain reader close retains capacity and the reader's trusted fatal-supervision
contract. `onFatal` must terminate the owning process, not merely log and continue.
Thrown fatal callbacks are contained, never interpreted as physical termination.
There is no timeout-based release, retry/replay, registration or Serving transition.

## Secret copies

`copyStageRole(owner, role)` accepts exactly `health-token`, `governance-ca`,
`governance-cert`, `governance-key`, `governance-token`, `evidence-ca`,
`evidence-cert`, `evidence-key`, `evidence-token`, `inbound-jwks`, `workload-ca`,
`workload-cert`, `workload-key`, and `instance-proof`. Caps are the existing
reader's: health token 43 bytes, instance proof 32 bytes, other roles 65,536 bytes.

`copyStageTool(owner, publishedReference)` selects only references in the joined
tool-binding entries, capped at 65,536 bytes. Neither helper accepts filenames,
paths, arbitrary references, coercible objects or disposed owners. Both return
fresh `Buffer` copies and use captured native views, not source copy/conversion
hooks. The caller owns each copy and must wipe it when its own physical consumer
has finished. Do not dispose the stage before required consumers have taken their
copies; do not confuse copied bytes with purpose validation or authentication.

Disposal wipes the reader's original tracked allocations, including metadata and
unused material, and revokes further access. It cannot erase immutable JS strings,
GC/native/runtime intermediates, TLS/OpenSSL copies, kernel buffers, snapshots,
crash dumps or consumer copies. This is bounded ownership, not whole-process
zeroization. Metadata intentionally survives disposal.

## Verification boundary

New focused tests use the real ENV/document parsers, an honest deferred loader,
and the real reader with a deterministic fake OS. They directly inspect allocation
wiping, held-open/failed-close retention, reentry, correlation, passive byte copying
and exact original-deadline edges. Fake OS outcomes are not native-kernel evidence.
The task-specific scratch Linux recipe additionally runs the public production
entry as UID/GID 10001 against actual read-only stage mounts, with no network and
a read-only container root. It checks success/rebootstrap, copy revocation,
stable FD count, invalid join, manifest mismatch, writable mount refusal and
pre-dispatch cancellation. It does not inspect inaccessible native allocations.

This dependency remains unintegrated pending review. No startup/factory, upstream
credential parser, listener, registration, signed-image or production-readiness
claim is added by Task 4G.
