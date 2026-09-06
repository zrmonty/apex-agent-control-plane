# Guard-only sealed stage

`startGuardStageLoad` reads exactly `/apex/runtime/guard-config.json` in the
guard's separate Linux container. Do not mount the gateway stage into the guard.
The producer must emit a key-free guard configuration; this byte loader does
not parse its meaning or certify provenance, network ownership, or readiness.

Inputs are an expected lowercase SHA256 manifest, a trusted supervisor fatal
callback, and an optional monotonic clock. No path, inventory, filesystem, tool
secret references, gateway bootstrap environment, or fallback is accepted.
The manifest is SHA256 of JSON containing the one filename and its byte SHA256.
It is an integrity check, not authorization to start a relay.

The fixed stage directory must be UID/GID10001 and mode0500. Its single regular
file must be UID/GID10001, mode0400, one link, and 1..262144 bytes. The actual
mount must be read-only, without nested mounts. Parent directories are protected
root-owned directories. The shared held-FD reader rechecks identity, metadata,
complete reads and mount state; unknown files or gateway secrets cause refusal.

The original five-second work deadline includes capture, queueing, I/O, and
physical close. Cancellation reports refusal but does not release the process
slot while I/O or close remains outstanding. Uncertain cleanup retains ownership
and invokes the supervisor after the five-second cleanup grace; it never invents
closure. The guard and gateway loaders share a process-level reservation, though
production deployment uses separate processes and separate stage mounts.

On success the caller owns the returned opaque buffers and must dispose them.
The load's `closed` acknowledges actual file/directory I/O cleanup, not buffer
disposal or relay shutdown. Copying bytes transfers cleanup responsibility for
those copies to their consumer. Parsing the strict guard schema, binding it to
the published topology, starting relays, and supervising their lifetime remain
separate integration requirements. No `Serving` transition is enabled here.
