# Durable pre-effect network reservations

Opted-in fresh instances now reserve an address slot before immutable staging or
container effects. The production path still returns
`RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE`: reservation is not a running network,
signature verification, readiness or permission to serve. Existing dormant mode
is unchanged. A previously staged/created v1 instance cannot be reinterpreted.

## Binding and ownership

The current authenticated operation and unchanged protected metadata are checked
before reservation. Selected schema3 ingress metadata must match installation,
scope, launch profile reference/version, and the catalog's exact network selector.
Governance/evidence origin host/port must match their respective protected grants.
Published upstream narrowing and actual engine topology inspection are later gates.

The existing exclusive installation journal lock excludes other agent processes.
One additional mutex serializes allocation across its eight physical workers.
The fixed `network-reservations.json` contains schema, installation, topology hash,
capacity and at most128 unique instance/owner/slot entries. Topology hash covers
protected pools, capacity, exact outer fabric ID, gateway and edge address. Owner
hash binds original operation/target/configuration and immutable launch/profile/
tool/publication data; it intentionally excludes the later network attachment.
The topology hash is not a digest of guard endpoint grants. Future guard staging
must separately bind the exact selected policy contents to immutable inspected
guard configuration; address reuse does not authorize policy replacement.

The lowest free slot is chosen once. Exact retries reuse it. Conflicting ownership,
changed layout/capacity, exhausted capacity or invalid journals never evict an
existing entry. Per-proxy records omit `network` for legacy checksum compatibility;
new records attach schema, slot, topology hash, owner hash and binding hash.
Record recovery revalidates this binding and refuses staged/engine identities in
the current reservation-only implementation.

## Durability and uncertainty

The bounded65,536-byte global journal requires root-owned regular0600 files with
one link. Original strict duplicate-preserving JSON and a checksum are both checked.
No parser or I/O error is converted into an empty catalog. A complete new version
is written to an exclusively created fixed `.next`, file-fsynced, renamed, and the
directory fsynced before acknowledgement. The process retains ownership through
the entire synchronous operation.

Read/write uncertainty poisons this process's allocator. An incomplete `.next`
quarantines recovery; it is not deleted or overwritten automatically. Missing
state after this process previously loaded it cannot silently initialize anew.
A rename followed by failed directory-fsync acknowledgement is uncertain, not
success; restart inspects the actual durable state. Crash after global commit but
before per-proxy attachment retains the slot for the same exact retry.

Before any legacy provisioning fallback, the owner consults this validated global
history under the same allocator mutex, even when the network opt-in is disabled.
A matching unattached reservation still fences the instance; an attached binding
must agree with its global entry. Corrupt, incomplete, previously observed missing
or poisoned history refuses fallback. The lookup neither creates a journal nor
changes any entry. A genuinely unreserved instance may retain its legacy path
when the protected history is valid (or has never been observed in this process).

There is deliberately no time-based expiration, eviction or release API yet.
Actual owned network/container cleanup and positive absence evidence are required
before release can be implemented. Pause/retire of a reservation-only Intent is
not claimed terminal; its history remains held. Do not remove journals or `.next`
files to force reuse. Missing global state on a fresh process never proves engine
absence: future effects must independently inspect all overlapping allocations
and quarantine unknown resources before any network creation.

## Verification scope

Linux tests exercise real filesystem writes/fsync/reopen, concurrent allocation,
capacity, original-owner conflicts, strict shapes/checksums, filesystem protection,
and deterministic failure after temp-file fsync or after rename. Failure injection
is test-only; it is not an actual machine-power-loss test.

A separately compiled production-agent test uses real mTLS callback ingress,
protected files, existing Docker read-only preflight and exact-name container
absence. It proves retries and higher-fence restart preserve one reservation with
no staged files or created container. A fixture health source is deliberately
absent: the path still reaches the reservation boundary without staging it. No
Cosign fixture is started; its catalog identity is test selection data only.

Real kernel topology, guard execution, signed Apex artifacts, stage-v2 handoff,
reservation release, HTTPS/root readiness, routing, lifecycle and full tracing
acceptance remain open.
