# Runtime reconciliation ingress and dormant provisioning

The Linux `apex-proxy-runtime-agent` binary now exposes the authenticated
`RuntimeExecutionService.ReconcileRuntime` endpoint. Without `execution`, it refuses with
gRPC `Unavailable` and static `RUNTIME_NOT_SERVING_EFFECT_OWNER_UNAVAILABLE`
after successful authentication, online deployment resolution and preparation.
With protected `execution` configured it owns signature verification, durable
identity, complete staging and actual Docker create/inspect/recovery. Containers
remain never-started, network-isolated and NotServing: Task4 owns network,
readiness and admission. This is not an operational managed gateway.

Build from the workspace with `cargo build --locked -p apex-proxy-runtime-agent`.
The only entry point is:

```sh
apex-proxy-runtime-agent --config-dir /etc/apex/runtime-agent
```

No alternate environment or RPC path selection exists. Unknown/repeated flags,
positional arguments, relative paths, and non-Linux production hosts refuse.

## Protected deployment files

The final directory must have mode `0700`. Every ancestor must be a real
directory owned by root or the agent's effective UID, with no group/other writers.
Every fixed file must be a regular file owned by root or that UID, mode `0400`
or `0600`, with exactly one hard link. Symlinks and replaced ancestor/root
identities refuse. Reads use descriptor-relative `openat`, `NOFOLLOW`, nonblocking
opens before type checks, before/after metadata checks, and original-byte bounds.
An untrusted/writable `/tmp` ancestor is deliberately unsuitable.

`agent.json` is an object with exactly these required fields; no secret values:

```json
{
  "schema_version": 1,
  "listen": "127.0.0.1:9443",
  "installation_id": "0191b7f1-7f2c-7c13-9a61-2f29f2be1001",
  "agent_identity_id": "runtime-agent-a",
  "enrollment_version": "enrollment-1",
  "host_policy_version": "host-1",
  "authority_endpoint": "https://control-plane-api:9444",
  "authority_tls_server_name": "control-plane-api"
}
```

The fixed files are `agent.json`, `peer-policy.json`, `launch-catalog.json`,
`server-ca.pem`, `server-cert.pem`, `server-key.pem`, `authority-ca.pem`,
`authority-client-cert.pem`, and `authority-client-key.pem`. Launch catalog is
limited to 262144 bytes; every other file to 65536 bytes. Empty files refuse.
The existing strict RuntimePeerPolicy and LaunchCatalog schemas apply; unknown,
duplicate and positional metadata fields refuse. All original file buffers are
zeroized on drop. Transport libraries and the existing authority client own
credential copies after transfer; this is not a claim that every allocator or
third-party PEM copy is zeroized.

The listener requires client certificates chaining to `server-ca.pem`, and the
current policy must register the actual controller leaf and exact installation,
workspace and namespace. Forwarded certificate metadata is not authentication.
The agent separately presents its own authority identity and verifies the
configured authority hostname with explicit roots. No system roots or RPC
transport override is introduced.

## Refresh and shutdown

One retained blocking thread rereads protected files every 250 ms after the
previous physical read completes. Its 2-second freshness limit starts at read
initiation, using a monotonic clock. A stalled reader is not replaced. Admission
expires while it remains held. Invalid or expired metadata immediately poisons
the published snapshot when observed; no last-valid serving fallback exists.
Revoked peers are denied by current authorization. Changed valid metadata can
recover admission to the no-effects refusal; transport/configuration changes
require process restart. Catalog validity is independently checked against the
agent's local clock, in addition to Task 1's authority-time preparation check.

Initial deployment delivery is not treated as metadata publication. After the
authority connection completes, startup awaits the reader's explicit first-result
publication latch before checking freshness or binding a listener. This wait stays
inside the same five-second startup deadline and shutdown select; no polling or
sleep retries are used. Cancellation leaves the physical reader owned until join.

Requests are capped at4096 bytes, responses at16384. No-effects operation budget
remains five seconds. Execution has eight fixed owned physical workers, immediate
overload/per-proxy-busy refusal, and a **120-second whole-job and RPC ceiling**.
Each authority check/resolve is at most5s; each Cosign/Docker child is at most30s,
also bounded by remaining job/current checked lease interval. Callbacks never
reset the whole-job clock. Original Request/TLS moves with the job. Cancellation
signals but does not release its slot/guard/ownership until physical work/reaping
ends. SIGINT/SIGTERM stop acceptance and join workers plus reader. Kernel IO may
outlast response deadlines; no replacement worker is spawned, and shutdown waits.

## Task3B handoff and evidence limits

The new response envelope separates current `claims` from optional installed
`runtime` evidence. The installed runtime and nested readiness keep their original
launch target/fence. Never rewrite these to the current operation fence or newer
pause generation. Missing runtime is never readiness or proof of completed cleanup.
Pending, Reconciling, Failed and NotServing are eligible nonterminal observations,
matching the Postgres current-operation check. Failed/NotServing retries still
require current online authority and all policy/freshness checks. Ready, Paused,
Retired, default and unknown observations refuse. Paused/Retired desired intent
never prepares a new launch.

Configured Serving success returns current claims, `NotServing`, original
installed target/fence/container ID, false ready/admitting, and static
`RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE`. It is not terminal deploy success.
The durable operation/generation selects the instance: new commands and higher
fences never rewrite the launch or select another container for that operation.
Paused/Retired use existing current `authority.check`, not new launch resolution.
Paused proves owned never-started state. Retired requires positive exact engine
absence and journaled exact stage cleanup of all retained owned entries. Empty
history, running/mismatched/corrupt/uncertain resources refuse/quarantine.

Static gRPC errors are refusal/uncertainty, not proof that no effect occurred.
The still-owning physical job may durably restore `Staged` after a failed fresh
authority/deadline check between saving `CreateIntent` and calling Docker create:
that local record proves no create was dispatched and authorizes no effect by
itself. Retry still requires current authority, signature and exact material
verification. A crash before that save, or any error after invoking create, keeps
the ambiguous intent; observing no container is not permission to recreate it.
A superseding Pause/Retire may consume a proven `Staged` no-create record only
after a successful exact-name absence query. Pause preserves the sealed files
and returns no fabricated container observation. Retire journals stage-removal
intent and verifies the exact remaining file manifest before cleanup. Unexpected
containers or unknown/mismatched files quarantine; cleanup never creates first.
After timeout retry the same operation with current authority; ResourceExhausted
(`RUNTIME_PROXY_BUSY`/`RUNTIME_OVERLOADED`) can persist until physical exit.
Task3B must decode16384 bytes and align transport/lease renewal with120s while
preserving current versus installed fences. No public effect executor exists.

Tests cover real mTLS and a separately compiled agent process against a TLS callback
fixture with synthetic authority timestamps, actual Cosign, confined staging and
Docker create/inspect/restart/two-proxy cleanup. They do not establish joint real
control-plane/PostgreSQL acceptance (Task3B), an approved Apex image, or operational
network/readiness/admission (Task4).

## Optional execution and material metadata

The strict optional `execution` object has exactly these absolute-path keys:
`journal_root`, `staging_root`, `material_root`, `docker_executable`, `docker_socket`,
`docker_config_root`, `cosign_executable`, `cosign_cache_root`. Null, arrays,
unknown/duplicate keys, invalid paths and overlapping roots refuse startup.
Configured-invalid never falls back. No caller engine flags or capacity/timeouts.
Executable descriptors are protected; the explicit Unix socket identity is
rechecked; Docker config remains empty0700. No inherited context/helper/env.
The journal has exclusive process ownership, bounded checksummed per-proxy records,
atomic replacement and file/parent fsync; uncertain intent stays durable.

Replay retention is bounded without forgetting old command bindings: each proxy
retains 64 exact command-to-operation entries plus an optional durable UUIDv7
eviction floor. Every canonical command ID at/below the floor permanently refuses
with `RUNTIME_COMMAND_REPLAY_EXPIRED`, even under otherwise current authority.
Retained IDs cannot be rebound to another operation. When full, a new ID at/below
the oldest retained ID also refuses rather than evicting the current binding.
Fresh IDs above the floor permit retries and current pause/retire indefinitely;
new command/fence does not mean a new instance. The floor is a replay tombstone,
not wall-clock validity, authority, or permission to reuse an old ID.

Task3B must durably allocate strictly increasing canonical UUIDv7 command IDs per
proxy across replicas, clock skew and restart (independent `now_v7()` calls across
machines do not establish this property). Use a fresh allocator ID on expired
replay, preserving the operation and current online proof; do not reuse an evicted
ID with a different operation. Legacy schema1 records omit the floor and retain
their original serialized checksum; the first eviction writes the floor. This
preserves the existing cross-operation per-proxy conflict invariant, not a new
installation-wide cross-proxy command-history index.

Docker effects carry the absolute monotonic minimum of original admission+120s
and the most recent checked lease expiry through argument construction and
synchronous protected socket/config preflight into the child runner. Child work
is additionally capped at30s; the runner checks immediately before spawn. Slow
preflight cannot mint a fresh duration. Expiry refuses without spawning, while
the physical worker retains its Request/slot/proxy ownership until it exits.
Each subsequent effect still requires a fresh <=5s authority callback; callbacks
can refresh the lease, never the original whole-job120s deadline.

Execution additionally requires `image-catalog.json` (65536 bytes),
`authority-profiles.json` and `tool-bindings.json` (262144 bytes each), refreshed
by the same poisoning/freshness owner. The latter two use strict schema1/version,
half-open SQL validity and1..32 exact scoped selectors. Authority profiles contain
governance/evidence HTTPS origins and TLS names. Tool bindings exactly match
published secret refs (maximum32), with unique refs/source names disjoint from
the13 deployment roles; each extra secret<=65536 bytes, total<=2097152.

One sealed stage contains config/launch, the13 fixed role files,
`authority-profile.json`, `tool-bindings.json` and reference-hash-derived tool
filenames. Files0400 UID/GID10001, directory0500. Exact bytes/hashes, ownership,
types, links and mount IDs are checked on recovery. No broad source root is
mounted. Task4 must validate staged selectors against launch before using them;
staging is not an admission grant.

## Code-owned mount profiles and trusted host changes

Ordinary protected staging uses an exact read-only **nonrecursive rprivate** bind.
Startup uses bounded DockerRootDir discovery and component containment. A staging
root containing daemon root refuses. A descendant is allowed only under a local
Docker volume with exact inspected mountpoint, empty options and matching
`io.apex.runtime.installation-id` label. Only this restricted profile uses
read-only **nonrecursive rslave**. The choice is persisted and compared against
both independently inspected mount views; no create-error fallback/caller flags.

Moby requires slave/shared propagation for overlapping daemon-root sources to
avoid private references interfering with daemon mount cleanup:
[validateBindDaemonRoot](https://github.com/moby/moby/blob/master/daemon/volumes_linux.go).
Unlike rprivate, rslave can receive later host mount/unmount propagation without
propagating container changes back. NonRecursive excludes existing nested mounts;
exact sealed-stage enumeration/statx mount-ID checks reject nested file mounts.
Both inspected mount views must be read-only and NonRecursive=true. No writable
nested stage mount is accepted. Host root/daemon and later host mount changes
remain trusted: this is not protection from privileged host replacement after
inspection. Task4 must revalidate before any start. Actual acceptance covers the
installation-labeled daemon volume, not ordinary-root host execution or hostile
privileged mount injection; no extra privileges/host changes were used.
