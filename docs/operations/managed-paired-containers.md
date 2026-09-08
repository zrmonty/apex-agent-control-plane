# Verified stopped MCP container pairs

This guide describes the historical Task4Y boundary: typed Docker creation and
recovery of protected guard and gateway stages as a **never-started pair**, not a
usable deployment. The integrated [Task4Z start/recovery owner](managed-paired-start.md)
now follows verified pair creation with guarded guard-first and gateway-second
start and running recovery, subject to current authority, signatures and sealed-stage
revalidation. The production reconcile branch still returns NotServing with
`RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE`. That refusal is **not proof that no
process started**; start is not registration, readiness, route publication,
admission or Serving. Pause/retire remain
`RUNTIME_NETWORK_CLEANUP_PENDING` for paired resources. No paired cleanup or
automatic repair is provided by this boundary.

## Durable ownership

An optional `installed.paired_containers` object holds the independently inspected
gateway/guard image IDs, exact inherited environment key inventories, observed
container IDs, a binding hash, and the following strict string phase:

| Phase | Proven state / allowed next action |
| --- | --- |
| `Prepared` | Both stages sealed and image identities pinned; gateway create may be issued. |
| `GatewayIntent` | Gateway create may have been dispatched; only exact completed inspection may advance. |
| `GatewayObserved` | Original gateway ID recorded; guard create may be issued. |
| `GuardIntent` | Guard create may have been dispatched; only exact completed inspection may advance. |
| `GuardObserved` | Both original IDs recorded; the guard's outer connection may be issued. |
| `ConnectIntent` | Outer connect may have been dispatched; only exact completed configuration may advance. |
| `Verified` | Both original containers independently inspected as never-started with the complete expected configuration. |

These phases describe Task4Y's creation boundary. Task4Z preserves the immutable
pair ownership and `Verified` phase while adding separate start observations;
`Verified` alone is not evidence that the current processes are still stopped.

Every create/connect intent is persisted before dispatch. Only the same physical
owner, still holding the installation effect lock and knowing spawn was never
attempted, can roll back its intent. Once spawn is attempted, failures remain
ambiguous. Missing containers, missing connections, failed inspection, unexpected
resources and substitutions never authorize recreation, reconnect, deletion,
proof regeneration or stage repair. Creation stdout is discarded as an identity
source. A successful inspection supplies each original full container ID.

The binding covers original installation ownership, both sealed stages, network
topology and IDs, mount profile, and both image/environment identities. Current
command or fence changes preserve original ownership and stage hashes. Legacy
records omit the new field entirely and retain their existing representation and
checksums. Null, positional arrays, duplicate/unknown fields, invalid phase
representations and inconsistent phase/ID combinations refuse recovery.

## Physical configuration

The gateway is `apex-runtime-<original instance>` on its reserved internal network
at `/29` offset 2. Its paired `apex-guard-<original instance>` is on the same
internal network at offset 3 and the original protected outer network at its
reserved slot address. The guard alone receives the outer attachment. Both have
IPv4 forwarding disabled and IPv6 disabled/forwarding disabled. Gateway DNS is
restricted to loopback; only the guard uses the daemon's DNS service. Search and
resolver options are explicit and independently inspected.

Each runs as 10001:10001 with a read-only root, all capabilities dropped,
no-new-privileges, private namespaces, 256 MiB memory/swap limit, one CPU, 128 PIDs,
and bounded noexec/nosuid/nodev tmpfs. Entrypoint is `/usr/local/bin/node`; the
gateway command is `/app/apps/mcp-gateway/dist/index.js`, the guard command is
`/app/apps/mcp-gateway/dist/managed/guard/main.js`. Healthchecks, restart and
logging are disabled. Unexpected environment, volumes, devices, ports, executable
arguments and namespace sharing refuse inspection. The bounded command argument
limit is 96 to accommodate the fixed paired profile plus at most 16 independently
inspected inherited keys; argument length and output/time bounds are unchanged.

The gateway emits the consumer's exact `sealed-stage-v2` environment: its original
ten fields plus `APEX_MCP_NETWORK_PROFILE=isolated-bridge-v1`, the original internal
guard address, and `APEX_MCP_NETWORK_BINDING_SHA256`. The guard receives only its
nine-field guard environment and its one-file, key-free stage. Each stage is a
separate nonrecursive read-only bind at `/apex/runtime` inside its respective
container. No credential/proof bytes appear in argv, Docker environment, labels,
journal or responses. The gateway's secret material is never mounted into guard.

## Docker stopped semantics and recovery

Docker 29.6.2 represents these never-started attachments in
`NetworkSettings.Networks` with fixed `IPAMConfig.IPv4Address`; NetworkID,
EndpointID, active IPs, sandbox IDs and network-inspect `Containers` stay empty.
An outer `network connect` on a stopped guard adds its configured membership and
its exact derived DNS names, without starting it. Empty active endpoint maps
alone therefore prove nothing about configured membership.

At the historical Task4Y boundary, recovery joins a bounded all-container inventory with protected journal/topology
history and exact original network-ID inspections. Every known paired resource
must match its phase, image, ownership labels, executable, environment, stage
mount, configuration and never-started state. Foreign stopped configurations on
reserved networks/outer addresses, extra/missing attachments, replaced IDs and
unexpected active endpoints refuse. Existing unrelated outer-network members
remain subject to the original protected-fabric rules. This is a point-in-time
stopped configuration check, not proof of running packet isolation or readiness;
Task4Z's guarded start/recovery owner revalidates before acting. Its independently
verified running-network recovery is described in the linked Task4Z guide;
actual readiness/admission composition remains a later boundary.

Production checks actual selected keyless signatures on creation and recovery.
Historical digest/signer metadata is never a permit. Current operation, policy,
metadata identity, cancellation, shutdown and the original monotonic job/lease
budget surround effects; final guarded dispatch rechecks authority and sealed
files. Gateway source/file/mount identities and bytes are revalidated without
rewriting them. The worker retains physical command/process cleanup ownership.
Non-Linux platforms refuse effects.

The shared authority checkpoint rechecks shutdown after its blocking RPC and
before returning authorization. Shutdown does not depend on the waiting request
having dropped and set cancellation. `task4y_held_final_rpc` reproduces this
schedule over real loopback mTLS while retaining the actual facility waiter;
the shared paired pull/create/connect command gate must refuse physical dispatch.
Its clean non-shutdown control launches only a harmless local child. These
confined tests do not contact Docker or grant signature/deployment evidence.

The installation journal explicitly unlocks its Linux advisory lock when its
owner is dropped. CLOEXEC alone cannot prevent a concurrent pre-exec child from
temporarily retaining the same open-file description and delaying close-only
release. Physical workers retain the journal through cleanup; a live owner still
excludes independent opens. The real-kernel lifetime regression also checks that
closing an old retained duplicate cannot unlock a successor owner. Held-RPC tests
collect failures before release and assert only after bounded RPC/worker drain;
their fatal drain watchdog is test-only and never detaches a physical owner.

## Verification boundary

`task4y` selects confined journal, environment and topology regressions.
`task4y_native_pair_ --include-ignored --nocapture --test-threads=1` selects
controller-owned native tests using an explicit inspected unsigned component
image via `APEX_TASK4Y_COMPONENT_IMAGE_ID`, the checked `APEX_TASK3A_ROOT` volume,
and the existing protected Docker executable/socket fixture. They exercise actual
typed Docker create/connect/inspect, restart recovery, intent uncertainty,
no-dispatch rollback, cancellation/deadline refusal, and hostile observation or
membership changes. Native cleanup checks exact names/labels/IDs and created
status before removing only its new fixture resources; journals/stages remain as
evidence. Test authority callbacks and unsigned component data do not prove a
positive signed production deployment. No release signing or publication is
performed.
