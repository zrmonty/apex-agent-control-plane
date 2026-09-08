# Managed paired process start

Task4Z extends a genuinely verified stopped gateway/guard pair to guard-first
process start. Running does not establish HTTPS, a session, registration, readiness,
route selection, or admission. The actual managed TypeScript factory still refuses
uncomposed live enforcement. Production keyless signature verification is unchanged.

## Durable start and recovery

The stopped pair remains `Verified`; original image/container IDs, stage/proof
identities, topology and ownership hashes never change when a new command or fence
arrives. An optional, strict start observation advances through `GuardIntent`,
`GuardObserved`, `GatewayIntent`, and `Running`. Legacy omission preserves bytes.
Intent is saved before each fixed `container start <original-full-id>` effect.
The guard must independently inspect as running before gateway dispatch.

Every production start/recovery check invokes actual protected keyless image
verification, current metadata/publication/operation and authority checks, and
revalidates exact sealed bytes, source/file identities and mounts. Shutdown,
cancellation and original monotonic job/lease deadlines remain physical-dispatch
gates. Journal hashes and saved process observations are not execution permits.

An intent without a receipt may adopt only an exact independently running effect.
An absent, still-created, exited, dead, restarting or substituted process is
quarantined without repair, recreation, reconnection or automatic restart. Only
the same physical invocation with positive knowledge of no dispatch can roll back
its intent. Paired pause/retire cleanup remains unsupported and refuses; it does
not fall back to the legacy one-container cleanup.

Recovery joins independent container and network inspections. Full IDs, endpoint
IDs, addresses/prefixes, MACs and names must agree; gateway has only its internal
network, guard only internal plus its protected outer network. Exact verified
members are projected out in memory before the unchanged empty-network/fabric
rules run. Unowned/extra/missing endpoints are not discarded. Running still means
`NotServing`; no readiness, route, registration or admission owner is added.

## Coordinated unsigned native fixtures

Use the controller's explicitly unsigned actual MCP component image
`sha256:37f8a7180f82b5bfc31c1b9c824358c1f077b30b742d1afbf3a9d9c32244152c`
as the base of a separately named, explicitly unsigned process fixture image.
No signed image or production verifier is bypassed. The fixture packages its own
test process entry files at build time; no replacement application-code bind mount.
The fixture reads all sealed files as configured UID/GID10001 before staying alive.
No contents, credentials, or proofs are printed or exported.

Only one native case at a time. Do not run any other Docker test/hash containers
concurrently, even network-none: removal between bounded inventory list and inspect
correctly fails closed. Each native case uses a new UUID and new resources:

- `apex-runtime-<uuid>` and `apex-guard-<uuid>`, original full IDs and pair labels.
- `apex-net-<uuid>` with the exact journal topology labels, internal pool
  `10.246.0.0/22` (one allocated `/29` per instance).
- `task4z-native-<uuid>` protected fixture outer network, `10.247.252.0/24`,
  gateway `.1`, reserved edge `.2`, guard address from the protected catalog.
- A uniquely owned fixture root beneath the controller-provided volume root;
  no existing fixture root, network, container, or stage is reused or mutated.
- The test runner's controller-approved read-only engine tools/socket and exact
  owned volume mount follow the existing native harness ownership constraints.

Before running, inspect the fixture image ID, confirm baseline subnet availability
and the controller's native window. Start only through typed production engine
operations. Cleanup checks exact container IDs, names, original pair binding and
image identities, issues bounded stop, independently confirms non-running state,
then removes those containers. Networks require exact ID/labels and empty endpoint
maps before removal. No prune, forced global cleanup, or legacy paired cleanup.
Retain the exact resource inventory and source hashes in the Task4Z report.

The no-network Rust test runner is a separate preapproved scope: ephemeral tmpfs,
read-only runtime/PKI fixtures, and no mounted host engine socket.

## Exact fixture and bounded ownership

The built unsigned process fixture is `apex-task4z-agent:unsigned-process2`,
image ID `sha256:ec822894f36568b02c894adef4cc387ea7b1968a90fe104a01a910a0ac1595ab`.
Its source is `apps/proxy-runtime-agent/tests/task4z_process_fixture.mjs` and its
build definition is `.superpowers/sdd/2026-09-05-runtime-execution-continuation/Task4Z-process-agent.Dockerfile`.
This image is packaged test code; it is not the actual managed factory acceptance.
Source and both packaged entrypaths have SHA256
`2efdfff6a0ac450d6896ebf531216b09ed12947db6017e01c06acf4297eaa672`.
After validating and reading all mounted files, the fixture sets a fixed key-free
process title. A bounded read-only `container top <id> -eo uid,gid,pid,args` confirms
UID/GID10001 and that title; it does not execute code inside the workload or assert
readiness. This replaces an invalid tmpfs `docker cp` evidence collector.

The native test and cleanup source is
`apps/proxy-runtime-agent/src/execution/guard_stage/tests/guard_staging/storage/gateway/containers/native/start.rs`.
Run only `task4z_native_start_` with `--include-ignored --test-threads=1`.
Use controller `run-task4z-native.ps1 -Image <exact-agent-id> -ProcessImage <exact-fixture-id>`.
Runner name: `apex-task4z-native-<fresh-invocation-uuid>`, label
`io.apex.task=task4z-native`, network `none`.
Follow the existing checked `apex-task3a-01a073bf-owned` volume mapping at
`/var/lib/docker/volumes/apex-task3a-01a073bf-owned/_data`, verify its original
installation/task labels and mountpoint before use, and create only the fresh
`task4z-<fresh-instance-uuid>` subdirectories. Retain these journals/stages.
Use the established engine socket mapping `/var/run/docker.sock` to
`/run/apex-docker.sock` only inside this explicitly approved native runner.

Every call to the native fixture generates a fresh UUIDv7, including independent
controller reruns. It prints the case and instance before creating resources.
No old root is removed or reused. Addresses remain deterministic within each
new isolated case; cases run serially and remove only their owned Docker resources.

| Case | Native case |
| --- | --- |
| 1 | Running, journal reopen, mounted readability |
| 2 | Unknown guard intent |
| 3 | Unknown gateway intent |
| 4 | Completed guard effect, missing receipt |
| 5 | Completed gateway effect, missing receipt |
| 6 | Guard no-dispatch rollback |
| 7 | Gateway no-dispatch rollback |
| 8 | Exited guard quarantine |
| 9 | Extra gateway attachment to this fixture's own outer network, refusal without repair |
| 10 | Remove only the independently stopped original gateway, refusal without recreation |

For each fresh instance, exact names are `apex-runtime-<instance>`,
`apex-guard-<instance>`, `apex-net-<instance>`, `task4z-native-<instance>`.
The outer label is `io.apex.task4z.owner=task4z-native-<instance>`.
Internal networks retain their generated immutable topology labels; both containers
retain installation `018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01`, role, peer-name,
pair-binding, and topology labels. IDs and hashes are captured after independent
inspection and never inferred from create/start stdout.

Every fixture Docker command is bounded to ten seconds by the existing command
owner. Cleanup verifies full IDs, names, images, pair and installation labels;
uses `container stop --time=2 <full-id>`; independently reinspects ID, non-running
state, PID zero and `created`/`exited`; then uses non-forced `container rm <full-id>`.
Network removal requires exact ID/label and an empty member map. Failure leaves
unverified resources untouched for controller quarantine. No volume removal.

The report beside `task-4z-brief.md` records exact tested agent image/source hashes,
actual native iterations (including failures), retained instance roots, cleanup
inventory and outstanding independent regression. Native process behavior and
mounted readability use unsigned fixtures; neither is signed production approval
or proof of the actual managed HTTPS/session factory, which continues refusing.
