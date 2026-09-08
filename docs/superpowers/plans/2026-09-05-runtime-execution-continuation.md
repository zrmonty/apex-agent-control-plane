# Runtime Execution Continuation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Execute the approved runtime sequence task by task; do not claim downstream gates from component tests.

**Goal:** Connect authenticated agent operations, publication-bound launch material, durable provisioning, enforced routing/lifecycle, and microsecond tracing.

**Architecture:** Keep PostgreSQL as desired-state/operation authority. The restricted agent authenticates actual Controller TLS, obtains current published configuration, binds protected deployment metadata, and owns bounded durable runtime effects. A running container is not readiness or admission.

**Tech Stack:** Existing Rust 2024 workspace, tonic/mTLS, PostgreSQL, Docker/OCI, TypeScript MCP gateway and integer-microsecond telemetry.

**Spec:** [Approved delivery design](../specs/2026-09-04-working-mcp-gateway-design.md), especially sections 4, 6, 8 and 9. This continuation decomposes the unfinished [runtime plan](2026-09-04-working-mcp-gateway-02-runtime.md); the user authorized the full sequence after CI passed on `179a770`.

## Current status — 2026-09-08

This continuation is a breakdown of work in the [22-task parent plan](2026-09-04-working-mcp-gateway.md),
not a replacement for it. Continuation Tasks 1–3 are complete for launch binding,
authenticated ingress and durable **stopped-container** provisioning. Task 4
(enforced routing/lifecycle) and Task 5 (microsecond tracing/integrated acceptance)
remain open: five and four aggregate acceptance checkboxes, respectively.
The parent plan still has 17 tasks not fully closed.

Task 4U's guard data producer is reviewed and committed in `71dc905`.
It supplies data only. Task 4W connects signature-gated protected guard
staging and exact recovery; scoped verification and independent review passed.
Task4W is committed in `cdbcd1f`, integrated in `d8cd2c7` with both CI workflows green.
Task4X adds protected paired gateway staging, committed in `4ca8cb1`; scoped and
final integration review passed. It is integrated in `003fd45`, whose CI34122122484
and Live mTLS + E2E34122122459 both completed successfully. Docker recovered on
2026-09-07; Task4Y paired stopped-container creation/inspection/recovery is
implemented and scoped-reviewed locally, not committed. A final-authority-RPC
shutdown race and a journal lock-lifetime defect were reproduced and fixed
test-first; both fix rounds passed re-review. Final independent verification passed
331 Linux tests/45 explicit ignores,170 Windows tests/5 explicit ignores, six
native paired tests and11 existing native network tests. This is never-started component evidence, not signed production
deployment or Serving acceptance.
Task4Z paired guard-first process start and running recovery is implemented and
scoped-reviewed locally, not committed. Independent native start7, stopped-pair6 and legacy
network11 checks passed, as did the full Linux suite, Windows170/5 explicit ignores,
strict Clippy and scoped formatting. Three subsequent module-header corrections
leave source bodies unchanged. Its unsigned native process fixtures do not
establish signed production startup. Combined integration and documentation-only
reviews passed with no open findings; changes remain uncommitted. The integrated branch can perform guarded paired start
before returning NotServing; refusal does not prove no process started. Next are
actual HTTPS/session composition, readiness, route selection, admission renewal
and safe lifecycle drain/cleanup, not reimplementation of paired creation/start/recovery. Trace
projection, scoped queries, UI and full release acceptance remain open.

Use the [integration checkpoint](../../operations/managed-runtime-checkpoint.md)
for the current resume order. Dated execution entries below retain historical
failures and intermediate next steps. Later checkpoints supersede those next
steps; they do not retroactively establish Serving or close parent tasks.

Subsequent local execution connects the actual managed executable to the fixed
sealed-stage application root, guarded live clients, HTTPS/session ownership and
nine-check PREPARE readiness. Scoped review and unsigned Linux public-root and
actual-index fixtures passed, including completion retention and first-stop-cause
shutdown handling. Packaged-image negative/development startup checks also pass;
they are not positive managed-image or signed deployment acceptance. Continue
Task4 at authenticated readiness observation and controller route/lifecycle
integration, then Task5. Aggregate acceptance checkboxes and parent counts remain
unchanged; details and evidence limits are in the integration checkpoint.

The separate fixed health observation executable is now packaged and scoped-
reviewed. Fresh source and compiled-image Linux health checks passed four cases
each, alongside gateway tests/typecheck/build. This is bound readiness metadata
from an unsigned component fixture, not agent-authenticated observation or route
permission. Continue agent collection and controller lifecycle integration; do not
repeat completed gateway composition or infer downstream acceptance from it.

## Global Constraints

- Work only in `E:/Agent Control Plane/.worktrees/working-mcp-gateway`; preserve unrelated UI formatting and the main checkout's concurrent work.
- Published revisions are immutable; mutations use lowercase UUIDv7 request IDs and optimistic concurrency.
- One logical proxy has at most one routable revision; a replacement candidate may coexist only during bounded validation and drain.
- Inbound credentials are never passed through to upstreams.
- Production never falls back to preview data, local governance, or in-memory proxy storage.
- Required evidence admission precedes success; downstream analytics and trace export do not become admission authorities.
- Every changed handwritten source/test file is at most 600 lines; generated artifacts are machine-owned and reviewed through reproducible generation.
- Timings preserve integer microseconds end to end; elapsed durations come from monotonic clocks.
- No raw credentials in argv, Docker environment, logs, RPC replies or revision storage. No arbitrary engine flags, host paths or caller manifests.
- Current-operation snapshots and compiled launch envelopes are data, not transferable execution permits. Recheck current operation/policy before effects and refuse stale generations.
- Production deployment and release signing remain unauthorized; use only scoped disposable acceptance fixtures. On 2026-09-06 the user explicitly authorized a verified commit, merge and push checkpoint, followed by resumed implementation. This does not relax any serving or release gate.

## Task 1: Bind the launch envelope and deployment material

**Files:** Create agent `src/launch.rs`, `src/launch/{catalog,validation,hash,tests}.rs` as responsibility requires; register `pub mod launch` in `src/lib.rs`. Add focused tests and a generated launch export consumed by the existing TypeScript launch parser. No runtime/proto changes in this task.

**Consumes:** `authority::ResolvedDeployment`, generated `RuntimeLaunchContext`, `RuntimeMaterialBinding`, `RuntimeMaterialRole`, and `secrets::ScopedMaterial`. The only public preparation input for configuration is `&ResolvedDeployment`.

**Produces:** `LaunchCatalog::parse(&[u8]) -> Result<LaunchCatalog, LaunchError>` and `LaunchCatalog::prepare(&ResolvedDeployment, &str) -> Result<PreparedLaunch, LaunchError>`. The string is an agent-selected canonical UUIDv7 process instance. `PreparedLaunch` has private fields and read-only getters for generated launch context, bounded config/launch JSON bytes, scoped material selection, image catalog ID and catalog version. It is not an execution permit.

The deployment-owned JSON document uses snake_case fields: `schema_version`, `version`, `valid_from_unix_us`, `expires_at_unix_us`, `profiles`. Original bytes are capped at 262144; schema is 1; versions are scope identifiers at most 128 bytes; times are positive signed-SQL-range integer microseconds with a nonempty half-open interval. Profile count is 1..32. Parsing must reject unknown/duplicate fields and invalid profiles, not defer independent invalid data until selection.

Each profile selects exactly `installation_id`, `workspace_id`, `namespace_id`, `proxy_id`, `revision_id`, `host_policy_version`, `deployment_bindings_version`, `config_hash`. It supplies `authority_profile_ref`, `authority_profile_version`, `image_catalog_id`, and `materials`. Each material supplies `role` (the generated named enum string), `reference`, `version`, `source_name`; scope is inherited from the exact profile, not caller input. No transport URLs, raw bytes or host paths occur in this catalog. Reject duplicate selectors and ambiguous material role/reference/source mappings.

The initial managed launch profile requires all 13 existing material roles, one each, with unique references and source basenames. This intentionally does not widen the pure gateway parser's subset support. Role references use strict `secret://` syntax and cannot overlap runtime configuration `secret_refs`; the health reference is distinct and health port is fixed at 8081. Profiles supply deployment credentials, not arbitrary tool credentials. Scope, installation, host-policy and deployment-bindings versions must exactly match the resolved authority/configuration. Production owner loading/refresh comes in Task 2.

Construct schema-1 launch bytes from the resolved target/config hashes/image and the selected process instance. Canonical launch hashing matches the existing TypeScript parser: generated ProtoJSON, omit only `launchContextHash`, recursively bytewise-sort keys, preserve array order. Bound final JSON at 16384 and configuration JSON at 262144. No file I/O, secret reads, signature calls or engine effects occur in preparation; parse/prepare errors and Debug remain static/redacted.

- [x] Write negative tests before implementation: forged target/version/hash, malformed/duplicate metadata, missing role, secret overlap, invalid UUID, expiry, oversized bytes and secret canaries.
- [x] Observe the focused test failing with an explicit refusal stub, then implement catalog selection and envelope construction.
- [x] Prove generated JSON passes the real TypeScript `parseRuntimeLaunchContext` using a real runtime export and a separately computed canonical digest; preserve integer fields above 2^53.
- [x] Run focused Rust tests, relevant gateway parser tests, formatting and Clippy; obtain scoped review before wiring the next boundary.

Task 1 verification: 128 Windows agent tests, 135 gateway parser/preflight tests, independent Rust-to-TypeScript launch digest parity, formatting, typechecks and Clippy passed. Scoped review approved; controller reran focused tests and parity. This verifies launch construction only, not production operation or Linux execution.

## Task 2: Authenticated operation-correlated production ingress

**Files:** Canonical runtime/authority protos and generated exports as needed; agent `src/{main,config,service}.rs`, service submodules, real mTLS tests; control-plane authority/store operation projection.

**Interface contract:** Add `RuntimeExecutionService.ReconcileRuntime(RuntimeReconcileRequest) -> RuntimeReconcileResponse`. The request contains only schema version, current target, operation UUIDv7, command UUIDv7 and published control hash. The response separately carries schema, exact current claims, operation observed state, optional installed `RuntimeObservation`, and a static error code. Nested runtime/readiness targets remain the original immutable installed target, not the current operation fence. Reject caller configuration and caller-selected effects. Preserve all legacy messages/RPCs and `RuntimeTarget` field numbers; do not register legacy mutation RPCs at the production listener. Actual request TLS supplies Controller identity. PostgreSQL supplies the exact current desired-state intent; the protected agent journal supplies effect phase and independently recorded predecessor ownership. Neither request claims nor check-only callbacks acquire execution semantics.

**Contract ruling:** The existing durable operation has desired state, not a separate effect kind/phase. Reconciliation therefore determines actions from authoritative desired state and durable host history, rather than adding caller-directed Ensure/Remove authority. This replaces the earlier proposed kind/phase projection. `Serving` may prepare the current candidate; `Paused` and `Retired` must never provision. Same-command retries and new commands for one operation converge on one owned record. A current-operation snapshot cannot authorize ongoing admission after terminal completion; Task 4 must implement a separate current-deployment/admission-renewal contract before serving is enabled.

- [x] Specify the minimal additive reconciliation contract from the existing journal types; test old wire compatibility, missing correlation and unknown/default states.
- [x] Exercise original Controller TLS through the real authority client and a real mTLS callback fixture: wrong role, absent TLS, stale operation, wrong installation/version and forged metadata dispatch no effects. Actual control-plane/PostgreSQL joint acceptance remains below.
- [x] Load explicit protected service files with bounded I/O/refresh and fail closed on revocation, expiry or invalid replacement; own listener and callback channel shutdown.
- [x] Run separately compiled production agent/control-plane/PostgreSQL acceptance, not a test-only ingress substituted for the agent binary.

The production ingress checkpoint passed scoped review after fixing retryable-state handling and first-snapshot startup ordering. A real Linux agent binary was tested, but its callback fixture is not the real control-plane/PG joint gate. That gate is integrated with Task3B; Task3A now supplies the reviewed dormant effects owner.

## Task 3: Bounded effects and durable container provisioning

Execute in two reviewed parts without a user checkpoint: **3A** connects actual agent-side durable dormant provisioning/signature/staging/create/inspect/recovery; **3B** replaces the control-plane direct-Docker path with authenticated durable reconciliation and proves the joint real control-plane/PG/agent path. Task4 enables start/readiness/admission only after network enforcement. Neither dormant creation nor a successful RPC is a Ready claim.

**Files:** Agent `src/{ownership,docker,effects}.rs` plus bounded submodules and Linux tests; runtime-agent deployment guide/service unit; control-plane authenticated runtime client/provider.

**Interface contract:** Durable journal records installation, full target, operation/command correlation, process instance, launch hash, owned resources and effect phase before external effects. Same-command retries reconcile the existing record; conflicts and lower fences refuse. Recheck currentness before create/start/admission/remove. Restart inspects exact labels and immutable image/configuration; unknown resources quarantine without broad deletion.

- [x] Test disk restart, duplicate ensure, stale fences, held blocking work, cancellation/timeout and uncertain engine results before effects are enabled.
- [x] Compose the real signature verifier, launch builder and stager behind fixed-capacity ownership retained until actual process/I/O cleanup.
- [x] Implement bounded typed OCI operations and independently inspect UID 10001, read-only root, capabilities, budgets, exact mount ownership and network isolation (dormant `network=none`; runnable egress remains Task4).
- [x] Replace legacy direct Docker provisioning with authenticated agent calls. Absence or unavailable dependencies remain `NotServing`.
- [x] Prove two-proxy isolation and crash recovery with disposable resources and an approved image fixture; never substitute arbitrary image approval.

Task3A dormant provisioning passed scoped review after fixing lifetime command-history exhaustion and an engine-preflight lease-budget reset. Final verification:202 Linux package tests,153 Windows tests,8 actual-engine tests, formatting/Clippy; the controller independently reran all8 engine tests successfully. Image `apex-task3a:fix-verified` digest `6f895ad9aedb73b77bf7c662f564a4505d6698dcd5ada1c482ce6dd2844d8274`. Safe persisted stage/create/removal boundaries,130 retries/restart/cleanup and synchronized metadata/currentness refusal are exercised. Evicted command IDs remain permanently refused through a bounded durable replay floor; Task3B must allocate increasing IDs across replicas/restarts. This is stopped-container provisioning, not serving admission or full production acceptance. Joint CP/PG/agent two-proxy acceptance remains Task3B, now in progress.

## Task 4: Enforced routing and lifecycle

**Files:** Runtime plan Tasks 8-10: agent network/routes, gateway dialer/admission state, control durable reconciliation, route projection and real edge fixture.

Execute the serving boundary in three reviewed slices after Task3B passes:

1. **Managed deployment and call authority:** exact installed/candidate/selected-serving records, agent-generated per-instance proof, protected workload credential enrollment, short-lived PREPARE/SERVE/CLOSED renewal, real Apex policy and durable per-proxy call reservations. Preserve original installed identity across operation-fence changes. Renew serving authority independently of terminal lifecycle operations; do not keep operations artificially nonterminal.
2. **Network and HTTPS path:** one isolated internal network per proxy, one narrowly configured dual-homed guard, fixed opaque ingress relay, a real HTTPS edge and scoped route projection. Only the guard crosses network boundaries; it receives no gateway TLS keys or control socket. Pin approved DNS/IP intersections at the actual connection and preserve the original TLS name.
3. **Production composition and lifecycle:** load and verify the complete immutable stage, construct real governance/evidence/upstream/admission owners, add typed start and fixed health-probe operations, then wire replacement, pause, resume and retirement with actual readiness, closure, drain and cleanup evidence.

**Admission ordering:** desired revision and selected serving instance are distinct. A current candidate may obtain PREPARE and complete all nine real readiness checks without admitting calls while an independently eligible old instance remains selected. Before replacement, withdraw the old route/grant, obtain its exact closure and physical drain acknowledgment or independently verified termination, recheck the candidate, then select SERVE and await its applied acknowledgment before publishing the route. Failed preparation must not prematurely withdraw an otherwise eligible old instance. After withdrawal, never resurrect an old grant implicitly. Pause/retire withdraw all candidate and selected authority.

**Freshness and physical ownership:** gateway renewal expires relative to its local monotonic request start, with a maximum ten-second interval, an echoed unpredictable nonce and a durable increasing epoch. Neither delayed responses nor repeated reads extend a grant. A call reservation's expiry ends permission to start; it is not proof an upstream operation ended. Release concurrency only after authenticated matching physical cleanup or verified instance termination. Required evidence still precedes success; read-only readiness must not consume a business-call reservation.

**Ingress identity:** the public HTTPS edge connects using inner mTLS through the guard's fixed TCP relay, with TLS terminated inside the gateway. Both sides validate their configured peer identity. An explicit new protected transport-profile variant may assign the existing WORKLOAD certificate roles to ingress; schema-1 governance/evidence-only profiles remain dormant and are not silently reinterpreted. Edge transport identity never replaces independent MCP bearer verification. Bind sessions to caller, proxy and installed generation/instance and support bounded POST/GET/DELETE streaming and cancellation.

**Evidence identity:** preserve canonical EventIngest durability and authenticated workload-to-event actor checks. Its existing single-agent staging resolver is not multi-proxy production enrollment. Add a distinct protected multi-workload mode with exact TLS/token/scope bindings and explicit per-proxy evidence identities; reject ambiguous mode selection and invalid/revoked refresh without stale fallback.

Local preflight confirms the installed Docker29.6.2 supports the proposed isolated bridge and per-container forwarding-disabled profile. A disposable single-network gateway reached the guard's internal interface but not its outer address. A separate real gRPC1.14.4/mTLS tunnel test accepted the correct original TLS name and credentials and rejected wrong-name, wrong-server-CA and wrong-client-CA cases. These are component compatibility checks, not the implemented guard, production admission or signed-runtime acceptance.

**Release boundary:** local unsigned component fixtures may verify code and transport behavior, but the production agent accepts only catalog-approved keyless-signed artifacts. Do not bypass signature verification or mount replacement application code over a signed fixture. Complete all safe local implementation and tests; record any final serving gate that requires approved signed Apex gateway/guard artifacts, deployment certificates or enrollment separately. No release signing or publication is authorized by this implementation request.

- [ ] Implement per-proxy internal network and egress guard; preserve TLS hostname verification while pinning approved DNS/IP intersections. Test direct CLI bypass, cross-proxy and metadata access.
- [ ] Compose the currently refusing managed-runtime factory with protected launch/material/authority-profile loading, concrete Apex governance/policy/evidence and upstream clients, admission/egress owners, live readiness/health and bounded shutdown. Existing primitive classes are not production wiring.
- [ ] Route only the ready current generation; test streamed MCP requests, cancellation and stale sessions through the real HTTPS edge.
- [ ] Make pause disable admission/routes then drain/stop; resume re-probes readiness; retirement removes only owned resources and retains history.
- [ ] Test rotation/rollback/restart crash points and guarantee at most one enabled route. Never revive revoked credentials or remove unknown containers.

## Task 5: Complete microsecond tracing and integrated acceptance

**Files:** Existing tracing tasks in [enforcement plan](2026-09-04-working-mcp-gateway-03-enforcement.md) and [operator/release plan](2026-09-04-working-mcp-gateway-04-operator-release.md); shared telemetry, gateway stages, evidence projection/query and operator trace display.

- [ ] Trace real ingress, authority, preparation, effect, readiness, routing and governed call stages with monotonic elapsed integers and explicit wall-clock uncertainty.
- [ ] Preserve 1, 7 and 999 microsecond differences and integers above 2^53 through serialization, durable evidence, projection, query and display using injected clocks, not sleeps.
- [ ] Keep pre-response admission and post-response completion evidence distinct; collector failure must report partial traces without bypassing required evidence.
- [ ] Run fresh deploy/call/deny, second proxy, pause/resume, rotation, retire and restart acceptance. Record exact commands/image digests and leave any unverified gate explicitly open.

## Execution tracking

Task3B intermediate verification: the first real two-proxy control-plane/PostgreSQL/production-agent journey passed in194.66s on fixture image `apex-task3b:joint` manifest `42f5e207605f4f2eb5a57e78469390a84667061b230509c059c090cca8ba1201`. It exercised authenticated dormant provisioning, accepted retries, query/identity refusals, restart with higher-fence recovery, pause and exact retirement of both isolated containers. This used the approved signed public Cosign fixture image, not a signed Apex serving release. A bounded transient-refusal retry follow-up and final review remain in progress; the parent joint checklist is intentionally still open. Independently rerun checkpoints:616 control-plane library tests,29 PostgreSQL operation tests and100 contract tests passed before that follow-up.

Detailed task briefs, test evidence and review decisions live in this plan's ignored SDD workspace. The parent Tasks 6-10 and release gates are updated only when their full acceptance criteria pass. Historical checkpoint tests are not repeated as new completion claims.

Task3B independent rerun found a reliability failure after the retry follow-up: fixture image `44ff1c44cc5b20bb4b9534263e241cdc26507e80ff91491d3999338be15c87f7` did not converge on a persisted dormant-runtime response within390s (`observed7`; test failed in393.05s). Earlier worker runs passed, but this independent failure reopens the checkpoint. Diagnose the actual response/observation persistence failure without extending the convergence limit or resetting durable authority. Final review and completion remain pending.

Follow-up isolated the failed proxy at durable `CreateIntent` without a container;
the healthy other proxy produced the successful response logs. A deterministic
actual-agent scheduling test reproduced authority refusal after intent persistence
but before Docker invocation. The fix records only that known no-dispatch fact
as `Staged`; unknown create completion and crash-boundary quarantine remain intact.
New regression passed, all9 real engine recovery tests passed, and independent
joint CP/PG/agent acceptance passed in13.42s on image
`80bc408587b8ea5493703d2bc25a019ab8b1856bde9d479871c871d942ef21f9`.
Earlier failed evidence is retained; this is dormant provisioning, not serving.
Scoped3B and coordinated agent-fix review remain the next gate.

Task3B complete after scoped review/fix1: Spec PASS / Quality Approved. The review
also exposed superseding cleanup of a known-no-create stage and frozen-retry
ordering before current approval/revision lookup; both have regression coverage
and passed scoped re-review. Final agent image
`e5d92604c2f1a30e9f469fc1d0bef3493f832b5a04e0312e4a6a1345f8ce2eac`
passed10 actual Docker cases in122.79s. Final combined image
`2d7f3927181938fd20a28bdd0a3c272f0ebc554aae7abcf92140eed3ad754c82`
passed the isolated real CP/PG/agent journey in14.55s. Final covering CP PG
tests33/33, validators3/3 and Clippy/fmt passed. Browser startup17/17,
Keycloak4/4 and refresh5/5 passed with the recovered fixtures; an earlier
session-store startup Unavailable in refresh testing remains recorded, not
claimed fixed. No NATS fanout or signed Apex serving release was tested here.
Task4 and full end-to-end tracing/serving acceptance remain open.

### Task 4A checkpoint — 2026-09-06

The durable deployment registry, short-lived workload renewal, protected
multi-workload evidence enrollment, actual managed Apex policy/admission services,
and optional mTLS control-plane routes now have scoped implementation and review
evidence. Agent registration joins the real current operation and protected
launch profile, preserving original sealed proof/launch identity and immutable
PostgreSQL provenance. Registration is metadata, not permission to serve.

The actual separately running control-plane/agent acceptance now proves sealed
stage -> authenticated registration -> PostgreSQL -> workload PREPARE, with the
fixture container independently verified stopped/network-none. The same image
also passed the existing schema-1 restart/Pause/Retire/isolation journey. The
explicit schema-2 `managed_preparation` mode does not assign ingress TLS purposes
or start containers. Scoped review found an alternate object representation
accepted by its enum decoder; the test-first string-only correction passed
re-review. The corrected image passed both joint gates (2/2, 19.26 seconds).

Current control-plane component evidence: managed authority 27/27, root 10/10,
registry/provenance 31/31, durable admissions 20/20 and contracts 107/107 passed;
these counts are not a full app or serving acceptance claim. The original server
and registration-client reviews passed. The business-call client and physical
executor ownership are the next integration work. Network/HTTPS enforcement,
production factory/lifecycle activation and full Task5 tracing remain open.

See [managed runtime authority](../../operations/managed-runtime-authority.md)
for deployment modes, credential separation, retry and commit uncertainty. Exact
commands, images, failed attempts and scoped reviews remain in the SDD ledger.

### Task 4 transport/network checkpoint — 2026-09-06

Subsequent reviewed components now include real governed call/evidence clients,
protected stage ownership, credential preflight, guarded upstream execution,
strict guard configuration and its relay process, and stage-bound governance/
evidence control transports. The latter passed a final-source native test with
distinct client certificates, tokens and proof handling, cancellation and peer
loss. The compiled executor remains the bounded read-only acceptance slice.

Agent network reservations and empty-network effect history are durable. A
concurrent publication race that could falsely quarantine valid topology history
was reproduced against the real Linux filesystem journal and fixed by serializing
the index snapshot with the sidecar scan. Independent review closed the finding;
genuine corruption still poisons history rather than silently resetting it.

This supersedes the earlier component-next-step descriptions above, not the open
Task4/Task5 acceptance checkboxes. Guard-stage production, verified paired
container creation/start/recovery, actual gateway HTTPS/session composition,
readiness, route/admission lifecycle, and end-to-end trace projection/query/UI
remain unfinished. See the [checkpoint and resume order](../../operations/managed-runtime-checkpoint.md).

### Task 4U guard data producer — 2026-09-06

Implemented after checkpoint merge and independently reviewed: exact bounded
key-free configuration, one-file manifest, fixed environment and guard image
selection from held publication/catalog inputs and original validated topology.
All required purpose grants intersect without widening. Current validity retains
exact integer microseconds through i64::MAX. Actual Rust output passes unchanged
TypeScript configuration/environment consumers. Final scoped tests passed17,
cross-language tests118, agent regression287 (34explicitly ignored), and native
empty-network/dormant regression10. An earlier existing service-test timing failure
is retained in the report, not claimed fixed by this producer.

Scope/spec/quality review passed. This supersedes only the data-production part
of the previous next step: no stage write, signature, paired container start,
readiness, route/admission or Serving authority was added. Continue protected
paired staging and lifecycle composition; Task4/Task5 aggregate gates remain open.

### Task 4W protected guard staging — 2026-09-06

Implemented and independently reviewed after published merge `e01f23e`, then
committed in `cdbcd1f`. Remote checks remain an exact-integration-SHA gate.
The [guard-staging composition](../../operations/managed-guard-staging.md) verifies
the real selected image signature, retains original data/signing/topology/root
identity in durable intent, and exclusively seals the key-free guard configuration.
Recovery accepts only an exact complete seal, rechecks current authority/metadata
and native topology, and syncs recovered files/directories before recording Sealed.
Missing, partial, replaced or changed state remains quarantined. Legacy checksums
and network owner identity remain compatible; no container start is added.

Exact formatted-source Linux image `de33a911ae500baa27a985e1e4ba5007b446b80c1f70f3cad88f133090d65cf1`
matches all25 Rust sources. Linux303 tests passed with36 explicit ignores; Windows170
passed with5 explicit ignores. Separately executed native network/signature-refusal
tests11 and same-inode bind-mount refusal1 passed. Linux/Windows strict Clippy and
scoped formatting passed; largest owned Rust file539lines. All94 unrelated dirty
file hashes and the complete pre-existing11-network inventory remain unchanged.

No positive signed production guard-stage or paired runtime acceptance is claimed.
Recovery covers service-process restart with retained mounts, not remount/reboot
or agent-container recreation. Paired gateway staging, verified paired container
lifecycle, HTTPS readiness/routes/admission and Task5 tracing remain open. Parent
task counts and Task4/Task5 aggregate checkboxes do not change.

### Task 4X paired gateway staging — 2026-09-06

Locally implemented after green integration `d8cd2c7`; scoped review passed. The
[paired-stage owner](../../operations/managed-gateway-staging.md) adds explicit
schema3 gateway files and scoped credential/proof staging after guard sealing.
Durable proof/write/seal phases bind original revision, signer, guard/topology,
protected roots, source identities and staged file identities. Recovery accepts
only a complete exact original seal; partial or substituted state remains untouched.
No image pull/create/start, registration, readiness, routes or admission is added.

Positive storage tests do not establish positive production signature/native
paired composition. Restart evidence retains the original mounts and source
hierarchy; it does not establish host reboot/remount or agent-container recreation.
Parent tasks and Task4/Task5 aggregate gates remain open.
