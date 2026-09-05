# Working MCP gateway release evidence

## Current status: registry only; release gate failed

This ledger covers the acceptance registry portion of [task 1](../superpowers/plans/2026-09-04-working-mcp-gateway-01-control.md) and the matrix in [task 21, subplan 04](../superpowers/plans/2026-09-04-working-mcp-gateway-04-operator-release.md).
All 15 required live cases are registered and **unimplemented**. Selecting any case produces `ACCEPTANCE_NOT_IMPLEMENTED`, a failed result and exit 1. No case is counted as skipped or passed.
This does not complete task 1's contracts, task 21's live runners, any G0-G3 gate, or the [implementation plan](../superpowers/plans/2026-09-04-working-mcp-gateway.md).

## Implementation checkpoints — not live acceptance

- `1161c95`: shared contracts, strict Rust/TypeScript JSON conversion, reproducible
  generation and compatibility checks. The registry's failure status is unchanged.
- `d9cc788`: monotonic/high-resolution gateway clock primitive, including exact
  1/7/999-microsecond and above-2^53 tests. This is not end-to-end tracing or a UI waterfall.
- Task 2 work after `d9cc788`: durable desired operations, frozen evidence intents,
  fencing, version guards and startup relay are implemented. Dedicated PostgreSQL
  tests cover transaction rollback, process death, uncertain enqueue, connection
  loss, competing leases, completed-command immutability, stale targets, schema
  incompatibility, fairness, lock-contention shutdown and cancellation cleanup.
  See the [operation journal guide](mcp-proxy-operation-journal.md). This checkpoint
  does not connect the Task 9 runtime controller or implement browser sessions.
- Task 2 reviewed transport work: an async-backed synchronous worker adapter adds overall
  connect and SQL deadlines, socket-driver cancellation, bounded DNS resource use
  and nested rollback. Startup-wrapper abort, healthy-primary/blocked-backup DNS,
  stalled trust-loader and real TLS verification/handshake regressions now pass.
  Independent specification/security review approved Task 2 after all findings
  were corrected and verified. Production release remains blocked on later tasks.
- Task 16 Rust clock primitive (uncommitted): 36 focused tests and all-target
  Clippy pass. Checked integer nanosecond/microsecond conversion, fixed wall
  anchoring and concurrent monotonic sampling are implemented. Source metadata
  distinguishes representation/local acquisition estimates from unknown UTC
  accuracy and drift. Independent review approved the Windows/Linux component;
  application spans, persistence, query and UI propagation remain incomplete.
- Task 3 browser foundation (uncommitted, in progress): crypto/security/error and
  typed RPC components are implemented. Nine real mTLS transport cases pass,
  including committed mutation/reply loss with no automatic retry. These use the
  actual handler with a component in-memory store, not live session acceptance.
  PostgreSQL session/worker, encrypted payload and OIDC component tests are being
  expanded; review found expiry/schema/isolation and token-validation issues
  which must be corrected before this task is approved. No browser login route,
  production session/startup flow or live Keycloak acceptance is complete.

Task 3 incremental development evidence at base `71921b5` plus the uncommitted
working tree (not a release SHA): `cargo test -p apex-control-plane-api --locked
--features postgres --lib browser:: --quiet` passed 237 tests in 10.36 seconds,
including 31 real HTTPS provider-transport tests and 40 strict callback parser
tests. The HTTP transport's corrected fixture PKCE value is canonical; production
validation was not relaxed. Provider composition review subsequently identified
late-poll side-effect admission and stale final-expiry checks; fixes are pending.

`cargo test -p apex-control-plane-api --locked --features postgres --test
browser_session_flow --quiet` passed the first eight HTTP/PG component cases in
2.31 seconds: safe unauthenticated routes, verified session/scopes/CSRF disclosure,
Origin/CSRF before mutation, scoped mTLS forwarding, invalid identity refusal,
local logout despite provider outage, durable expiry and request bounds. Provider
credentials are explicitly seeded for these cases; they do not prove OIDC login,
refresh rotation, the external HTTPS edge or production startup. A separate fresh
nine-case management mTLS rerun passed in 2.03 seconds. Callback-consumption HTTP
cases are being added, and the real Keycloak fixture is not yet verified.

The PostgreSQL review regressions exposed eight lock-wait expiry races and
schema drift weaknesses. After correcting a test URL's PostgreSQL options
encoding, all four Repeatable Read quota cases reached the intended race and
failed with 1,001/1,000 login attempts or 10,001/10,000 sessions (initial and
reconnected workers). These are recorded failures under repair, not acceptance.
The session actor's separate 17-case scheduling suite passed, including the
reviewed late-poll shutdown correction; the Rust clock's 36-case result above
remains component-only.

Fresh local command evidence after the deadline-adapter and serial-harness fixes:
`cargo test -p apex-durability -p apex-control-plane-api --locked --all-features
--quiet`, with `RUST_TEST_THREADS=1` and the dedicated PostgreSQL environment,
passed 267 control library tests, 31 startup tests, 10 contract tests, 21 recovery
entries (17 real database cases plus 4 child-process entry helpers), and 116
durability tests. Recovery took 33.85 seconds and durability 41.28 seconds.
All-feature/all-target Clippy with `-D warnings` passed for both packages.
The worker's 14 socket/DNS/trust/TLS tests also passed in parallel and serial runs.
Staged-diff, changed-Rust formatting and all-tracked-source 600-line checks passed.
Existing separately environment-gated
live suites are not counted as live evidence; their zero-time returns do not prove
deployed behavior. The dedicated journal database was present and its tests did
not skip. These numbers are a development checkpoint, not a G0–G3 result.

| Verification class | Entry point | What a successful command establishes |
| --- | --- | --- |
| Registry inventory | `node scripts/verify-working-mcp-gateway.mjs --list` | Metadata is available; `releaseGate: not-run`. |
| Component tests | `node --test scripts/tests/verify-working-mcp-gateway.test.mjs` | CLI selection, validation and failure accounting work. No live gate credit. |
| Required live acceptance | `node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all` | Must eventually prove real production paths; currently exits 1 with 15 failures. |

Every registered case has `kind: live-acceptance`, `required: true`, suite membership, an observation and `requiredEvidence`. Component tests are deliberately outside that registry and its pass/fail totals. A component test passing because the CLI correctly fails is not a passing acceptance case.

## CLI contract

Run from the repository root. Node built-ins suffice for this registry; `--list` also works outside the repository without Docker, services or a populated `PATH`.

```powershell
node scripts/verify-working-mcp-gateway.mjs --list
node scripts/verify-working-mcp-gateway.mjs --list --suite tracing
node scripts/verify-working-mcp-gateway.mjs --list --case evidence-outage
node scripts/verify-working-mcp-gateway.mjs --profile lab --case fresh-ui-create-deploy
node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all
node scripts/verify-working-mcp-gateway.mjs --profile ci --suite failure --artifacts "artifacts/mcp acceptance" --keep-on-failure
```

`--profile` accepts only `lab|ci` and defaults to `lab`. Select either `--case <case-id>` or `--suite smoke|isolation|failure|tracing|all`; they cannot be combined. `--list` can inspect either selection or the entire registry. `all` includes every case exactly once, including cases in multiple suites.

`--artifacts <directory>` requires a nonempty value and reports an absolute requested directory. `--keep-on-failure` is an explicit boolean opt-in, default false. Both are parsed for the future live runner; this skeleton creates no artifacts, directories, containers or other resources. Results say `liveExecution: not-started` and `artifacts: []`. There are no retained resources or teardown claims.

Valid output is JSON on stdout. Inventory exits 0 without an execution claim. Required unimplemented cases exit 1 with explicit reasons, evidence requirements and selected/passed/failed/skipped/unimplemented counts. Missing selection, unknown IDs/options, invalid profiles/suites, missing values, positional arguments and duplicate/conflicting options exit 2 with `INVALID_ARGUMENTS` JSON on stderr. Empty invocation has no default success; `--list` never suppresses argument validation.

## Required evidence for every live case

The following is a collection contract, not an assertion that artifacts exist. Each case needs the common run manifest plus its row below. Preserve exact IDs and integer strings needed to verify correlations; use consistent aliases for sensitive actor/host metadata.

Common manifest and diagnostics must contain:

- Tested Git SHA and dirty-state/diff identity, actual deployed image digests, run ID and unique disposable Compose project/ownership labels.
- Machine/OS/CPU/memory, runtime/tool versions, clock source/resolution/uncertainty, profile, exact sanitized commands and start/end times.
- Selected case IDs, expected/actual observations, exit status and pass/fail/skip/unimplemented counts; zero required skips and zero unexpected upstream writes are release requirements.
- Redacted artifact paths for browser/Playwright traces, SDK outcomes, runtime metadata/logs, durable event queries and exact expected/actual event IDs. Keep live production execution separate from component/fixture results.
- Failure injection and recovery boundaries, bounded wait/timeout diagnostics, limitations and ownership-scoped cleanup results. Prove no orphan containers, processes or test volumes remain.

Before persisting logs, screenshots, DOM snapshots, Playwright/network traces or JSON, remove authorization headers, cookies, tokens, passwords, private keys, raw tool inputs/results, CLI argv and private host paths. Record only credential-reference metadata and approved profile/digest identifiers. Keep ephemeral credentials in private temporary files outside reports. Scan exported artifacts for secret canaries; record the scan outcome without the canary value. Do not attach raw database backups to this ledger.

| Case ID | Suites | Required redacted evidence in addition to the common manifest |
| --- | --- | --- |
| `fresh-ui-create-deploy` | smoke | Empty-install/project baseline; real OIDC login and authorized scope; visible create/save/reload/discovery/publish/deploy journey; operation/revision IDs; selected tools matching SDK `tools/list`; actual new container/image digest/HTTPS route and readiness handshake. No preseeded proxy or intercepted API responses. |
| `allowed-denied-call` | smoke | Real SDK allow/deny outcomes and Apex policy decision IDs; exact upstream counter deltas, including zero denied execution/unexpected writes; expected/actual durably admitted event IDs matching call/proxy/revision; actual activity query/UI. |
| `two-proxies` | isolation | Separate upstream, proxy/revision IDs, credential-reference versions, catalogs/tools/policies, runtime routes and independent state; cross-proxy token/session/egress denials with upstream counters and no credential values. |
| `cli-stdio` | isolation | Unrelated structured tool outcomes; approved executable/profile digests; actual subprocess ownership and SDK stdio framing; shell/argument escape and forbidden network denials; exact execution counters and correlated durable events. No raw argv. |
| `approval-limits` | isolation, failure | Pending/dual approval IDs with distinct approver aliases, expiry and policy revalidation; single consumption/no duplicate execution; configured queue/concurrency/rate/budget limits against exact accepted/rejected/executed counts and durable decision IDs. No raw approval arguments. |
| `pause-retire` | smoke, failure | Pause-during-call operation and observed-state timeline; new and existing-session admission rejection; in-flight/drain counters; successful resume; runtime stopped/removed and route removed on retire, with lifecycle event IDs. |
| `rotate-rollback` | isolation, failure | Before/after operation/revision/generation/image digest and credential-reference versions; old-session denial; route observations proving at most one routable revision; bounded candidate validation/drain; rollback uses valid credentials and fresh readiness. |
| `controller-runtime-crash` | failure | Separate control-plane/runtime-agent/gateway crash/restart boundaries; persistent request/operation/generation/fencing IDs; exact provision/execution counters with no duplicates; fresh readiness, owned runtime inventory and canonical durable event IDs. |
| `governance-identity-outage` | failure | Separate governance and issuer/identity outage/recovery boundaries; fail-closed SDK/admission errors, actionable redacted UI state and upstream counters; durable decision correlations where evidence admission remains available. |
| `evidence-outage` | failure | Failure before/after upstream execution and durable admission; client failure/uncertain outcomes, exact execution counters and absence of successful unrecorded responses; expected/actual event IDs after reconciliation; no blind duplicate write retry. |
| `projection-outage` | failure | Separate NATS, ClickHouse and archive outage/recovery injections; durable ACK/event IDs and accepted-call counts; visible UI lag/stale state/cursors; eventual projection and archive IDs matching admitted events. |
| `microsecond-precision` | tracing | Instrumented test-clock inputs for 1/7/999 us, `1788480000123456`, optional `7000` ns and `9007199254740993`; exact integer strings across gateway, RPC/JSON, admission, durable store, projection/query and UI/download; six fractional timestamp digits and clock/span metadata. |
| `wall-clock-jump-skew` | tracing | Backward wall-clock and skew inputs; process anchors, nonnegative monotonic durations, resolution/uncertainty, separate overlapping call/span IDs; UI marks unknown/skewed clocks and does not infer cross-host wire latency or sum overlapping child durations as root time. |
| `trace-exporter-loss` | tracing, failure | Exporter outage/recovery boundary; intact durable ACK/event IDs and accepted-call/upstream counts; visible partial traces/loss flags, dropped-span counters and bounded queue measurements in real query/UI output. |
| `backup-restore` | failure | Sanitized backup/restore commands and dedicated database/project ownership; exact restored proxy/revision/approval/history IDs/counts; restore/restart reconciliation and readiness-before-routing timeline; reconciled evidence/history queries. |

Live runners must use production-built browser, Rust governance, runtime agent, gateway, database/admission/query paths and real MCP SDK clients. Only the issuer, business upstream and instrumented clock injector may be fixtures. A running process, mock browser response, source-only test, hardening flag or printed timestamp precision is insufficient evidence.

When live execution is implemented, missing Docker/dependencies, `NotServing`, failed assertions and timeouts must remain failures. Use bounded observations, authenticated provisioning and ownership-labeled disposable resources with cleanup in `finally`; never target normal installation data. Task 21 still requires two full runs from fresh projects plus a recovery-injection run with cleanup proof. Nothing here supplies that proof.

## Observed local component verification: 2026-09-04

Working directory: `E:/Agent Control Plane/.worktrees/working-mcp-gateway`.
Base HEAD: `a332aaf489fd993c6f87dde6a76d2c1b2d379399`, with uncommitted registry/test/ledger files and unrelated concurrent changes. This is not a tested release SHA or image.
Machine: Windows `10.0.26200`, x64, 8 logical CPUs, approximately 62 GiB RAM; Node `v24.16.0`.
Image digests: none exercised. Live/browser/runtime/evidence artifacts: none collected. Docker/service availability was not probed by the registry.

Each test-first cycle used the exact command:

```powershell
node --test scripts/tests/verify-working-mcp-gateway.test.mjs
```

| Cycle | RED observation (exit 1) | GREEN observation (exit 0) |
| --- | --- | --- |
| Inventory | 0 passed, 1 failed: missing CLI entry point. | 1 passed, 0 failed: all 15 live cases listed without service prerequisites. |
| Case selection | 1 passed, 1 failed: `--case` returned usage failure instead of a selected acceptance failure. | 2 passed, 0 failed: each of 15 cases returns explicit unimplemented failure. |
| Suites | 2 passed, 1 failed: `--profile`/suite selection unsupported. | 3 passed, 0 failed: smoke/isolation/failure/tracing/all select exact required sets. |
| Validation | 3 passed, 1 failed: unsupported production profile accepted. | 4 passed, 0 failed: invalid/missing/duplicate/conflicting selectors return usage errors. |
| Artifact flags | 4 passed, 1 failed: `--artifacts` unsupported. | 5 passed, 0 failed: flags validated, opt-in preserved, no fake live run/artifacts. |

All component runs had zero skips. Console output is recorded in the task transcript; no persisted test-report artifact was created.

The exact acceptance command was also executed:

```powershell
node scripts/verify-working-mcp-gateway.mjs --profile ci --suite all
```

Observed: exit **1**, 15 selected, **0 passed / 15 failed / 0 skipped / 15 unimplemented**, `releaseGate: failed`, `liveExecution: not-started`, and no artifacts. These are registry failure results, not attempted live observations. G0-G3 remain unproven in this ledger.

## Task 3 HTTP/login/refresh development checkpoint

2026-09-04 America/Chicago (2026-09-05 UTC), Windows worktree above,
HEAD `71921b5639d084dbb1543bf2a83109d5f2d0ea3b` plus uncommitted Task 3 files.
This is not a release SHA, deployed gateway image or completed Task 3 gate.

The owned PostgreSQL fixture uses loopback port 55439 and isolated UUID-named
schemas. The owned HTTPS Keycloak fixture uses loopback port 18451, a fresh
local CA and pinned image
`quay.io/keycloak/keycloak@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007`.
Its browser credentials are explicitly lab-only in the realm import, not
production defaults. `node --test scripts/prepare-browser-keycloak.test.mjs`
passed 9 tests; the helper's actual start and HTTPS readiness succeeded locally.
CI now starts and performs ownership-scoped cleanup of this fixture; that CI
workflow has not been executed on GitHub at this checkpoint.

With the required owned-fixture environment set, these fresh local commands passed:

| Command | Observed result and scope |
| --- | --- |
| `cargo test -p apex-control-plane-api --locked --features postgres --test browser_session_store -- --test-threads=1` | 51 passed, 0 skipped, 28.17s. Includes post-lock expiry, schema drift, quota isolation, reconnect and fixture host policy. Independent fix review approved the bounded store component. |
| `cargo test -p apex-control-plane-api --locked --features postgres --lib browser::oidc::http:: --quiet` | 42 passed, 5.40s before subsequent mechanical Clippy test edits. Fixed process-shared bounded DNS and exact child-watchdog ownership; not a live stalled OS resolver test. |
| `cargo test -p apex-control-plane-api --locked --features postgres --test browser_keycloak_flow --test browser_session_flow -- --test-threads=1` | Real Keycloak 4/4 in 1.68s; HTTP/PG/mTLS composition 13/13 in 11.35s, zero skips. |
| `cargo test -p apex-control-plane-api --locked --no-default-features --quiet` | Library 180, startup 30 and the enabled integration groups passed. Feature-gated browser cases are not covered by this command. |
| `cargo clippy -p apex-control-plane-api --locked --features postgres --all-targets -- -D warnings` | Passed after mechanical lint corrections; this is not all-features Clippy. |

Real Keycloak tests perform HTTPS authorization-code/PKCE login and actual token
verification, opaque session creation, allow/deny mTLS management calls, one-use
callback rejection, local logout, refresh-token rotation and rejection of the old
refresh token. Eight concurrent requests share one refresh generation. To avoid
a four-minute sleep, refresh tests shorten the copied access expiry and reseal
its authenticated bundle only in their owned schema; signed credentials,
provider responses and grants are not fabricated or extended. The first refresh
test failed semantically (503 instead of 200) before orchestration was implemented.
The concurrent-refresh and provider-outage cases are additional regression tests,
not claimed as separate red/green implementation cycles.

The component HTTP suite also proves Origin/CSRF checks before refresh or idle
touch, strict bounded RPC bodies, forbidden scope denial, and a provider outage
leaving one non-serving, non-retryable refresh claim. Logout can revoke that
claimed session and erase its ciphertext. An abandoned claim expires closed;
the code never reuses its old refresh token or launches detached retries.

Limits: the test client maps the fixed external HTTPS callback to a confined
internal HTTP test hop and manually handles cookies. It does not prove an actual
browser cookie jar, external TLS edge, React UI, production startup or root
process shutdown. Management tests use the real authenticated handler with a
component in-memory proxy store; production desired-state behavior is covered
separately by Task 2, not silently certified here. BFF audit/timing integration,
remaining edge/deadline reviews, full refresh crash/cancellation matrix and
end-to-end microsecond tracing are still outstanding. G0-G3 remain incomplete.

### Root startup follow-up (same uncommitted development checkpoint)

`cargo test -p apex-control-plane-api --locked --features postgres,test-support
--bin apex-control-plane-api startup::tests::root_browser:: -- --test-threads=1`
passed **6/6, zero skipped, 3.60s** with the owned fixtures above. These additional
regressions run `startup::service::run_until` in exact-selector child processes,
not a separately assembled HTTP edge. They verify real PKCE login, persisted
opaque session, allowed/forbidden management scope against actual PostgreSQL
proxy storage, callback replay rejection and logout. Other cases cover disabled
browser shutdown, occupied control/browser ports, and wrong bridge CA/name after
gRPC startup. Parent and child independently observe zero root-named PostgreSQL
connections after startup returns while the child is still alive. This is not
connected NATS/Valkey, external browser cookie-jar or full gateway acceptance.

Material-loader tests freshly passed **13/13 in 0.02s** after a semantic
relative-path RED (12 passed, one failed). They cover base-relative/absolute
confinement, bounds, raw keys, strict client-secret grammar and zeroizing return
types. Windows uses the explicit existing `test-support` permission waiver;
these results do not prove production Windows ACLs or erased heap contents.
Unix-only symlink/mode cases still require Linux CI execution. Supervisor helper
tests also passed **4/4** for signal/guard, unexpected exit, join failure and
timed-out drain. Root regression tests were added after production wiring and
are not represented as a separate test-first implementation cycle.

### Browser admission and observation checkpoint (September 4 local / September 5 UTC)

Uncommitted development tree on `codex/working-mcp-gateway`, base `71921b5`.
Fresh main-run results, all with zero ignored tests:

- Startup binary: **71/71, 5.49s**, including seven real root-process cases,
  bounded connection cancellation, exporter shutdown results and metrics HTTP.
- Real Keycloak login/rotation: **4/4, 1.60s**.
- Browser HTTP flows: **19/19, 22.78s**, including durable login admission and
  actual redacted observations; output failure leaves the RPC result unchanged.
- Observation primitive: **22/22, 0.48s**. Partial-write regression first failed
  with two corruptly counted exports; the fixed worker closes after uncertain I/O.
- Refresh races: **5/5, 11.65s**. Three cases use actual held Keycloak replies;
  two exercise withheld PostgreSQL startup/query delivery. Before bounded
  transport, both fault cases failed under the independent child watchdog
  (**0/2, 20.01s**). Fixed cases prove helper/runtime termination and gate release.
- PostgreSQL session store/worker previously passed **59/59 (31.92s)** and
  **12/12 (7.62s)** after version-2 durable login admission.
- `cargo clippy -p apex-control-plane-api --locked --features
  postgres,test-support --all-targets -- -D warnings`: **passed, 4.37s**.

The normal Keycloak issuer remains on owned loopback 18451; a separately owned
18462 backend advertises the 18461 response gate for refresh races. Tests never
substitute a fabricated successful provider response. Fault peers are only for
transport failure, not identity/data assertions. Local Windows permission tests
still use explicit `test-support`; Linux production ACL behavior and GitHub CI
are not certified by these results. Independent observation/E2 fix reviews are
pending at this checkpoint; full Task 3 and G0-G3 are not marked complete.

### Cross-language/image checkpoint (September 5 UTC, approximately 03:53)

Development tree still based on `71921b5`; no new release SHA or GitHub run.
The observation, refresh-race and session-context review fixes are now accepted
on independent source review. The TypeScript consumer's aggregate object-size
preflight fix is likewise accepted; it rejects repeated-string/key expansion
before generated serialization, with seven additional targeted regressions.

- Full control-plane `cargo test --locked --features test-support,postgres,valkey`
  passed: 576 library, 71 binary, browser suites 4/9/5/19/59/12, compiler 18,
  contract suites 3/7 and operation recovery 21. The existing separate legacy
  live targets report another 33 passes but contain environment-based early
  returns; **these are not live integration evidence**. None used libtest ignore.
  This run predates the new, not-yet-executed Chromium root journey.
- Fresh all-target/all-feature control-plane Clippy passed (10.09s) after the
  Chromium root bridge compiled; the browser journey itself is still pending.
- Collector: 23/23 Windows tests passed (1.66s). Its separately Unix-only
  file-symlink case is not claimed as locally exercised. The collector copied
  the actual fresh Rust export: 3,632 bytes, SHA-256
  `970cfd7a059a4761fc8b4ad6f8f9d5dd4f4f4f4c4f2d16995cde807d20fdd554`.
  The gateway consumed that file, not a handwritten substitute.
- Gateway: 178 passed, zero failed, **one Windows symlink-privilege skip**, 179
  total (2.84s); typecheck/build passed. The skip remains a Linux release-gate
  obligation, not a waived security test. Generated contracts verify passed;
  contract tests 38/38 passed (0.19s).
- Image packaging first failed with missing `@apex/contracts` during install.
  Repository-root build then passed, using Node image digest
  `sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203`
  and pnpm 10.34.5. The test image
  `apex-mcp-gateway:working-contract-check` (manifest
  `sha256:521d3a9f7c7bea9ffa73a683b4a4b34ca8b957c9583f233fd435b7c8125965f6`)
  imported actual live/generated modules and found both live proto files under
  UID 10001, `--network none --read-only`, with no source mount. This image
  predates the later parser byte-budget fix and is packaging evidence only.
  Compose configuration validation passed; startup/readiness are not certified.
- Readability checker tests: 4/4 passed (0.36s) using a new isolated temp root
  after the host's existing pytest temp directory denied access. Tracked files
  and 211 changed/untracked handwritten files were below 600 lines at the prior
  scan; additions since that scan still need the final check.

CI now transfers the actual Rust artifact to its dependent gateway test job,
runs UI tests, and prepares the pinned browser for the new root journey. YAML
parsing passed before the last browser-preparation additions; actual GitHub CI
and final packaging/CI review remain pending. The browser uses Playwright 1.62.0;
the installer-created release-age exclusions for newly released 1.63.0 were
removed, and the final lockfile passed the unchanged supply-chain policy.

### Actual browser checkpoint (September 5 UTC, approximately 04:25)

Development tree remains based on `71921b5`, not a release SHA. The exact test
`startup::tests::root_browser::root_browser_chromium_create_reload_outage_restart_logout`
passed **1/1 in 2.39s**, using the built UI, Chromium, actual Keycloak and a fresh
PostgreSQL schema through two successive production roots. It logged in, created
one scoped UUIDv7 draft through the UI, reloaded detail/inventory, observed the
unavailable session gate while the API was stopped, recovered the same durable
record/session after restart, and signed out. The root also verified encrypted
session erasure, one proxy row and zero owned database connections after shutdown.

This followed real failures: Windows verbatim-path runner startup (0.58s), then
an incorrect test expectation that the bounded multi-tab login-binding cookie
must disappear (1.33s). The path regression was RED then GREEN; the cookie helper
was 38 passed/8 failed against the prior expectation, then **46/46 GREEN**. The
production cookie policy was not weakened or changed.

- UI: **301/301 tests**, 2.55s; typecheck and production build passed.
- Rust protocol/path components: **5/5**, 0.45s. Diagnostic filtering: **2/2**.
  Fresh all-target/all-feature Clippy passed, 0.78s.
- Independent Rust diagnostics review accepted the separately piped, static-only
  Node error forwarding; Node does not inherit the parent-facing diagnostic pipe.
- One batched desktop/mobile inspection covered inventory and draft. No horizontal
  clipping was observed; the root-route navigation highlight needs correction.
  Impeccable's static scan of eight changed screen/style targets returned no findings.
  Captures are retained under
  `C:/Users/zrmon/AppData/Local/Temp/apex-ui-artifacts-a5408f580d9c484faf8541fc3097c1f2/ui-journey-stSy8o/`.
- Physical-line scan: **229 changed handwritten source/test files**, all at most
  600 lines at this checkpoint. Later changes require a fresh final scan.

The passing live run is provisional acceptance evidence: independent review
identified two harness false-success paths (suppressed browser-close failure and
frontend-overwritten upstream cache policy). Their fixes and regressions are in
progress. The developer proxy also needs callback-query log redaction on backend
errors. No complete Task 3/4, G0-G3, production browser trust, Windows production
ACL, deployment readiness or end-to-end MCP tracing claim is made yet. The browser
uses an explicit lab-leaf SPKI exception, not a system/public-CA trust change.

### Reviewed browser foundation (September 5 UTC, approximately 04:46)

Development tree remains based on `71921b5`; this is not a release SHA or a
GitHub CI result. The preceding browser checkpoint's open review findings are
now closed on independent source review and checked by fresh execution:

- Final startup binary: **79/79 passed, 10.94s**, including the actual Chromium
  create/reload/outage/restart/logout journey after all harness fixes. The test
  used the same owned PostgreSQL/Keycloak fixtures and explicit lab TLS policy.
- Full browser helpers: **85/85 passed, 0.302s**, zero skipped/cancelled. Rejected
  browser cleanup cannot emit PASS; the frontend validates the actual BFF cache
  policy instead of manufacturing upstream no-store evidence. Focused fix RED
  was 14 passed/6 failed before the implementation, then 24/24 GREEN.
- UI: **305/305 passed, 2.19s**; typecheck and production build passed (1.75s).
  Actual Vite error-path tests prove default proxy logging does not print OAuth
  callback query values. Explicit `DEBUG=vite:proxy` tracing is not sanitized
  by this narrow wrapper and must not be enabled with sensitive traffic.
- Root navigation now redirects to `/mcp-proxies`. One confirmation batch of
  desktop/mobile inventory captures shows the correct active navigation and no
  horizontal clipping. Captures are under the preceding artifact root in
  `ui-journey-VkHMX6/`. The bounded Task 4 visual cycle is complete.
- Rust clock: **36/36 passed**; clock Clippy passed (0.11s). These are integer
  timing primitives, not proof of durable end-to-end MCP trace delivery.
- The CI preparation now runs the complete browser helper suite before the
  Rust journey. Workflow YAML parses with 12 jobs; GitHub execution is pending.

The actual browser run proves normal cleanup, not every OS process-tree failure
or forced Chromium termination. Linux production private-file modes, readiness,
network enforcement and the remaining release cases still require their gates.
Task 5 publication tests now expose a genuine failure (4 passed/3 failed, 1.02s):
unsupported executable capabilities can mutate memory/PostgreSQL publication or
emit success evidence. Its transaction guard and TypeScript generated-runtime
migration are being implemented; G0-G3 are not complete.

### Publication checkpoint and browser regression (September 5 UTC, 05:05)

Commit `33a053a4ee20a711a775e8d8d124315794ce71b8` contains only the independently
reviewed publication guard and its ten source/test files. The larger browser,
compiler and clock foundation remains staged and uncommitted.

- Publication tests passed **7/7, 6.18s** twice against required PostgreSQL;
  independent review found no blocking issue. Both stores reject unsupported
  executable capabilities before mutation while preserving editable drafts,
  committed replay, scope/conflict precedence and failed-request-ID reuse.
- Fresh Rust library: **576 passed**. Named integration suites passed:
  Keycloak 4 (1.51s), mTLS 9 (3.10s), refresh races 5 (11.81s), HTTP 19 (22.73s),
  session store 59 (31.64s), worker 12 (7.55s), compiler 18 (0.08s), operation
  recovery 21 (33.16s) and publication 7 (6.18s). All-target/all-feature Clippy
  passed (3.60s). These results are from the development tree, not solely the
  ten-file publication commit.
- Fresh UI **305/305**, typecheck/build passed; generated consumer **27/27**
  consumed the new actual Rust export with the same recorded SHA-256. Contract
  generation verify and **38/38** compatibility tests passed.

The fresh startup run **failed: 78 passed/1 failed, 10.25s**. The no-screenshot
Chromium case reproduced a cookie failure in 1.32s. Credential-safe diagnostics
then isolated its lifetime comparison: Chromium expiry exceeded the test's
separately sampled Node response-event time plus 600 seconds. A diagnostic run
passed (4.85s), but the next failed (1.28s); that pass is not treated as a fix.
The production cookie policy has not changed. Investigation of the observation
boundary continues; foundation commit and G0 remain held until fresh acceptance.

### Cookie observation and production packaging (September 5 UTC, 05:29)

Development tree based on `33a053a`, not a release or GitHub CI result.

- The cookie test now validates the original actual Set-Cookie lifetime
  instruction (`Max-Age` 1..600 and strict security attributes), correlates its
  opaque value with a pre-credential browser snapshot, and rejects subsequent
  binding issuance, value replacement or expiry extension. It does not pretend
  to calibrate Chromium's cookie-creation clock against Node. Production cookie
  behavior is unchanged. Independent source review passed without actionable
  findings; its frozen hashes match the verified implementation.
- With no screenshot/artifact variable and the same dedicated temporary root,
  PostgreSQL and Keycloak fixtures, three consecutive actual Chromium root
  journeys passed (4.90s, 2.17s, 2.09s); the fresh full startup binary passed
  **79/79 in 2.65s**. Full browser helpers passed **150/150 in 0.301s**.
  These fresh runs supersede the preceding intermittent test failure, not the
  remaining production deployment gates.
- Generated runtime chain: **200 total, 199 passed, 0 failed, 1 existing Windows
  private-material symlink skip**, 12.855s; all-source typecheck and production
  build passed. Independent source review accepts the staged fail-closed design
  but requires bounded direct-process startup tests; that correction is active.
  Managed execution remains unavailable before secret/client/discovery/listener
  construction until real network/admission enforcement exists.
- Actual old image `apex-mcp-gateway:working-contract-check`, ID
  `sha256:521d3a9f7c7bea9ffa73a683b4a4b34ca8b957c9583f233fd435b7c8125965f6`,
  failed a packaging probe: 78 compiled test files and one embedded test-only
  private key. The build now emits only the entrypoint's transitive production
  graph; separate all-source typechecking is retained.
- Fresh image `apex-mcp-gateway:working-production-check`, inspect ID
  `sha256:f89a2e34a62a96a55596e6e586ce95830c24467e65c0cace6416333212636afa`,
  built in 9.28s and passed the same real probe under UID 10001, a read-only
  filesystem, no network, dropped capabilities and no-new-privileges: zero
  compiled tests/embedded private keys, actual live module/generated package
  imported, both governance/event schemas present. The three-file build delta
  has independent approval. A reusable bounded image harness is being added.

The packaging probe is not an entrypoint readiness or serving test. Explicit
development-only stdio, authenticated health transitions, durable MCP traces,
host network enforcement and G0-G3 remain open. No merge/push was performed.

The reviewed browser/UI foundation, pure generated-config compiler/consumer,
Rust clock primitives, fixture/CI preparation and production build-selection
changes are committed locally as
`cc30a1c31a288535ec35db7cd4bddd195ed3a871` (263 files). The generated runtime
chain and reusable image harness are excluded pending their separate review.
This is a development checkpoint, not a validated release image or completed G0.

### Generated chain and real packaging gate (September 5 UTC, 05:56)

The independently reviewed generated runtime migration and its bounded startup
regressions are committed as `2ec12975565aae2c41ca18bb3e03979794de19aa` (28 files).
The test helper now owns Node directly, caps retained output at 16 KiB per
stream, latches timeout/overflow failures and bounds cleanup independently.
Focused 16/16 passed; main's fresh full run passed **210/211 tests, 12.110s**,
with zero failures and one existing Windows private-material symlink skip.
All-source typecheck and production build passed. Independent rereview closed
the startup process-lifetime finding; no production authority fallback was added.

The reusable packaging harness now runs against actual Docker images:

```powershell
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-contract-check --suite packaging
node apps/mcp-gateway/scripts/verify-image.mjs --image apex-mcp-gateway:working-production-check --suite packaging
```

The first command correctly exited 1 with `PACKAGING_ARTIFACTS_REJECTED`:
189 files, 619069 bytes, 84 test/fixture artifacts and one test-only private key.
This broader artifact count includes fixture paths/directories; the earlier 78
count covered compiled tests only. The second exited 0 with `PACKAGING_OK`:
34 files, 129977 bytes, zero test artifacts and zero private-key markers.
Both loaded two real proto entrypoints, three service descriptors, four expected
RPC methods and three generated schemas under the fixed confinement policy.
Both confirmed removal of their exact owned containers; combined runtime 3.80s.
Image IDs remain the `521d...` and `f89a...` values recorded above. Each report
explicitly says `readinessVerified: false`. Full helper suite: **62/62, 1.087s**.
Independent spec/quality review passed for the reusable packaging harness;
all nine frozen source hashes match. Full Task 6 readiness remains open.

Actual checks first exposed omitted image `Volumes` and nullable container
collection fields in Docker's templates. The corrected projections retain
strict zero-volume/mount/bind/port/device checks. Cleanup verifies only exact
ID/name/image/run-label ownership and no longer depends on confinement-only
fields. Main verified and removed the two never-started containers left by the
initial failing check; no shared container, volume or installation data was removed.

Task 6 now adds explicit process profiles and additive launch/readiness wire
contracts. RuntimeConfiguration v1 and its existing tool-secret union stay
unchanged: health and authority bootstrap belong to a separate agent-owned
deployment binding. That choice requires strict cross-binding validation later;
neither a generated message nor matching hashes establish authority or readiness.
Full health, admission, egress, trace delivery and G0-G3 gates remain open.

### Explicit profiles and additive health contracts (September 5 UTC, 06:30)

Local development checkpoints, not a release, merge, push or GitHub CI result:
packaging harness `24e329092d82f690ceef4a720ed9c96beb4a7a20`;
additive launch/readiness wire `a6fc19b0f1894b205a75d51f2fc74e24283f5595`;
explicit profiles and bootstrap health configuration `b973488`.
Independent spec/quality reviews passed and frozen candidate hashes matched
before these commits. RuntimeConfiguration remains v1; launch metadata and
readiness reports are generated contracts, not authentication or lease proof.

- Fresh contracts: **85/85**, 0.218s; regeneration/compatibility verification
  passed. Corrected Rust library run: **576/576**, 11.31s, plus **3/3** JSON
  contract tests. An initial run omitted the required TLS fixture-directory
  variable; its 544/32 result was setup failure, not a contract regression.
- Fresh real Rust export: **18/18**, followed by generated TS consumer **27/27**.
  Artifact: `C:/Users/zrmon/AppData/Local/Temp/apex-health-wire-1123e8d8aa224f4d89f1365cd70a3cc1/collected-runtime-revision.json`,
  SHA-256 `970cfd7a059a4761fc8b4ad6f8f9d5dd4f4f4f4c4f2d16995cde807d20fdd554`.
  These are existing-v1 compatibility checks, not new health Rust semantics.
- Fresh gateway suite: **223 total, 222 passed, zero failed, one existing
  Windows symlink skip**, 29.414s; all-source typecheck and production build
  passed. The actual SDK initializes and lists tools through the directly
  owned entrypoint under both explicit development selectors. Default/missing
  managed configuration refuses; valid generated metadata still refuses
  unavailable enforcement before clients or listeners.
- Bootstrap source-policy tests: **3/3**. Actual resolved Docker Compose JSON
  confirms exact managed/live profile, disabled healthcheck (no success
  command), UID10001/read-only/all capabilities dropped/no published ports.
  This checks configuration only and launches no Compose containers.
- Rebuilt image in 8.65s: inspect ID
  `sha256:eebcc8a6953bbece333b81076be5e1ddcd734b5a2ebcbd9dee7a5d1ec8dff6ba`.
  Actual packaging passed: 35 files, 131401 bytes, zero compiled test artifacts
  or private-key markers in the app output; two protos, three services, four
  expected RPC methods and three generated schemas. Confinement and removal
  of the exact owned container were verified. `readinessVerified: false`.

The image startup-profile suite and readiness lifecycle components are being
added. No image startup/managed health result is inferred from host tests or
packaging. No actual trusted launch producer, egress/admission enforcement,
cross-process trace delivery or release gate is certified by this checkpoint.

### Launch validation and original image entrypoint (September 5 UTC, 06:52)

Pure launch metadata validation is committed as
`0ba80dc670384736506ca63bc336d54d3e2c2c19`. The independent review's test-only
amplification-spy gap is closed: removing the early guard produced the targeted
failure, restoring the exact production bytes passed. Main's fresh frozen
baseline-plus-parser run passed **350/351**, one existing Windows symlink skip,
28.483s; active uncommitted readiness tests were explicitly excluded from that
run. All-source typecheck and production-graph build passed. Hash/shape checks
still do not authenticate a launch, current lease, image or material provider.

New generated Rust health-wire coverage is committed as
`79de522af44702cd726cb097428acdfc8eb1a4d3`: **6/6**, 0.01s, and targeted Clippy
with warnings denied passed in 5.46s. It preserves 1/7/999-us stages, optional
zero uncertainty and uint64 values above 2^53 through strict ProtoJSON and
protobuf round trips. This is wire regression coverage, not a readiness owner.

The new `--suite startup` initially passed both old and new images because its
negative cases lacked caller identity. That result did not prove profile
refusal. The corrected suite supplies five otherwise-valid fixed identity
entries to every case. Main's actual old-image replay (`521d...` above) now
fails correctly: default production expected exit1 but observed exit0; it
cleans that exact owned container and starts no further cases. The actual
new-image replay (`eebc...` above) passes **8/8**, with all confinement and
owned cleanup checks. Corrected helper suite: **206/206**, 1.106s; independent
spec/quality review closes the identity-confounding finding.

The reviewed seven-file startup harness is committed as `3679446`.

The suite preserves the original entrypoint and reports both
`readinessVerified: false` and `protocolHandshakeVerified: false`.
Configured managed health, authenticated launch ownership, real enforcement,
end-to-end microsecond traces and release gates remain incomplete. No merge,
push or GitHub CI result is claimed.

## Runtime continuation

See [runtime evidence](mcp-gateway-runtime-evidence.md) for the reviewed readiness
lifecycle checkpoint and subsequent runtime work; aggregate gates remain open.
