# Working MCP gateway: runtime evidence

Continuation of the [release evidence ledger](mcp-gateway-release-evidence.md).
These are bounded implementation checkpoints, not aggregate release acceptance.

## Task 6E: readiness lifecycle — 2026-09-05

Tested and committed source: `6dafe00d78db7a8aa54845b17f6232bbff42bd39`,
branch `codex/working-mcp-gateway`. Thirteen handwritten source/test files,
1,281 physical lines total, maximum 313 per file. Same Windows/Node 24 fixture
environment and unchanged actual Rust export as the parent ledger.

- Nine mandatory checks bind to an independently copied configuration/launch;
  hashes and synthetic component owners do not authenticate that launch.
- One sweep, four underlying operations maximum, 2s deadline, at most 5s cleanup
  grace, minimum 5s sweep cadence and maximum 10s local evidence age, shortened
  by owner expiry. Cancellation retains ownership until actual I/O termination.
- Cached reads do no probe I/O and preserve observation time. Timing stages
  retain integer nanoseconds, microseconds, process/source/resolution and optional
  uncertainty; 1/7/999us and values above JavaScript's safe-number range survive.
- Independent review found callback-shutdown ownership and aliased-test-fixture
  gaps. Executable regressions reproduced both, plus nested startup replacing
  pending ownership. Fixes passed re-review; those findings are closed.

Fresh main verification after the corrective changes:

```powershell
$env:APEX_RUNTIME_FIXTURE_PATH = 'C:/Users/zrmon/AppData/Local/Temp/apex-health-wire-1123e8d8aa224f4d89f1365cd70a3cc1/collected-runtime-revision.json'
pnpm --dir apps/mcp-gateway test
pnpm --dir apps/mcp-gateway typecheck
pnpm --dir apps/mcp-gateway build
```

Full gateway: **392 total, 391 passed, one existing Windows symlink skip,
zero failures, 29.704s**. Typecheck/build passed. The component's 41 tests include
actual loopback socket termination and a direct child with real unresponsive
socket I/O: required fatal exit 73, bounded runner cleanup and PID disappearance.
That watchdog uses shortened component bounds; exact default timing edges use
controlled clocks/timers. Neither proves hard-real-time or deployed shutdown.

No production probe owners, authenticated HTTP health listener, secure health
credential loader, runtime-agent authority or admission wiring are supplied by
this commit. The private report builder is not an incoming-report validator;
that shared codec is the next slice. Managed composition still fails closed.
No image rebuild, configured-health image proof, end-to-end MCP trace, G0-G3
completion, merge or push is claimed by this checkpoint.

## Task 7A: pure runtime-agent boundary — 2026-09-05

Source: `b5d03917bc58289c7f3d425c7f0ed0a1ad2e02fe`. Fifteen package files,
maximum 315 handwritten lines per file, plus workspace/lock integration.
The lock change adds one package entry; existing package versions are unchanged.
Canonical runtime Protobuf types are generated independently with the shared
redacted codec, without importing the control-plane application.

Pure checks validate exact target/configuration relations and a bounded Docker
identity/state projection against an explicitly unverified immutable expectation.
Inspection is capped at 65,536 UTF-8 bytes, depth 32 and 64 unique bounded labels;
missing/duplicate identity fields refuse. Only validated identity and a closed
engine state are returned, never ignored environment/mount/error data.

Main observed the initial semantic RED: 20 passed / 20 failed against stubs.
A descriptor filename compile error preceding it was setup failure, not RED.
Independent review later found a v1 image-name compatibility refusal; both
underscore and trailing-dot positives reproduced it (1 pass / 2 failures).
The correction reuses the already-locked URL parser and preserves digest,
repository and exact-origin restrictions. Independent re-review closed the gap.

```powershell
$env:CARGO_TARGET_DIR = 'E:/Agent Control Plane/target'
cargo test --locked --offline -p apex-proxy-runtime-agent --test runtime_boundary
cargo clippy --locked --offline -p apex-proxy-runtime-agent --all-targets -- -D warnings
cargo fmt -p apex-proxy-runtime-agent -- --check
```

Fresh corrected results: **43/43**, zero ignored, 0.01s tests; locked rerun
compile 0.23s. All-target Clippy passed (7.05s); scoped formatting passed.
The separate workspace-wide formatting check failed on 97 existing Rust files,
none in this new crate. It changed no files and remains release-cleanup debt,
alongside the parent ledger's unresolved cargo-deny license-policy finding.

This is not an authenticated ownership, current-lease, image-signature, staging,
engine-operation, readiness or admission implementation. Generated wire tests use
the canonical fixture with synthetic values, not the real exporter artifact:
its runtimeManifestHash differs. Real producer/agent compatibility and the legacy
provider regression must be verified before provider replacement. Task 7, G1
and aggregate release acceptance remain open; no merge/push/CI run is claimed.

## Task 6F: bound report codec — 2026-09-05

Source: `09c04fa56432d0649d7f04f237a8692b17dae809`. Fourteen files, 1,144
physical lines total, maximum 316 per file. Eleven are new; existing changes
are limited to monitor publication, the shared stage-name list, and explicit
optional uint64 presence in descriptor validation.

`ReadinessReportCodec` binds once to independently copied/revalidated generated
configuration and launch metadata. Both encode and original-text decode share
one semantic checker: exact six-field target and four digest/instance bindings,
nine unique checks, valid status/reason pairs, and complete successful stages for
ready reports. Non-ready initial/stale/shutdown reports remain representable.
The trusted caller still owns launch authentication, current lease and freshness.

Original UTF-8 is capped at 8,192 bytes before parsing, preserving duplicate,
alias and strict integer-string checks. Generated data rejects active objects
before descriptor/encoding work; final encoded text is also bounded. Optional
uncertainty preserves absence versus zero, durationNs is required, and bigint
division retains exact microseconds plus the original nanosecond remainder.
Readiness has no trace-context owner yet; arbitrary trace/span IDs are refused,
not replaced with fabricated IDs or advertised as end-to-end tracing.

Independent review found a test-strength issue: later shape rejection could mask
removal of the early size guard. The corrected test observes descriptor entry
and all serialization, with restored instrumentation and a valid positive.
Single-guard removal produced RED (0/1); exact source restoration produced GREEN
(1/1). Re-review closed the finding; no production behavior correction was needed.

Main reran the same actual Rust artifact and three gateway commands shown above
after that final correction: **417 total, 416 passed, one existing Windows symlink
skip, zero failures, 29.854s**; typecheck and production build passed. The 66
readiness/codec tests include the existing real socket/direct-child ownership
checks. The codec owner separately verified 27 existing consumer/preflight tests.
The exact 8,192-byte incoming positive uses legal trailing whitespace; no claim
is made that the fixed canonical report can reach that exact output size.

This commit provides no HTTP listener/probe, secure credential loading, runtime
authority, network enforcement or admission owner. Those integrations remain
open and managed composition still refuses unavailable enforcement. No image
rebuild, configured-health image acceptance, aggregate gate, merge or push claim.

## Task 7B1/7C: peer policy and shared manifest — 2026-09-05

Source: `d65227683dbb69d611dd32844a76dd9ce2bd5286`. Twenty-three source,
test and dependency files; 2,760 insertions and 28 deletions. Largest changed
handwritten file is 374 lines. The lock adds nine dependency edges without
changing existing package versions. Both slices passed independent review.

The compiler and separately generated runtime-agent wrapper share the existing
v1 manifest algorithm: recursively sorted generated ProtoJSON, array/schema-text
order preserved, only the root self-hash omitted. Encoding failures stay static
and fallible. Publication, image signatures and authority are separate checks.
Main observed shared-helper RED (1 pass/7 fail) and agent RED (1 pass/5 fail),
then verified compiler delegation without changing the actual exported bytes.

Fresh post-delegation producer artifact:
`C:/Users/zrmon/AppData/Local/Temp/apex-runtime-fixture-01a070bb-3c74-7c33-8cf8-dbfeecbab8fb/runtime-revision.json`,
3,632 bytes, SHA-256
`970cfd7a059a4761fc8b4ad6f8f9d5dd4f4f4f4c4f2d16995cde807d20fdd554`.
Manifest: `db5ddc4670e5f901240e1c2910d9f78dd8a65237c86f197d13938be967afe5da`.
Producer tests: 18/18; actual-artifact TypeScript consumer/preflight: 27/27,
250.285ms. The repository fixture was not substituted for that artifact.

The new shared peer policy strictly parses original JSON under a 64KiB/depth32
bound and rejects ambiguous fields, malformed pins/identifiers, conflicting
rotations and noncanonical integer timestamps. Authorization uses the actual
TLS leaf, exact registered role and one installation/workspace/namespace tuple.
Every public check samples local integer Unix microseconds with checked overflow
and inclusive-start/exclusive-expiry semantics. The borrowed result cannot outlive
its policy, but holding it does not keep that policy current.

Main semantic RED: 31 pure cases, 14 pass/17 fail; eight actual TLS cases,
0 pass/8 fail. Valid policies hit the refusal stub and real TLS reached its
handler; most deeper assertions were not independently RED at that checkpoint.
Fresh GREEN: full auth49/49 plus lifetime compile-fail doc1/1; agent boundary43,
manifest6 and actual TLS8 all passed with zero ignored. Tests cover valid peers,
wrong/no certificates, wrong roles, revoked/unlisted leaves, exact-scope isolation,
spoofed metadata and stale/future policies. Test acknowledgments never claim
ready/admitting/connected. Existing PKI was reused without regeneration.

Scoped formatting and warnings-denied Clippy passed; the tracked-source 600-line
checker passed after staging. Existing supervisor verification also passed:
23 unit tests, one real credential-isolation case and one Windows direct-child
termination case. This does not establish Unix process-group behavior on Windows.

These libraries do not load current deployment policies, enroll an installation,
authenticate a current operation/worker/fence, verify image signatures, stage
secrets or operate containers. Microsecond representation is preserved here,
not certified as calibrated cross-host accuracy or an end-to-end MCP trace.
Task7, managed serving and aggregate release gates remain open.

## Task 7D: CI coverage for shared boundaries — 2026-09-05

Source: `68d8d7767d065261b56864044cb5737e981bff7d`. Twelve workflow lines
and a 131-line dependency-free Node source-contract suite. The existing cached
Rust control-plane job runs domain/auth/runtime-agent package tests and all-target
Clippy after collecting the real export, reusing its PKI. No extra Rust job,
exporter run, certificate generation, dependency upgrade or policy waiver.

Owner source-contract RED: 2 pass/5 fail; unchanged tests then passed7/7.
Main rerun: 7/7, 50.7842ms, plus full YAML parse: 12jobs/four added Cargo commands.
Main executed those exact commands from the configured application directory,
with local fixture/target paths:

```powershell
cargo test --locked -p apex-domain
cargo test --locked -p apex-auth
cargo test --locked -p apex-proxy-runtime-agent
cargo clippy --locked -p apex-domain -p apex-auth -p apex-proxy-runtime-agent --all-targets -- -D warnings
```

Results: domain17, auth49+doc1, agent43+6+8 = **124 passed, zero ignored**;
combined Clippy passed (0.51s). This is local Windows execution, not a GitHub
Actions run, all-feature/full-workspace proof or a pipeline speed benchmark.
No merge or push was performed; unrelated runtime work remains separate.

## Task 7B2: current PostgreSQL operation snapshot — 2026-09-05

Source: `aff8ae38c32158e2aaaa738946be5b49db1bbf43`. Fifteen source/test
files, maximum 553 physical lines (maximum new file 261), independently reviewed.
No schema, wire, dependency, startup, provider or runtime-effect changes.

`read_current_runtime_operation` validates exact scope/typed IDs/worker and
checked SQL-width generation/fence before accessing the connection. One
transaction locks the scoped proxy and exact unexpired lease, independently
compares stored operation columns with its bounded protobuf, and verifies the
current revision/generation/desired state. Publication and the existing control
hash algorithm are checked against the actual stored spec. A final database
microsecond expiry check follows all validation; success returns after commit.
The lookup neither issues/renews a lease nor changes durable application rows.

The shared live-lease predicate preserves journal observation order and exact
terminal-event retries. The returned snapshot is copyable point-in-time data,
not an authenticated caller, enrollment record or reusable execution permit.

Main semantic RED: 0 passed/18 failed/zero ignored, 7.10s. Seventeen tests
stopped at their first valid positive, so deeper branches were not independently
RED. Frozen tests then passed against the real owned PostgreSQL fixture:

```powershell
cargo test --locked --offline -p apex-control-plane-api --features postgres --test proxy_runtime_operation -- --test-threads=1
```

GREEN: **18/18**, zero ignored, 27.50s. Coverage includes two-connection takeover,
reconnect, busy/locked storage, unchanged seven-table snapshots, malformed or
inconsistent stored data, legacy target changes and terminal operations. The
final-expiry case observes a valid lease while blocked at the actual revision
query, releases after database expiry and requires NOT_CURRENT rather than a
transport timeout. It does not claim two reads sampled the identical microsecond.

Existing regressions with `test-support,postgres,valkey`, serial execution:
journal **24/24**, 3.40s; recovery **21/21**, 33.10s (17 real cases plus four
child-entry helpers). Default and all-feature/all-target control-plane Clippy
passed with warnings denied (4.92s/9.42s); exact owned Rust formatting passed.
No full workspace suite or GitHub Actions run is inferred.

Authentication, current policy, installation enrollment, bounded whole-job
dispatch/cancellation and lease-to-engine race handling remain integration gates.
No runtime command calls this API yet. Full Task7, serving, end-to-end tracing
and aggregate release acceptance remain incomplete; no merge/push performed.

## Task 6G: authenticated loopback health transport — 2026-09-05

Source: `6c4cc952f1dd5608dacc533dd30665c87d8040ed`. Thirteen new files,
962 physical lines total, maximum172, independently reviewed. No production
root/factory, startup parser, readiness owner/codec or process-runner changes.

The server binds only `127.0.0.1:8081`. Exact authenticated HTTP/1.1 `/livez` and
`/readyz` requests use one cached snapshot and one bound encoding. Authentication
requires the dedicated32-byte token and canonical Bearer encoding; malformed,
ambiguous, duplicate, oversized, body-bearing or pipelined envelopes cannot
start probes. Responses preserve the original observation and integer stages,
with empty static failures instead of raw diagnostics or secrets.

The client probes only that fixed loopback endpoint, with no caller URL, proxy
configuration, redirects or retries. Strict bounded framing and original UTF-8
reach the same8KiB bound codec. Server/probe own their token copies and socket
cleanup; absolute2s work limits cannot be extended by trickling activity. The
server has at most8 tracked sockets and5s cleanup grace; the probe requires
actual close notification within1s or reports failure. Failure does not pretend
an unresponsive socket was gracefully closed. Timers require a progressing
event loop; this is not a hard operating-system deadline.

Owner incremental tests recorded actual refusals before implementation, while
separately identifying already-working delegated behavior. Final focused
transport suite: **19/19**, zero ignored, 8.124s, over real HTTP/raw sockets and
the actual Rust artifact with explicitly synthetic launch/probe owners.
Independent review found a masked current-binding-loss assertion. The corrected
test first proves a fresh200, changes only currentness and requires503 with nine
decoded MISMATCH reasons, unchanged observation/stages and no extra probe starts.
Re-review closed the finding; no production change was needed.

Main fresh post-correction commands using the actual export listed under7B1/7C:

```powershell
pnpm --dir apps/mcp-gateway test
pnpm --dir apps/mcp-gateway typecheck
pnpm --dir apps/mcp-gateway build
```

Results: **436 total,435 passed, one existing Windows symlink skip, zero
failures,29.866s**; typecheck/build passed. Exact staged hashes/whitespace and
tracked-source600-line checks passed. Two checked-in child cases cover real
socket lifetime and cleanup/refusal with exact owned-process reap assertions.

Main additionally ran the fixed `watchdog-child.ts actual-grace` under a bounded
9s execution/1s reap parent with4KiB output caps: actual5,120ms cleanup grace,
required fatal exit73, empty stderr and exact PID45628 reaped/ESRCH. The held
destroy hook deliberately remained unresponsive (`closed=false`); this proves
fatal process termination, not graceful socket completion. That separate parent
was a manual acceptance command, not a checked-in CI long-grace test.

These uncomposed libraries are not yet imported by the production build entry.
Secure material loading, authenticated launch/currentness, real network/admission
owners, executable probe packaging and configured-health image acceptance remain
required. No deployed readiness, end-to-end tracing, aggregate gate, GitHub
Actions run, merge or push is claimed.

## Check-only authority wire and peer-pair checkpoint — 2026-09-05

Source checkpoint: `b9540048f58e7df439ed2cde1ef743a933dcfe95`.

The separate `RuntimeAuthorityService.CheckRuntimeAuthority` contract has one
check-only action, seven request fields and sixteen snapshot fields. Existing
RuntimeTarget fields, browser management allowlist and event contracts remain
unchanged. It carries no engine action, secret material or reusable permit.
The shared pair check authenticates the actual TLS Agent and checks its observed
Controller pin against the same policy/time/exact scope. That observation is an
Agent attestation, not proof the Controller signed the callback.

The control-plane generator now selects the existing shared redacted protobuf
codec for all generated clients/servers. Valid encoding is unchanged; malformed
protobuf payloads receive the static InvalidArgument envelope error instead of
Internal with prost message details. One existing dependency edge was added;
no dependency versions changed. Framing/header/application errors outside the
protobuf decoder are not covered by this redaction claim.

The eighteen wire/codec files and nine peer-pair files passed separate independent
reviews with no remaining findings. Verification includes 94 generated-contract
tests and reproducible generation/compatibility, independent Rust wire assertions,
64 auth units, four compile-fail doctests and actual mTLS pair controls. Three
actual malformed-RPC tests exercise the new server, new client and legacy
SubmitCommand decoder with healthy-before/after controls and listener cleanup.
Temporarily restoring the old codec produced three expected failures; restoring
the shared redacted codec passed all three. Integer tests retain 1/7/999us
differences above 2^53 and across the full uint64 wire range.

The live authority service, deployment-policy reader, enrollment, bounded PG
worker/cancellation and startup registration are not included. No generated
contract or borrowed identity view establishes serving or execution authority.

## Task 6H1: fixed Linux health-material loader — 2026-09-05

Source checkpoint: `dba56cec691f15711f43624ba6c54de4380a0187`.

Thirteen new source/test files, 1231 lines total, maximum273. The uncomposed
loader reads only `/run/apex/runtime` configuration, launch metadata and a
canonical43-byte health token under the explicit Linux UID/GID10001,0400,
regular-file/nlink1 contract. Required O_NOFOLLOW/O_NONBLOCK and same-descriptor
metadata checks have no weaker fallback. Complete generated configuration and
launch values must equal the independently supplied expected binding before
token acquisition. Immutable ancestry and material provenance are trusted
integration preconditions, not inferred from those local checks.

One process job owns pending reads, closes and writable buffers until actual
cleanup. Cancellation or a fatal callback cannot authorize replacement. The
absolute2s work/5s cleanup observations use monotonic time; fatal notification
does not pretend an unresponsive OS operation terminated. Returned token bytes
are explicitly owned and disposable, without claiming erasure of all native/GC
copies. Generated integer metadata never passes through JavaScript Number.

Independent review found two P2s: an early one-shot cleanup timer could lose
fatal escalation, and a Clock callback could invalidate ownership after its
last check. Targeted tests first produced40 pass/10 fail; cleanup-only41/9;
both corrections50/50; final strengthened tests51/51. Scoped re-review closed
both findings and an inaccurate role-test label. MAIN then independently ran:

- Focused loader51/51, zero skips,678.6071ms.
- Full gateway487 total:486 pass, one existing Windows symlink skip, zero
  failures,33.2613271s; typecheck and production build passed.
- Rebuilt Docker `build` target image
  `sha256:1c3fa49d0c8498d8f6136c04ca02053fca2941e48559cdf2a1a20757043afac7`.
  This is a verification build image, not a final production-image claim.
- Actual native Linux15/15: valid and exact JSON caps, overflows, symlink,
  hardlink, FIFO, UID/GID/mode, missing/short/newline/noncanonical token.
  Each used an independent actual Rust artifact and synthetic expected owner,
  fixed mounts, non-root execution, read-only root/staged volume, no network
  and restricted capabilities. All owned containers/volumes were removed and
  absence checked; unresolved cleanup0.

Trusted credential staging, authenticated currentness, fatal-process supervision,
real network/admission probes and production composition remain open. These
checks do not complete Tasks6/7, end-to-end tracing or aggregate G0-G3 gates.

## Merge-checkpoint packaging and regression checks — 2026-09-05

The final production image was also rebuilt as
`sha256:644ceae35bb4f1be664a18cde70f6696fb1acc47bc3b2615103abb6768197f4c`.
The existing packaging suite passed (35 files, zero test artifacts/private-key
files); all eight original-entrypoint startup cases passed. Both reports retain
`readinessVerified: false`; startup retains `protocolHandshakeVerified: false`.
They establish packaging and truthful profile refusal, not live MCP serving.

UI tests passed305/305 with typecheck/build. The combined Node workflow,
browser-journey-helper and image-harness tests passed408/408. Source-line
checker tests passed4/4 and the tracked600-line and lab-only-settings checks
passed. The Python check initially hit the documented Windows shared-temp ACL
problem; a new private temp root resolved setup without changing repository code.
Likewise, one main Rust command omitted the mandatory PKI fixture variable;
the complete shared-package rerun with explicit PKI/artifact passed. Neither
setup failure is a semantic implementation RED or a production fix.

The full control-plane test command with `test-support,postgres,valkey` and
serial execution passed using the existing real PostgreSQL and Keycloak
fixtures. This includes576 library and79 startup tests, plus the integration
targets. Existing optional live tests can return early when their separate
environment switches are absent; this is not full deployment-gate acceptance.
One earlier run failed the existing refresh fixture's transport-error counter
after the positive token-rotation assertions. The focused rerun and complete
rerun passed. Temporary static-only diagnostics did not reproduce a failure
label and were removed; a further unmodified refresh suite passed5/5. No root
cause or fix is claimed for that intermittent fixture result.

Final authority codec/contract tests passed3/3 and9/9; control-plane
all-feature/all-target Clippy passed with warnings denied. The durability
all-feature library suite passed116/116, subject to its existing optional-live
environment gates. Local checks do not claim a completed GitHub Actions run.
