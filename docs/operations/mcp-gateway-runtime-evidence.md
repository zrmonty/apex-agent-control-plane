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
