# Working MCP gateway release evidence

## Current status: registry only; release gate failed

This ledger covers the acceptance registry portion of [task 1](../superpowers/plans/2026-09-04-working-mcp-gateway-01-control.md) and the matrix in [task 21, subplan 04](../superpowers/plans/2026-09-04-working-mcp-gateway-04-operator-release.md).
All 15 required live cases are registered and **unimplemented**. Selecting any case produces `ACCEPTANCE_NOT_IMPLEMENTED`, a failed result and exit 1. No case is counted as skipped or passed.
This does not complete task 1's contracts, task 21's live runners, any G0-G3 gate, or the [implementation plan](../superpowers/plans/2026-09-04-working-mcp-gateway.md).

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
