# Final MCP Gateway Fix Report

Date: 2026-09-03
Branch: `codex/mcp-gateway`
Base reviewed: `5e618c79cbb770d5efef09a78dfa459ee021f153`

## Summary

Resolved all five confirmed findings from the final whole-branch review while preserving the thin, read-only gateway design. The gateway still exposes exactly one `portfolio.read` tool over stdio, derives identity and scope only from injected authenticated context, and keeps live Apex/HTTP/operator wiring deferred.

The pre-existing untracked `apps/mcp-gateway/pnpm-workspace.yaml` was not edited or staged.

## Findings Resolved

### 1. Runtime event-receipt admission

- Added an exact, strict `EventReceiptSchema`.
- Required lowercase UUIDv7 identifiers with the same shape accepted by Rust `is_lowercase_uuidv7`.
- Validated every fulfilled `ApexEvents.emit` response on allowed, denied, and approval-required paths.
- Allowed calls now return `EVENT_ADMISSION_FAILED` for `null`, `{}`, wrong UUID versions, uppercase UUIDs, extra keys, or other malformed receipts and never return portfolio data.
- Denied and approval-required calls preserve their original result when event admission or receipt validation fails and record only `EVENT_ADMISSION_FAILED` through safe telemetry.
- Replaced the local `evt-<UUIDv4>` receipt with a standards-shaped UUIDv7 generated from the current Unix-millisecond timestamp and random bits.

### 2. Telemetry failure containment

- Added a non-throwing telemetry guard at the denied-event failure boundary.
- A throwing `SafeTelemetry.record` can no longer reject the executor or leak exception text.
- Added an in-memory MCP client/server regression where both event admission and telemetry throw; the response remains the stable `AUTHORIZATION_DENIED` result.
- Added explicit malformed-receipt coverage for both denial and approval-required outcomes.

### 3. Stable transport validation

- Kept `PortfolioReadInputSchema` as the strict advertised tool schema, including `additionalProperties: false` and only `portfolioId`/`asOf` properties.
- Installed a narrow raw `tools/call` handler on the SDK server so the transport-neutral executor performs the authoritative parse and stable error conversion.
- Invalid input through `Client.callTool` now returns exactly `INVALID_INPUT: request rejected safely` without the unknown key name or supplied value.

### 4. Rust-compatible Apex wire contracts

- Reduced `PolicySnapshot` and its strict runtime schema to the canonical Rust shape: exact scope, policy ID, and revision.
- Restored the Rust-required event `resource` field throughout contracts, event construction, local admission, and tests.
- Replaced slash-containing/caller-identifying resources with `portfolio:sha256:<lowercase digest>` references. These are opaque, contain no caller portfolio ID, and satisfy Rust `ResourceName` validation.
- Updated local authorization to compare precomputed opaque resource references rather than extracting portfolio IDs from event-bound metadata.
- Tightened authenticated principal validation to the existing Rust caller boundary.

### 5. Bounded governance and event metadata

- Reused Rust-compatible identifier grammar: non-empty ASCII alphanumeric plus `.`, `_`, `:`, or `-`; no `..`; maximum 256 bytes.
- Bounded field restriction and removed-field arrays to 64 entries.
- Bounded aggregate field-path content to 4096 bytes.
- Bounded total serialized event metadata to 4096 bytes.
- Bounded Rust integer-shaped metadata to JavaScript-safe nonnegative integers and retry count to `u32`.
- Rejected non-empty restrictions on denied/approval decisions to match Rust constructors.
- Governance output violations fail as `GOVERNANCE_UNAVAILABLE` before adapter/filter access.
- Event metadata violations fail as `EVENT_ADMISSION_FAILED` before event sink invocation.
- All returned errors remain code-only and do not echo oversized values, dependency errors, raw inputs, or records.

## TDD Evidence

Focused red command:

```text
node .\scripts\run-tests.mjs src/context.test.ts src/execution.test.ts src/schemas.test.ts src/server.test.ts
```

Before implementation: 13 passed and 15 failed. Failures directly reproduced opaque-resource mismatch, Rust-principal mismatch, missing receipt schema/validation, malformed denied/approval receipt handling, pre-emission size validation, raw SDK validation text, and raw telemetry exception leakage.

Focused green command after implementation:

```text
node .\scripts\run-tests.mjs src/context.test.ts src/execution.test.ts src/schemas.test.ts src/server.test.ts
```

Result: 31 passed, 0 failed.

## Final Verification

From `apps/mcp-gateway`:

- `node .\node_modules\typescript\bin\tsc --noEmit -p tsconfig.json` — passed, exit 0.
- `node .\scripts\run-tests.mjs` — 42 passed, 0 failed.
- `node .\node_modules\typescript\bin\tsc -p tsconfig.json` — passed, exit 0.

From the repository root:

- `cargo test -p apex-domain -p apex-policy` — 15 unit tests passed plus doc tests, 0 failed.
- `cargo clippy -p apex-domain -p apex-policy --all-targets --all-features -- -D warnings` — passed.
- `cargo test --workspace` — passed across the full workspace.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `git diff --check` — passed; only line-ending notices were emitted.

The package-level `pnpm test`, `pnpm typecheck`, and `pnpm build` wrappers were also attempted. Each stopped during the wrapper's automatic install phase because the protected untracked workspace configuration does not approve the `esbuild@0.28.2` build script (`ERR_PNPM_IGNORED_BUILDS`). One concurrent attempt also encountered pnpm's internal lock rename. No policy/configuration file was changed; the equivalent checked-in direct runners above all passed serially afterward.

## Scope and Design Review

- Exactly one tool remains advertised: `portfolio.read`.
- No write, trade, HTTP, live client, operator route, policy database, approval ledger, or audit store was added.
- Execution remains parse -> authorize -> policy -> read -> filter -> emit -> return.
- Allowed data is returned only after a valid durable receipt.
- Denials and approval requirements never execute the adapter.
- Events remain metadata-only and exclude raw prompts, full records, full responses, and caller portfolio IDs.
- Live Apex authorization/event clients and the operator-visible slice remain deferred.

## Files Changed

- `apps/mcp-gateway/README.md`
- `apps/mcp-gateway/src/contracts.ts`
- `apps/mcp-gateway/src/context.ts`
- `apps/mcp-gateway/src/context.test.ts`
- `apps/mcp-gateway/src/execution.ts`
- `apps/mcp-gateway/src/execution.test.ts`
- `apps/mcp-gateway/src/governance/local.ts`
- `apps/mcp-gateway/src/schemas.ts`
- `apps/mcp-gateway/src/schemas.test.ts`
- `apps/mcp-gateway/src/server.ts`
- `apps/mcp-gateway/src/server.test.ts`
- `apps/mcp-gateway/src/telemetry.ts`
- `.superpowers/sdd/2026-09-03-mcp-gateway/final-fix-report.md`
