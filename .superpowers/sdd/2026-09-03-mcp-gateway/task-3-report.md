# Task 3 Report

Date: 2026-09-03
Commit SHA: `673a09c6dd6abef3c4ea47771a6c861357e56bfb`
Base: `59a839d`

## Scope Delivered

Implemented Task 3 for the thin TypeScript MCP gateway plan inside `apps/mcp-gateway`:

- Added a deterministic local read-only portfolio adapter.
- Added the exact `RawPortfolioRecord` and public filtered portfolio view types.
- Added an explicit allowlist filter that constructs the public view field-by-field.
- Enforced fail-closed filtering for unsupported restrictions, missing required fields, and non-finite numeric values.
- Preserved safe error behavior by avoiding requested portfolio identifiers in adapter failures.
- Kept raw fixture data private to the adapter and tests.

## Files Changed

- `apps/mcp-gateway/src/adapters/portfolio.ts`
- `apps/mcp-gateway/src/adapters/portfolio.test.ts`
- `apps/mcp-gateway/src/filtering.ts`
- `apps/mcp-gateway/src/filtering.test.ts`

## RED Verification

Command attempted per brief:

```powershell
pnpm test -- src/adapters/portfolio.test.ts src/filtering.test.ts
```

Result:

- Did not reach test execution.
- The local `pnpm` wrapper attempted `pnpm install` first and failed on ignored build-script policy for `esbuild`.
- Error included: `[ERR_PNPM_IGNORED_BUILDS] Ignored build scripts: esbuild@0.28.2`

Equivalent direct runner used to obtain the required red test signal without changing workspace policy files:

```powershell
node ./scripts/run-tests.mjs src/adapters/portfolio.test.ts src/filtering.test.ts
```

Result:

- Exit code: `1`
- Failure mode matched the missing implementation:
  - `Cannot find module ... src/adapters/portfolio.js`
  - `Cannot find module ... src/filtering.js`

This confirmed the tests were failing for the expected missing-feature reason.

## GREEN Verification

Focused tests:

```powershell
node ./scripts/run-tests.mjs src/adapters/portfolio.test.ts src/filtering.test.ts
```

Result:

- Exit code: `0`
- `6` tests passed, `0` failed

Package regression tests:

```powershell
node ./scripts/run-tests.mjs
```

Result:

- Exit code: `0`
- `12` tests passed, `0` failed

Typecheck:

```powershell
node ./node_modules/typescript/bin/tsc --noEmit -p tsconfig.json
```

Result:

- Exit code: `0`
- No type errors

## Implementation Notes

### Portfolio Adapter

- Exposed only a `read(input: PortfolioReadInput)` method via `PortfolioAdapter`.
- Seeded a single in-memory `northstar-401k` record.
- Returned a deep-frozen cloned record per read for deterministic, immutable access.
- Raised `GatewayError("ADAPTER_FAILED", "portfolio record unavailable")` for unknown portfolios.

### Filtering Boundary

- Defined `RawPortfolioRecord`, `PortfolioPublicView`, and `FilterResult`.
- Constructed the public view only from the allowlisted output fields:
  - `portfolioId`
  - `asOf`
  - `baseCurrency`
  - `totalValue`
  - `client.displayName`
  - `positions[].symbol`
  - `positions[].quantity`
  - `positions[].marketValue`
- Recorded only supported restricted raw-field paths in stable input order:
  - `client.account_number`
  - `client.tax_id`
  - `positions.cost_basis`
- Rejected unsupported field restrictions with `FILTERING_FAILED`.
- Rejected missing required strings and non-finite numbers with `FILTERING_FAILED`.
- Computed `sourceBytes` and `filteredBytes` from serialized JSON payload sizes.
- Deep-froze the filtered public view before returning it.

## Concerns / Deferred Items

- The brief-specified `pnpm test -- ...` command is currently blocked in this worktree by the existing `pnpm` build-script approval policy, so direct package runners were used for verification instead of modifying unrelated workspace policy files.
- Task 3 did not integrate the adapter/filtering boundary into a higher-level execution pipeline because the brief scoped this task to the adapter and filtering layer only.

## Review Fix Round 1

Date: 2026-09-03
Review base commit: `673a09c6dd6abef3c4ea47771a6c861357e56bfb`

### Findings Addressed

- Validated all required `RawPortfolioRecord` fields before constructing the public view, including restricted private fields `client.account_number`, `client.tax_id`, and `positions.cost_basis`.
- Added explicit object/array guards so malformed `raw.client`, `raw.positions`, and malformed position entries fail with safe `GatewayError("FILTERING_FAILED", ...)` instead of native `TypeError`.
- Rejected mismatched `input.asOf` requests in `LocalPortfolioAdapter.read()` with a safe `ADAPTER_FAILED` error.

### Additional Files Updated

- `apps/mcp-gateway/src/adapters/portfolio.ts`
- `apps/mcp-gateway/src/adapters/portfolio.test.ts`
- `apps/mcp-gateway/src/filtering.ts`
- `apps/mcp-gateway/src/filtering.test.ts`

### RED Verification

Focused regression command:

```powershell
node ./scripts/run-tests.mjs src/adapters/portfolio.test.ts src/filtering.test.ts
```

Result before fix:

- Exit code: `1`
- `5` tests failed, `6` passed
- Confirmed failures:
  - mismatched `asOf` request was incorrectly accepted
  - hidden `client.tax_id` missing was incorrectly accepted
  - hidden `positions.cost_basis` non-finite was incorrectly accepted
  - malformed `client` structure produced a non-`GatewayError`
  - malformed `positions` entry produced a non-`GatewayError`

### GREEN Verification

Focused regression command:

```powershell
node ./scripts/run-tests.mjs src/adapters/portfolio.test.ts src/filtering.test.ts
```

Result after fix:

- Exit code: `0`
- `11` tests passed, `0` failed

Full package tests:

```powershell
node ./scripts/run-tests.mjs
```

Result:

- Exit code: `0`
- `17` tests passed, `0` failed

Typecheck:

```powershell
node ./node_modules/typescript/bin/tsc --noEmit -p tsconfig.json
```

Result:

- Exit code: `0`
- No type errors

### Concerns / Deferred Items

- The unrelated untracked file `apps/mcp-gateway/pnpm-workspace.yaml` remains untouched.
- The `pnpm test -- ...` wrapper issue remains unchanged; direct package runners were used again to preserve task scope.
