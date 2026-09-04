# Task 1 Report: Versioned MCP Proxy Contract

## Implementation

- Added `contracts/proto/apex/v1/mcp_proxy.proto` with the versioned `McpProxyService` contract and the required RPC surface: `CreateProxy`, `GetProxy`, `ListProxies`, `UpdateProxyDraft`, `ValidateProxy`, `DiscoverUpstream`, `TestProxyConnection`, `PublishProxyRevision`, `DeployProxy`, `PauseProxy`, `ResumeProxy`, `RotateProxyCredentials`, `RollbackProxy`, `RetireProxy`, and `ListProxyActivity`.
- Modeled the contract around the approved design boundaries:
  - `workspace_id`, `namespace_id`, and `proxy_id` scope fields.
  - optional UUIDv7 `request_id` idempotency keys on mutating calls.
  - immutable `revision_id` / `expected_revision_id` fields for optimistic concurrency.
  - opaque `page_token` / `next_page_token` pagination cursors.
  - lifecycle state and redaction state enums.
  - secret references only, not secret values.
- Registered the new proto in `apps/control-plane-api/build.rs` so tonic/prost generates the proxy client/server types.
- Added the Task 1 fixture/test setup in `apps/control-plane-api/src/proxy/tests.rs` and the minimal `apps/control-plane-api/src/proxy.rs` test module hook.
- Added the `mod proxy;` hook in `apps/control-plane-api/src/lib.rs` so the test module is compiled and exercised with the crate tests.

## Tests And Results

- Baseline before changes:
  - `cargo test -p apex-control-plane-api --lib --no-default-features`
  - Result: passed, 130 tests green.
- Focused red step:
  - `cargo test -p apex-control-plane-api --lib --no-default-features`
  - Result: failed as expected because `proto::CreateProxyRequest` did not exist yet.
- Focused green step:
  - `cargo test -p apex-control-plane-api --lib --no-default-features`
  - Result: passed, 133 tests green.

## TDD Evidence

- RED:
  - `error[E0425]: cannot find type CreateProxyRequest in module proto`
  - `error[E0422]: cannot find struct, variant or union type CreateProxyRequest in module proto`
- GREEN:
  - `Finished test profile ...`
  - `running 133 tests`
  - `test result: ok. 133 passed; 0 failed`

## Files Changed

- `contracts/proto/apex/v1/mcp_proxy.proto`
- `apps/control-plane-api/build.rs`
- `apps/control-plane-api/src/lib.rs`
- `apps/control-plane-api/src/proxy.rs`
- `apps/control-plane-api/src/proxy/tests.rs`

## Self-Review

- The new contract stays separate from the existing `ControlGateway` boundary.
- The fixture uses lowercase UUIDv7-looking IDs and keeps the idempotency key shape explicit.
- No later domain, storage, lifecycle runtime, or UI behavior was implemented.
- No raw secrets were introduced; the contract uses secret references only.
- All changed source/test files remain well below the 600-line ceiling.

## Concerns

- The contract is intentionally broad enough for later lifecycle work, so the follow-on implementation tasks will need to keep the server-side semantics aligned with this proto without widening the boundary.
- The worktree already contained unrelated untracked files outside this task (`.superpowers/sdd/2026-09-04-mcp-proxy-control-plane/` and `apps/mcp-gateway/pnpm-workspace.yaml`); they were left untouched.

## Round 1 Fix

- Changed `request_id` on the mutating proxy RPC request messages from `optional string` to required `string`, with comments stating that the server must reject empty, missing, or non-UUIDv7 values before state changes.
- Added `expected_revision_id` guard fields to `DeployProxyRequest`, `PauseProxyRequest`, `ResumeProxyRequest`, `RotateProxyCredentialsRequest`, `RollbackProxyRequest`, and `RetireProxyRequest`.
- Changed `PublishProxyRevisionRequest` to use `draft_revision_id` instead of accepting an inline `McpProxySpec draft`, while preserving `expected_revision_id` as the optimistic concurrency guard.
- Kept the declarative governance binding fields unchanged.
- Strengthened `apps/control-plane-api/src/proxy/tests.rs` with `request_id_is_valid()`, which rejects empty and non-v7 IDs and checks canonical lowercase UUID spelling.
- Focused red/green evidence:
  - Red compile: `cargo test -p apex-control-plane-api --lib --no-default-features`
  - Failure before the proto update: `expected Option<String>, found String` for `CreateProxyRequest.request_id`.
  - Green compile: `cargo test -p apex-control-plane-api --lib --no-default-features`
  - Result after the fix: `running 134 tests` and `test result: ok. 134 passed; 0 failed`.
- Line-limit check:
  - `apps/control-plane-api/build.rs` = 21 lines
  - `apps/control-plane-api/src/lib.rs` = 110 lines
  - `apps/control-plane-api/src/proxy.rs` = 2 lines
  - `apps/control-plane-api/src/proxy/tests.rs` = 90 lines
  - `contracts/proto/apex/v1/mcp_proxy.proto` = 460 lines
  - `task-1-report.md` = 58 lines
