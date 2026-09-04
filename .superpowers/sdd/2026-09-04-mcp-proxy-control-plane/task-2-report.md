# Task 2 Report: Implement proxy domain types and validation

## Scope

Implemented Task 2 only in:

- `apps/control-plane-api/src/proxy.rs`
- `apps/control-plane-api/src/proxy/validation.rs`
- `apps/control-plane-api/src/proxy/tests.rs`
- `apps/control-plane-api/src/lib.rs`

No storage, lifecycle, runtime, or UI work was implemented.

## RED evidence

### Step 1: failing tests added first

Added focused tests for:

- empty slug
- invalid scope
- unknown transport
- missing credential reference
- empty tool allowlist
- shell-enabled CLI profile
- unbounded timeout
- unbounded output
- private destination without explicit allow rule
- valid read-only `portfolio.read`

### Step 2: focused RED run

Command:

```powershell
cargo test -p apex-control-plane-api proxy::tests --no-default-features
```

Observed RED result:

- initial compile failed because the new proxy domain types and validator did not exist
- after correcting a test-only enum-name typo, the focused RED run failed only on unresolved proxy-domain imports from `src/proxy.rs`

That confirmed the tests were exercising missing implementation rather than passing against existing behavior.

## GREEN evidence

### Implemented domain boundary

Added bounded proxy domain types and validation:

- `ProxyId` and `ProxyRevisionId` as UUIDv7-validated newtypes
- `SecretRef` as a bounded reference type
- bounded enums for transport, lifecycle state, approval mode, data classification, tool classification, and private-destination allowance
- domain records for `ProxySpec`, `UpstreamBinding`, `CliProfile`, `GovernanceBinding`, `ProxyDraft`, `McpProxyRevision`, and `ProxyError`
- fail-closed `validate_proxy_spec(&ProxySpec)`
- `TryFrom<proto::McpProxySpec>` and supporting conversions that reject unsupported transport values before domain use

### Focused GREEN run

Command:

```powershell
cargo test -p apex-control-plane-api proxy::tests --no-default-features
```

Observed GREEN result:

- `14 passed; 0 failed`

Covered passing cases included all required rejection tests plus the valid read-only `portfolio.read` case.

### Line-limit gate

Command:

```powershell
python scripts/test_check_source_line_limits.py
```

Observed result:

- exit code `0`

Current touched file lengths:

- `apps/control-plane-api/src/proxy.rs`: 537
- `apps/control-plane-api/src/proxy/validation.rs`: 242
- `apps/control-plane-api/src/proxy/tests.rs`: 372
- `apps/control-plane-api/src/lib.rs`: 117

## Changed files

- `apps/control-plane-api/src/lib.rs`
- `apps/control-plane-api/src/proxy.rs`
- `apps/control-plane-api/src/proxy/validation.rs`
- `apps/control-plane-api/src/proxy/tests.rs`

## Self-review

- Validation is fail-closed for the required cases: missing upstream credential refs, empty tool exposure, shell-enabled CLI profiles, zero timeout, zero max output, and private IP destinations without an explicit allow rule.
- Task 1 contract assumptions were preserved: request-id fixture tests still assert lowercase UUIDv7 semantics, and this task did not alter lifecycle guard or publish-request behavior.
- Only `SecretRef` references are carried in the new domain types; no raw secret values were introduced.
- The proxy module stayed within the 600-line cap by splitting validation helpers into `src/proxy/validation.rs`.
- An accidental partial `cargo fmt --all` touched unrelated files, but those unrelated changes were restored before commit preparation. The final diff remains scoped to Task 2 files only.

## Concerns

1. The current Task 1 protobuf contract exposes `exposed_tools` as plain strings and `runtime_profile.network_policy` as a plain string, so the Task 2 domain conversion has to infer a default upstream/classification and cannot derive structured destination rules directly from protobuf alone.
2. Because of unrelated repository-wide rustfmt drift, `cargo fmt --all --check` is not a clean signal for this task. Focused verification was done with the targeted test command, the line-limit gate, and a scoped diff/status check.

## Round 1 Fix Report

### Review findings addressed

- Replaced the permissive `repeated string exposed_tools` wire field with structured `McpProxyToolExposure` entries containing `upstream_id`, `tool_name`, `alias`, and `classification`. Conversion now maps and validates every field, rejects empty or unknown values, and validates upstream binding without selecting a default upstream.
- Added structured `McpProxyEgressDestination` entries with host, port, and explicit private-destination allowance. Runtime conversion preserves the network policy string and destination list; an empty destination list now fails closed instead of being inferred from the policy string.
- Expanded the domain model and validator to retain and bound ingress, upstream, tool, CLI, auth, governance, runtime, argv, environment, secret-reference, exit-code, destination, and collection data. `ProxyDraft`, `McpProxyRevision::new`, and protobuf conversion invoke validation at their admission boundaries.
- Uppercase content hashes are rejected. Plain 64-hex catalog/config hashes and `sha256:`-prefixed image/executable digests are validated separately without normalization.
- Added `parse_proxy_spec_wire_json` and `validate_proxy_spec_wire_json` over a serde mirror whose structs use `deny_unknown_fields`. Unknown JSON fields fail before protobuf/domain conversion. The prost conversion remains fail-closed for missing, unsupported, and unsafe known values.
- Governance remains a declarative `GovernanceBinding`; no local policy authority, storage, lifecycle, runtime, or UI behavior was added.

### RED evidence

After adding the review regression tests and changing the generated-contract expectations, before the fix implementation:

```powershell
cargo test -p apex-control-plane-api proxy::tests --no-default-features
```

The compile failed with unresolved `Ingress`, strict wire-parser, revision-validator, and collection-limit symbols, plus the old conversion's type mismatch because `exposed_tools` was now structured. This demonstrated that the new tests and contract shape were not passing against the prior fallback implementation.

### GREEN evidence

After the fix implementation and the hash-format correction:

```text
cargo test -p apex-control-plane-api proxy::tests --no-default-features
running 24 tests
test result: ok. 24 passed; 0 failed
```

The focused library compile also passed:

```text
cargo check -p apex-control-plane-api --lib --no-default-features
Finished `dev` profile
```

The source line-limit gate passed:

```text
python scripts/test_check_source_line_limits.py
exit code 0
```

Final touched Rust line counts are `proxy.rs` 502, `proxy/validation.rs` 598, `proxy/wire.rs` 469, `proxy/tests.rs` 581, and `lib.rs` 118. The contract source is 488 lines.

### Changed files

- `contracts/proto/apex/v1/mcp_proxy.proto`
- `apps/control-plane-api/src/lib.rs`
- `apps/control-plane-api/src/proxy.rs`
- `apps/control-plane-api/src/proxy/validation.rs`
- `apps/control-plane-api/src/proxy/wire.rs`
- `apps/control-plane-api/src/proxy/tests.rs`

### Self-review

- No first-upstream, implicit read classification, alias inference, or flat-network-policy-to-empty-list fallback remains.
- Secret-bearing fields accept only bounded `SecretRef` references; no raw secret values were introduced.
- Destination hosts are structurally bounded and restricted to valid IP/DNS host forms; private, loopback, link-local, internal, and local destinations require explicit allowance.
- The strict raw-input path rejects unknown fields at every mirrored nested object. The report intentionally keeps the protobuf unknown-field limitation visible: prost discards unknown fields during decode, so callers requiring unknown-field rejection must use the strict raw-input entry point.

### Round 1 concerns

1. The required contract correction changes `McpProxySpec.exposed_tools` from strings to structured entries and adds structured runtime egress destinations; downstream service handlers must adopt the regenerated types before wiring RPC behavior.
2. `cargo fmt --all --check` remains non-clean because the repository contains unrelated pre-existing formatting drift. The touched files were checked with scoped rustfmt using the 110-column cap needed to remain within the 600-line requirement.
