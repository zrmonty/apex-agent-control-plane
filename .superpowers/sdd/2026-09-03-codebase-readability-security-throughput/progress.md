# SDD progress: codebase readability, security, and throughput

Plan: `docs/superpowers/plans/2026-09-03-codebase-readability-security-throughput.md`
Workspace: `E:/Agent Control Plane/.worktrees/codebase-hardening`

## Rules

- Keep held roadmap work paused.
- Preserve the live vertical slice and fail-closed trust boundaries.
- No tracked source or test file over 600 lines.
- Every task gets implementation evidence and an independent review before merge.

## Task ledger

| Task | Scope | Status | Evidence | Review |
| --- | --- | --- | --- | --- |
| 1 | line-limit checker, tests, CI enforcement, baseline | implemented | checker tests 2 passed; CI runs the checker and reports no tracked source/test file over 600 lines | reviewed; CI coverage added after review |
| 2 | oversized Rust module splits | implemented | event-ingest, apex-policy, apex-durability, control inbox, envelope, startup, poll, and security test responsibility splits; workspace tests and clippy pass | reviewed; test-only admission wrapper was made feature-gated after review |
| 3 | TypeScript test/fixture split | implemented | gateway `pnpm test` (57 total: 56 passed, 1 conditional symlink skip), `pnpm typecheck`, `pnpm build`; admission/live-boundary tests are split | reviewed; security findings fixed and retested |
| 4 | security hardening and adversarial tests | implemented | strict raw live-target/deadline validation, trusted secret-base checks, read-only ingest container, safe `__proto__` conversion, PKI file-import compatibility, and gateway adversarial suite passed | reviewed; all findings fixed and retested |
| 5 | throughput measurement and optimization | implemented | dry-run harness baseline plus equivalent 5x100k Struct microbench; current loop median 70.51ms vs 126.72ms baseline (44.4% faster) | reviewed; benchmark now asserts equivalent wire output |
| 6 | full verification, roadmap update, merge | implemented | workspace tests, clippy `-D warnings`, configured cargo-deny checks, cargo-audit, Python/deployment tests, gateway tests/typecheck/build, source limits, and staged diff checks passed; roadmap/progress docs updated | review complete; integration pending |

## Rulings

- A reviewer-reported Linux secret-fixture failure was valid; private test files now use mode `0600` so the positive path exercises production policy on POSIX hosts.
- A reviewer-reported `__proto__` prototype-setter risk was valid; field accumulation defines that legal key as an own enumerable property without changing the fast path for ordinary keys.
- A reviewer-reported file-based `generate_pki.py` import regression was valid; the script has a sibling-module fallback for `spec_from_file_location` callers.
- A reviewer-reported URL canonicalization gap was valid; raw URL shape is rejected before WHATWG parsing.
- A reviewer-reported benchmark-equivalence gap was valid; the pre-refactor encoder now matches the current protobuf oneof shape and numeric validation, and the harness compares outputs before timing.
- A final staged review found missing MCP PR coverage, endpoint trim acceptance, and host-secret symlink traversal. CI now runs the gateway test/typecheck/build, endpoint validation rejects surrounding whitespace, and host-secret staging refuses symlinked output/source/destination paths; focused deployment and gateway checks pass.
- A follow-up review found the configuration loader still trimmed endpoints and the PKI source root could be symlinked. The loader now rejects endpoint whitespace before normalization, and host-secret staging plus PKI generation reject symlinked source/output roots and destinations; the updated gateway suite and deployment tests pass.
- The final PKI review found direct README/credential writes that bypassed the destination check. All generated files now pass through the symlink rejection helper, with a regression test covering a planted destination link; the gateway count remains 57 total (56 passed, 1 conditional skip).
- The repository-wide `cargo fmt --all -- --check` remains outside this pass's write scope because it reports pre-existing formatting drift across untouched files; changed Rust modules pass compilation, tests, clippy, and focused formatting checks where applicable.
