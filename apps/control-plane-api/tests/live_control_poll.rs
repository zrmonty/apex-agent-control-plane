//! **The live end-to-end proof of this pass**: an operator's `stop` reaches a
//! real agent process and halts it.
//!
//! Everything in this file runs against real containers and real processes:
//!
//! - a real `control-plane-api` container terminating mTLS
//!   (`deploy/compose/compose.gateway-ref.yaml`),
//! - a real Python process using the product SDK's own
//!   `GrpcControlTransport` and `ReferenceReasonActLoop`
//!   (`deploy/compose/gateway-ref/agent_under_control.py`),
//! - a real `SubmitCommand` call over mTLS with an operator credential, using
//!   the RPC that already worked and is not modified here.
//!
//! The causality claim is deliberately not "the process exited". A process can
//! exit for a dozen reasons. What is asserted is that the `command_id` the
//! gateway minted for *this* submission is the same `command_id` the agent
//! printed when it halted, that the agent completed whole iterations before
//! the submission and none after, and that the agent's own JSONL trace
//! contains the terminal `control` + `turn_end(stopped)` pair naming it. A
//! coincidental exit cannot produce a freshly-minted UUIDv7 it never saw.
//!
//! Opt-in via `APEX_CONTROL_LIVE_POLL=1`, so offline unit CI stays green.
//!
//! Grouped by scenario: `stop_pause_resume` (the `stop` and `pause`/`resume`
//! proofs), `budget_inject` (`set_budget` and `inject`), and `isolation`
//! (cross-agent and cross-credential-space isolation, live). `support` holds
//! the fixtures -- including [`support::AgentProcess`], the real subprocess
//! harness -- shared across all three.

// Integration-test crate roots resolve a bodiless `mod x;` relative to
// `tests/` itself (like `src/main.rs`/`src/lib.rs` do for `src/`), not a
// `tests/live_control_poll/` subdirectory named after this file -- hence the
// explicit `#[path]` on each, pointing at the actual sibling-directory
// layout.
#[path = "live_control_poll/budget_inject.rs"]
mod budget_inject;
#[path = "live_control_poll/isolation.rs"]
mod isolation;
#[path = "live_control_poll/stop_pause_resume.rs"]
mod stop_pause_resume;
#[path = "live_control_poll/support.rs"]
mod support;
