//! `apps/agent-supervisor`: the OOB control gateway's forced-termination
//! backstop.
//!
//! # Why this exists, and why it was deferred until now
//!
//! `ADR-0005 Cooperative V1 Controls` shipped five controls --
//! `stop`/`pause`/`resume`/`inject`/`set_budget` -- and explicitly rejected a
//! sixth: *"Offer forced stop immediately -- rejected until process isolation
//! and a safety model exist."* All five are **cooperative**: the gateway
//! delivers a command to the agent's own SDK process over `PollCommands`, and
//! that process chooses to honor it. A 2026-08 security pass on the gateway
//! (`OOB Control Gateway — Command Delivery Gap`) found the sharp edge that
//! trust model has: whoever compromises an agent's host already holds that
//! agent's own poll/ack credential (same host, same key material), so they
//! can poll-and-ack an emergency `stop` on a second connection before the
//! real, compromised runtime ever acts on it. Concretely, in the incident
//! that motivated this whole gateway -- an agent reaching for an
//! AMSI-bypass one-liner mid-task -- a `stop` issued through the cooperative
//! channel could have been silently swallowed by a sufficiently capable
//! attacker already on that host.
//!
//! That finding's own stated conclusion is what this binary builds:
//! *"The actual backstop for a non-cooperative agent remains a
//! host/orchestrator-level kill (process termination, network isolation)
//! outside this channel entirely."* This is that component. It:
//!
//! 1. **Is the real OS parent of the agent process**, not a PID read out of
//!    a file -- see [`process_group`] for why that distinction is load-bearing
//!    (a PID on its own carries no kill authority the kernel recognizes, and
//!    a file can be stale or spoofed; being the actual `fork`/`exec` parent
//!    and process-group leader is what lets `SIGKILL -pgid` reach the whole
//!    tree the agent may have spawned, matching the AMSI incident's own
//!    shape -- the dangerous PowerShell script was itself a *child process
//!    the agent spawned*, not the agent's own top-level process).
//! 2. **Holds its own workload credential, distinct from the agent's.** See
//!    [`child_env`] for the mechanism (the child's environment is built from
//!    scratch, never inherited) and
//!    `apex_control_plane_api::agent_auth::supervisor_agent_id` in
//!    `apps/control-plane-api` for the identity-naming convention this
//!    relies on. **This is the property that makes the whole feature
//!    meaningful.** If the supervisor used the agent's own credential -- or
//!    the agent could read the supervisor's credential out of its own
//!    environment, arguments, or an inherited file descriptor -- a fully
//!    compromised agent process could poll-and-ack its own `force_stop`
//!    exactly the way the Delivery Gap finding describes for an ordinary
//!    `stop`, and this binary would add OS kill authority to the system
//!    without adding the one property (a credential the compromised process
//!    cannot reach) that makes that authority trustworthy.
//! 3. **Polls for `force_stop` scoped to its own identity**, the same
//!    `PollCommands` mechanism an agent uses for `stop`, and kills the whole
//!    process group -- unconditionally, no graceful grace period -- on
//!    receipt. See [`control_client`].
//!
//! # What this is not
//!
//! It is not a general process manager, a health-check/restart supervisor,
//! or a replacement for the cooperative controls. Every other control keeps
//! going through the agent's own SDK poll loop, unchanged; this binary's only
//! job is to exist as the credential- and process-isolated last resort for
//! the one case cooperative delivery structurally cannot cover: a host that
//! is already hostile.
//!
//! # Windows
//!
//! Best-effort only, stated honestly rather than silently matched to the
//! Linux story: see [`process_group::SupervisedChild::terminate_tree`]. The
//! project's actual deployment target is Linux containers (`deploy/` is
//! Docker/compose throughout), and Windows has no POSIX process-group
//! primitive to reach for here.

pub mod proto {
    tonic::include_proto!("apex.v1");
}

pub mod child_env;
pub mod config;
pub mod control_client;
pub mod credentials;
pub mod process_group;
