//! Numeric, bounded-range settings: admission/poll ceilings, inbox capacity,
//! the fanout worker's tick, command-id retention, and the NATS retry ladder.
//! None of these carry a complex type -- every one is `bounded_secs_value` or
//! a hand-rolled equivalent over a `u32`/`usize`.

use std::env;
use std::io;
use std::time::Duration;

use apex_control_plane_api::DEFAULT_INBOX_SCOPE_QUOTA;

use super::{bounded_secs_value, optional};

/// Cross-replica admission ceiling: how many commands one operator subject may
/// have accepted per window, **across every replica** when the shared store is
/// configured.
///
/// Configurable rather than a bare constant because the ceiling has to be
/// observable to be provable. The live two-replica test bursts past it and
/// asserts the combined admission equals the ceiling instead of twice it,
/// which is only deterministic when the window is long enough that a burst
/// cannot straddle two windows -- so both are settings, both are range-checked,
/// and both keep the shipped defaults (50 per second) when unset.
pub(crate) fn admission_limits() -> Result<(u32, Duration), io::Error> {
    let limit = admission_limit_value(optional("APEX_CONTROL_ADMISSION_LIMIT").as_deref())?;
    let window = bounded_secs_value(
        optional("APEX_CONTROL_ADMISSION_WINDOW_SECS").as_deref(),
        1,
        1,
        3600,
        "APEX_CONTROL_ADMISSION_WINDOW_SECS must be an integer from 1 through 3600",
    )?;
    Ok((limit, window))
}

pub(crate) fn admission_limit_value(raw: Option<&str>) -> Result<u32, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_ADMISSION_LIMIT must be an integer from 1 through 100000",
        )
    };
    let limit = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u32>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(50);
    // Zero is refused rather than treated as "unlimited": an admission ceiling
    // of zero admits nothing, and an operator who meant to disable the control
    // is far more likely to have fat-fingered a digit.
    if !(1..=100_000).contains(&limit) {
        return Err(invalid());
    }
    Ok(limit)
}

/// Per-`(workspace_id, namespace_id)` ceiling on tracked inbox commands,
/// enforced in *addition* to the shared global inbox capacity every
/// `CommandInbox` backend already applies. See
/// `apex_control_plane_api::DEFAULT_INBOX_SCOPE_QUOTA` for why this exists
/// (an operator credential is commonly scoped to one workspace/namespace, and
/// nothing previously stopped a single scoped credential from filling the
/// entire shared inbox and blocking delivery -- including an emergency
/// `stop` -- to every other tenant) and why 20,000 is the default.
pub(crate) fn inbox_scope_quota(capacity: usize) -> Result<usize, io::Error> {
    inbox_scope_quota_value(
        optional("APEX_CONTROL_INBOX_MAX_COMMANDS_PER_SCOPE").as_deref(),
        capacity,
    )
}

pub(crate) fn inbox_scope_quota_value(
    raw: Option<&str>,
    capacity: usize,
) -> Result<usize, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "APEX_CONTROL_INBOX_MAX_COMMANDS_PER_SCOPE must be a positive integer no greater than the inbox capacity ({capacity})"
            ),
        )
    };
    let quota = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or_else(|| DEFAULT_INBOX_SCOPE_QUOTA.min(capacity));
    // Zero is refused rather than treated as "unlimited" -- same rule, same
    // reason, as `admission_limit_value`: a quota of zero admits nothing for
    // anybody, which is never what an operator setting this variable meant.
    // Wider than `capacity` is refused for the same fail-loud-not-clamped
    // reason every other bounded setting in this file uses: silently
    // clamping would make the configured number a lie an operator could
    // never observe.
    if quota == 0 || quota > capacity {
        return Err(invalid());
    }
    Ok(quota)
}

/// How often the background fanout worker drains the durable outbox into
/// JetStream.
///
/// **Five seconds**, matching `event-ingest`'s own outbox replay worker
/// (`apps/event-ingest/src/startup/service.rs` spawns it with
/// `Duration::from_secs(5)`). That is the same job -- drain a durable outbox
/// into the same broker -- so there is no reason for this service to poll on
/// a different rhythm, and an operator reading either binary sees one number.
///
/// Why not faster: [`crate::outbox::ControlOutboxBackend`] serialises *every*
/// outbox operation behind a single `Mutex`, and `submit_command` on the
/// accept path takes that same lock. A sub-second tick would buy milliseconds
/// of delivery latency at the cost of contending with the one path ADR-0006
/// requires to stay fast and available whatever else is degraded. It would
/// also turn a JetStream outage into a connect-attempt storm (each attempt
/// carries a 5s connect timeout) instead of a paced retry.
///
/// Why not slower: `ControlCommandResponse.delivered` and the queryable
/// `control` event are how an operator confirms a `stop` actually reached the
/// trace. Minutes of lag there is indistinguishable, to the human watching,
/// from the command having been dropped.
const DEFAULT_FANOUT_INTERVAL_SECS: u64 = 5;

/// One hour. Past this the worker is effectively off, and an operator who
/// meant to disable fanout should unset `APEX_CONTROL_NATS_URL` -- which says
/// so -- rather than leave a worker running on a tick nobody will notice.
const MAX_FANOUT_INTERVAL_SECS: u64 = 3600;

const DEFAULT_POSTGRES_POOL_SIZE: usize = 4;
const MAX_POSTGRES_POOL_SIZE: usize = 16;

pub(crate) fn postgres_pool_size() -> Result<usize, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_POSTGRES_POOL_SIZE must be an integer from 1 through 16",
        )
    };
    let size = env::var("APEX_CONTROL_POSTGRES_POOL_SIZE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(DEFAULT_POSTGRES_POOL_SIZE);
    if !(1..=MAX_POSTGRES_POOL_SIZE).contains(&size) {
        return Err(invalid());
    }
    Ok(size)
}

pub(crate) fn fanout_interval() -> Result<Duration, io::Error> {
    fanout_interval_value(env::var("APEX_CONTROL_FANOUT_INTERVAL_SECS").ok().as_deref())
}

pub(crate) fn fanout_interval_value(raw: Option<&str>) -> Result<Duration, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_FANOUT_INTERVAL_SECS must be an integer from 1 through 3600",
        )
    };
    let seconds = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(DEFAULT_FANOUT_INTERVAL_SECS);
    // Zero is refused rather than clamped: a zero-interval `tokio::time::sleep`
    // is a busy loop that would hold and release the shared outbox mutex as
    // fast as the scheduler allows, starving the accept path.
    if !(1..=MAX_FANOUT_INTERVAL_SECS).contains(&seconds) {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

/// How long settled command identities remain in the inbox. During this
/// window a retry with the same `command_id` remains idempotent; after it,
/// reusing that identity is allowed and creates a new delivery.
const DEFAULT_COMMAND_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const MIN_COMMAND_RETENTION_SECS: u64 = 60 * 60;
const MAX_COMMAND_RETENTION_SECS: u64 = 365 * 24 * 60 * 60;

pub(crate) fn command_retention() -> Result<Duration, io::Error> {
    command_retention_value(env::var("APEX_CONTROL_COMMAND_RETENTION_SECS").ok().as_deref())
}

pub(crate) fn command_retention_value(raw: Option<&str>) -> Result<Duration, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_COMMAND_RETENTION_SECS must be an integer from 3600 through 31536000",
        )
    };
    let seconds = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(DEFAULT_COMMAND_RETENTION_SECS);
    if !(MIN_COMMAND_RETENTION_SECS..=MAX_COMMAND_RETENTION_SECS).contains(&seconds) {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

/// Bounded publish-retry ladder for the JetStream transport, mirroring
/// `event-ingest`'s `APEX_RETRY_ATTEMPTS` (same 1..=8 range, same default,
/// same `RetryingJetStreamTransport` ceiling). Named with this crate's own
/// prefix because the control gateway's broker budget is not the ingest
/// gateway's to set.
pub(crate) fn nats_retry_attempts() -> Result<usize, io::Error> {
    nats_retry_attempts_value(env::var("APEX_CONTROL_NATS_RETRY_ATTEMPTS").ok().as_deref())
}

pub(crate) fn nats_retry_attempts_value(raw: Option<&str>) -> Result<usize, io::Error> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_NATS_RETRY_ATTEMPTS must be an integer from 1 through 8",
        )
    };
    let attempts = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<usize>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(3);
    if !(1..=8).contains(&attempts) {
        return Err(invalid());
    }
    Ok(attempts)
}
