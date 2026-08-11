//! Environment parsing for the OOB control gateway binary.
//!
//! Every value that carries a policy decision is split into a pure
//! `*_value` function taking `Option<&str>`, with the thin `env::var` wrapper
//! on top. This crate has `unsafe_code = "forbid"` and Rust 2024 requires
//! `unsafe` to call `env::set_var`, so a test cannot inject an environment
//! variable -- the split is the only way these rules get real coverage. Same
//! pattern as `apps/event-ingest/src/startup/env.rs`
//! (`attempts` / `attempts_value`).

use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Loopback by default. See [`resolve_bind_addr_value`] for why a non-loopback
/// value still needs an explicit acknowledgement even now that this process
/// terminates TLS itself.
pub(crate) const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9443";

pub(crate) fn metrics_bind_addr() -> Result<Option<SocketAddr>, io::Error> {
    metrics_bind_addr_value(env::var("APEX_CONTROL_METRICS_ADDR").ok().as_deref())
}

pub(crate) fn metrics_bind_addr_value(raw: Option<&str>) -> Result<Option<SocketAddr>, io::Error> {
    let Some(raw) = raw.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let addr: SocketAddr = raw.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_METRICS_ADDR must be a host:port socket address",
        )
    })?;
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_METRICS_ADDR must remain loopback-only",
        ));
    }
    Ok(Some(addr))
}

pub(crate) fn required(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")))
}

pub(crate) fn path(name: &str) -> Result<PathBuf, io::Error> {
    Ok(PathBuf::from(required(name)?))
}

pub(crate) fn optional(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.is_empty())
}

pub(crate) fn resolve_bind_addr() -> Result<SocketAddr, io::Error> {
    resolve_bind_addr_value(
        env::var("APEX_CONTROL_BIND_ADDR").ok().as_deref(),
        env::var("APEX_CONTROL_ALLOW_NONLOCAL_BIND").ok().as_deref(),
    )
}

/// Refuses a non-loopback bind address unless the operator explicitly
/// acknowledged it with `APEX_CONTROL_ALLOW_NONLOCAL_BIND=true`.
///
/// This gate predates native TLS in this binary, where it was justified by
/// the process serving plaintext gRPC. It is deliberately **kept** now that
/// the process terminates mTLS itself, for two reasons:
///
///  1. Defence in depth, not transport confidentiality. This is the
///     out-of-band control channel -- the one surface that can `stop`,
///     `pause`, or `inject` into a running agent (ADR-0005). Widening its
///     listener to every interface should be a decision someone typed, not a
///     default that survives a copied `.env`. TLS protects the bytes on the
///     wire; it does not make "who can reach this socket at all" a
///     non-decision.
///  2. It mirrors the acknowledgement the ingest profile already requires
///     (`APEX_ALLOW_NONLOCAL_INGEST_BIND`, enforced in
///     `deploy/compose/preflight.sh`/`.ps1`) for a gateway that has *always*
///     been mTLS-only. So this is the established pattern here, not an
///     artefact of the plaintext era.
///
/// What did change with native TLS is the remediation text: the old message
/// told an operator to put a TLS-terminating proxy in front of the process,
/// which is now actively wrong advice.
pub(crate) fn resolve_bind_addr_value(
    raw: Option<&str>,
    acknowledgement: Option<&str>,
) -> Result<SocketAddr, io::Error> {
    let raw = raw
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_BIND_ADDR);
    let addr: SocketAddr = raw.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_BIND_ADDR must be a host:port socket address",
        )
    })?;
    // Exact match, deliberately: a typo ("TRUE", "1", "yes") must fail closed
    // into "not acknowledged" rather than be generously interpreted as
    // consent to expose the control channel.
    let acknowledged = acknowledgement == Some("true");
    if !addr.ip().is_loopback() && !acknowledged {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "APEX_CONTROL_BIND_ADDR={raw} is not a loopback address. This is the out-of-band control channel; set APEX_CONTROL_ALLOW_NONLOCAL_BIND=true only behind an approved network policy, with operator client certificates issued."
            ),
        ));
    }
    Ok(addr)
}

/// Shared bounded-integer-seconds parser. Every duration this binary reads is
/// range-checked rather than clamped, so a typo fails closed at startup
/// instead of silently becoming a policy nobody chose.
pub(crate) fn bounded_secs_value(
    raw: Option<&str>,
    default: u64,
    min: u64,
    max: u64,
    message: &'static str,
) -> Result<Duration, io::Error> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, message);
    let seconds = raw
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<u64>().map_err(|_| invalid()))
        .transpose()?
        .unwrap_or(default);
    if !(min..=max).contains(&seconds) {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

mod backends;
mod credentials;
mod keycloak;
mod limits;

pub(crate) use backends::{control_postgres_url, control_valkey_env, nats_config};
pub(crate) use credentials::{AgentTokenSource, OperatorTokenSource, agent_revocation_env, agent_token_source, operator_token_source};
pub(crate) use keycloak::keycloak_env;
pub(crate) use limits::{
    admission_limits, command_retention, fanout_interval, inbox_scope_quota,
    nats_retry_attempts,
};
#[cfg(feature = "postgres")]
pub(crate) use limits::postgres_pool_size;

// Only `startup::tests` (a sibling of `env`, not a descendant, so it cannot
// reach `env::credentials`/`env::keycloak`/`env::limits`/`env::backends`
// directly) needs these re-exports; every non-test caller reaches the
// `*_value` pure functions' thin `env::var` wrapper instead. Gated so a
// non-test build does not carry (and does not warn about) a re-export
// nothing in it uses.
#[cfg(test)]
pub(crate) use backends::{control_postgres_url_value, control_valkey_host_value};
#[cfg(test)]
pub(crate) use credentials::{
    AgentRevocationEnv, agent_revocation_env_value, agent_token_source_value,
    operator_token_source_value,
};
#[cfg(test)]
pub(crate) use keycloak::{expected_token_typ_value, global_subjects_value};
#[cfg(test)]
pub(crate) use limits::{
    admission_limit_value, command_retention_value, fanout_interval_value,
    inbox_scope_quota_value, nats_retry_attempts_value,
};
