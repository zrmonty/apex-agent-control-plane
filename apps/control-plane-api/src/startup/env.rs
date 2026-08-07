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

use apex_event_ingest::NatsTlsConfig;

/// Loopback by default. See [`resolve_bind_addr_value`] for why a non-loopback
/// value still needs an explicit acknowledgement even now that this process
/// terminates TLS itself.
pub(crate) const DEFAULT_BIND_ADDR: &str = "127.0.0.1:9443";

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

/// Resolves where the operator credential table comes from.
///
/// A file is the production path: Compose, Kubernetes, and `docker inspect`
/// all treat `environment:` as non-secret and readable
/// (`/proc/<pid>/environ`), so a bearer-token table does not belong there in
/// a real deployment -- every other credential in `deploy/compose/compose.yaml`
/// is a file secret. The inline env var stays for local/lab and CI use.
///
/// Setting both is a hard error rather than a precedence rule. Two configured
/// credential sources means one of them is silently ignored, and "the
/// operator token I set is not working" is exactly the failure that gets
/// debugged by loosening something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OperatorTokenSource {
    File(PathBuf),
    Inline(String),
    Unset,
}

pub(crate) fn operator_token_source() -> Result<OperatorTokenSource, io::Error> {
    operator_token_source_value(
        optional("APEX_CONTROL_OPERATOR_TOKENS_FILE").as_deref(),
        optional("APEX_CONTROL_OPERATOR_TOKENS").as_deref(),
    )
}

pub(crate) fn operator_token_source_value(
    file: Option<&str>,
    inline: Option<&str>,
) -> Result<OperatorTokenSource, io::Error> {
    match (file, inline) {
        (Some(_), Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "set APEX_CONTROL_OPERATOR_TOKENS_FILE or APEX_CONTROL_OPERATOR_TOKENS, not both",
        )),
        (Some(file), None) => Ok(OperatorTokenSource::File(PathBuf::from(file))),
        (None, Some(inline)) => Ok(OperatorTokenSource::Inline(inline.to_owned())),
        (None, None) => Ok(OperatorTokenSource::Unset),
    }
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

/// Resolves the JetStream client configuration for the fanout worker, or
/// `None` when `APEX_CONTROL_NATS_URL` is unset.
///
/// Optional on purpose. Making it required would give this binary a hard
/// startup dependency on the primary data path's broker configuration, which
/// is the exact coupling ADR-0006 exists to remove -- the gateway must come up
/// and accept commands with JetStream unreachable or unconfigured. When it is
/// unset the caller logs loudly that accepted commands will stay durably
/// pending and never reach the queryable trace.
///
/// When it *is* set, the three TLS paths become required rather than
/// optional: a half-configured broker client is a misconfiguration, not a
/// reason to silently fall back to no fanout.
pub(crate) fn nats_config() -> Result<Option<NatsTlsConfig>, io::Error> {
    let Some(server_url) = optional("APEX_CONTROL_NATS_URL") else {
        return Ok(None);
    };
    Ok(Some(NatsTlsConfig {
        server_url,
        ca_file: path("APEX_CONTROL_NATS_CA_FILE")?,
        client_cert_file: path("APEX_CONTROL_NATS_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_CONTROL_NATS_CLIENT_KEY_FILE")?,
        // Both-or-neither; `NatsTlsConfig::validated` refuses a lone one.
        username_file: optional("APEX_CONTROL_NATS_USERNAME_FILE").map(PathBuf::from),
        password_file: optional("APEX_CONTROL_NATS_PASSWORD_FILE").map(PathBuf::from),
    }))
}

/// Selects the Postgres outbox backend, or `None` for the file outbox.
pub(crate) fn control_postgres_url() -> Result<Option<String>, io::Error> {
    control_postgres_url_value(
        optional("APEX_CONTROL_POSTGRES_URL").as_deref(),
        optional("APEX_POSTGRES_URL").as_deref(),
    )
}

/// `APEX_CONTROL_POSTGRES_URL` is this crate's own variable, deliberately not
/// `event-ingest`'s `APEX_POSTGRES_URL`.
///
/// `apex_event_ingest::PostgresOutbox` hardcodes the table name
/// `apex_event_outbox` (`deploy/postgres/outbox.sql`). Two services pointed at
/// one database therefore share one outbox table, and that is not a cosmetic
/// overlap: `event-ingest`'s replay worker claims pending rows with
/// `FOR UPDATE SKIP LOCKED` and fans them out through *its* sinks, so it would
/// claim and republish control commands; this crate's fanout worker would
/// likewise claim ingest events and republish them. Each service must be given
/// a URL resolving to its own database or its own schema (e.g.
/// `?options=-c%20search_path%3Dapex_control`), the Postgres equivalent of the
/// separate `control-outbox` volume the file backend already gets.
///
/// Seeing both variables set in one process is refused rather than resolved by
/// precedence, the same rule and for the same reason as the two operator-token
/// sources above: it means one of two configured durability targets is being
/// silently ignored, and this is the surface where that matters most.
pub(crate) fn control_postgres_url_value(
    control: Option<&str>,
    ingest: Option<&str>,
) -> Result<Option<String>, io::Error> {
    if control.is_some() && ingest.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_POSTGRES_URL is set alongside APEX_CONTROL_POSTGRES_URL; the control gateway must be given its own database or schema because apex_event_outbox is a shared table name",
        ));
    }
    if let Some(ingest) = ingest {
        let _ = ingest;
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_POSTGRES_URL is event-ingest's variable; set APEX_CONTROL_POSTGRES_URL to the control gateway's own database or schema",
        ));
    }
    Ok(control.map(str::to_owned))
}
