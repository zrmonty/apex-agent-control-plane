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
