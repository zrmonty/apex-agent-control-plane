//! Optional external-service connections: the control gateway's own Valkey
//! accelerator, the JetStream client the fanout worker publishes through, and
//! the Postgres outbox/inbox selector. Each carries its own crate-distinct
//! variable family -- see each function's own doc for why.

use std::io;
use std::path::PathBuf;

use apex_event_ingest::NatsTlsConfig;

use super::{optional, path};

/// The control gateway's own Valkey accelerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlValkeyEnv {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password_file: PathBuf,
    pub(crate) ca_file: PathBuf,
    pub(crate) client_cert_file: PathBuf,
    pub(crate) client_key_file: PathBuf,
}

/// `APEX_CONTROL_VALKEY_*` is this crate's own variable family, deliberately
/// not `event-ingest`'s `APEX_VALKEY_*`.
///
/// Same rule and same reason as `APEX_CONTROL_POSTGRES_URL` and the separate
/// NATS account: every shared infrastructure dependency this crate has gets
/// its own distinct identity, because "independently authenticated"
/// (ADR-0006) has to hold at each dependency or it stops at the gRPC edge. In
/// the Valkey case there is a second, concrete reason -- `event-ingest`'s
/// `ephemeral::types::KEY_PREFIX` is the fixed literal `apex:ingest`, so a
/// shared instance would put both services' counters in one keyspace under one
/// ACL user, and either service's credential would then be able to clear or
/// inflate the other's rate-limit state.
///
/// Seeing `APEX_VALKEY_HOST` on this process is refused outright rather than
/// honoured.
pub(crate) fn control_valkey_env() -> Result<Option<ControlValkeyEnv>, io::Error> {
    let Some(host) = control_valkey_host_value(
        optional("APEX_CONTROL_VALKEY_HOST").as_deref(),
        optional("APEX_VALKEY_HOST").as_deref(),
    )?
    else {
        return Ok(None);
    };
    let port = optional("APEX_CONTROL_VALKEY_PORT")
        .unwrap_or_else(|| "6379".to_owned())
        .parse::<u16>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_VALKEY_PORT must be a TCP port",
            )
        })?;
    Ok(Some(ControlValkeyEnv {
        host,
        port,
        username: optional("APEX_CONTROL_VALKEY_USERNAME")
            .unwrap_or_else(|| "apex-control".to_owned()),
        password_file: path("APEX_CONTROL_VALKEY_PASSWORD_FILE")?,
        ca_file: path("APEX_CONTROL_VALKEY_CA_FILE")?,
        client_cert_file: path("APEX_CONTROL_VALKEY_CLIENT_CERT_FILE")?,
        client_key_file: path("APEX_CONTROL_VALKEY_CLIENT_KEY_FILE")?,
    }))
}

pub(crate) fn control_valkey_host_value(
    control: Option<&str>,
    ingest: Option<&str>,
) -> Result<Option<String>, io::Error> {
    if ingest.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_VALKEY_HOST is event-ingest's variable; set APEX_CONTROL_VALKEY_HOST with the control gateway's own Valkey credentials and instance",
        ));
    }
    Ok(control.map(str::to_owned))
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
/// precedence, the same rule and for the same reason as `credentials`'s two
/// operator-token sources: it means one of two configured durability targets
/// is being silently ignored, and this is the surface where that matters most.
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
