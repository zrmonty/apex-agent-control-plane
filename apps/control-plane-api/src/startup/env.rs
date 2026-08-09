//! Environment parsing for the OOB control gateway binary.
//!
//! Every value that carries a policy decision is split into a pure
//! `*_value` function taking `Option<&str>`, with the thin `env::var` wrapper
//! on top. This crate has `unsafe_code = "forbid"` and Rust 2024 requires
//! `unsafe` to call `env::set_var`, so a test cannot inject an environment
//! variable -- the split is the only way these rules get real coverage. Same
//! pattern as `apps/event-ingest/src/startup/env.rs`
//! (`attempts` / `attempts_value`).

use std::collections::BTreeSet;
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
    /// The production path: short-lived, scope-bound credentials issued by
    /// Keycloak and verified here (`apex_control_plane_api::keycloak`). Carries
    /// the configured issuer; the rest of the settings are read by
    /// [`keycloak_env`].
    Keycloak(String),
    Unset,
}

pub(crate) fn operator_token_source() -> Result<OperatorTokenSource, io::Error> {
    operator_token_source_value(
        optional("APEX_CONTROL_OPERATOR_TOKENS_FILE").as_deref(),
        optional("APEX_CONTROL_OPERATOR_TOKENS").as_deref(),
        optional("APEX_CONTROL_KEYCLOAK_ISSUER").as_deref(),
    )
}

/// Adds the Keycloak path to the same exclusivity rule the two static sources
/// already had.
///
/// **Explicitly selected, never inferred.** `APEX_CONTROL_KEYCLOAK_ISSUER`
/// being set is what chooses the production verifier; it is not derived from
/// the absence of a token table, because "the operator table was not mounted"
/// and "this deployment authenticates through Keycloak" are different
/// situations with very different consequences, and the first silently
/// becoming the second is how a lab configuration ends up in production.
///
/// Setting Keycloak alongside either static source is refused for exactly the
/// reason the two static sources already refuse each other: two configured
/// credential sources means one of them is being silently ignored, and this is
/// the surface where "my operator token is not working" gets debugged by
/// loosening something.
pub(crate) fn operator_token_source_value(
    file: Option<&str>,
    inline: Option<&str>,
    keycloak_issuer: Option<&str>,
) -> Result<OperatorTokenSource, io::Error> {
    let configured = usize::from(file.is_some())
        + usize::from(inline.is_some())
        + usize::from(keycloak_issuer.is_some());
    if configured > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "set exactly one of APEX_CONTROL_KEYCLOAK_ISSUER, APEX_CONTROL_OPERATOR_TOKENS_FILE, or APEX_CONTROL_OPERATOR_TOKENS",
        ));
    }
    match (file, inline, keycloak_issuer) {
        (Some(file), None, None) => Ok(OperatorTokenSource::File(PathBuf::from(file))),
        (None, Some(inline), None) => Ok(OperatorTokenSource::Inline(inline.to_owned())),
        (None, None, Some(issuer)) => Ok(OperatorTokenSource::Keycloak(issuer.to_owned())),
        _ => Ok(OperatorTokenSource::Unset),
    }
}

/// Where the **agent workload** credential table comes from.
///
/// A separate variable family from `APEX_CONTROL_OPERATOR_TOKENS*`, and that
/// separation is the whole point: these two tables authorize different
/// principals to do different things, and one file holding both would be one
/// mount away from an operator credential that can also poll.
///
/// Same file-vs-inline rule and the same both-is-an-error rule as the operator
/// table, for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentTokenSource {
    File(PathBuf),
    Inline(String),
    Unset,
}

pub(crate) fn agent_token_source() -> Result<AgentTokenSource, io::Error> {
    agent_token_source_value(
        optional("APEX_CONTROL_AGENT_TOKENS_FILE").as_deref(),
        optional("APEX_CONTROL_AGENT_TOKENS").as_deref(),
    )
}

pub(crate) fn agent_token_source_value(
    file: Option<&str>,
    inline: Option<&str>,
) -> Result<AgentTokenSource, io::Error> {
    match (file, inline) {
        (Some(_), Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "set APEX_CONTROL_AGENT_TOKENS_FILE or APEX_CONTROL_AGENT_TOKENS, not both",
        )),
        (Some(file), None) => Ok(AgentTokenSource::File(PathBuf::from(file))),
        (None, Some(inline)) => Ok(AgentTokenSource::Inline(inline.to_owned())),
        (None, None) => Ok(AgentTokenSource::Unset),
    }
}

/// Everything the Keycloak resolver needs, read from the environment.
///
/// The CA arrives here as a *path*; `startup::service` resolves it through
/// `trusted_secret_path` and hands `KeycloakConfig` the bytes, so the
/// trusted-secret policy has exactly one implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeycloakEnv {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    pub(crate) ca_file: PathBuf,
    pub(crate) jwks_url: String,
    pub(crate) jwks_refresh: Duration,
    pub(crate) jwks_max_age: Duration,
    pub(crate) scope_claim: String,
    pub(crate) role_claim: String,
    pub(crate) global_role: Option<String>,
    pub(crate) global_subjects: BTreeSet<String>,
    pub(crate) max_token_lifetime: Duration,
    pub(crate) expected_typ: Option<String>,
}

/// Default JWKS refresh interval, and therefore the upper bound on how long a
/// key Keycloak has rotated away keeps verifying tokens here.
///
/// **Five minutes.** Not shorter, because the JWKS endpoint is on the identity
/// provider's critical path for every service in the deployment and this
/// process gains nothing from polling it harder -- Keycloak realm keys rotate
/// on the order of months, and a *revocation* is handled by the same refresh
/// either way. Not longer, because "how long does a compromised signing key
/// keep working after we pull it" is the number this variable is, and an hour
/// is a long time to be verifying with a key the realm has disowned.
const DEFAULT_JWKS_REFRESH_SECS: u64 = 300;
/// Default hard staleness ceiling: three refresh intervals. Long enough that
/// two consecutive failed refreshes do not lock every operator out during a
/// brief identity-provider blip; short enough that a sustained JWKS outage
/// stops this process trusting keys of unknown age within fifteen minutes
/// rather than indefinitely.
const DEFAULT_JWKS_MAX_AGE_SECS: u64 = 900;
/// Default ceiling on `exp - iat`. Keycloak's own default access-token
/// lifespan is five minutes, so an hour is generous headroom for a deployment
/// that has lengthened it, while still refusing the long-lived token a
/// misconfigured client would otherwise get away with presenting here.
const DEFAULT_MAX_TOKEN_LIFETIME_SECS: u64 = 3600;
/// Keycloak stamps `typ: Bearer` on access tokens, `ID` on ID tokens and
/// `Refresh` on refresh tokens -- all signed with the same realm keys.
const DEFAULT_EXPECTED_TOKEN_TYP: &str = "Bearer";

pub(crate) fn keycloak_env(issuer: String) -> Result<KeycloakEnv, io::Error> {
    let jwks_url = optional("APEX_CONTROL_KEYCLOAK_JWKS_URL").unwrap_or_else(|| {
        apex_control_plane_api::KeycloakConfig::default_jwks_url(&issuer)
    });
    let jwks_refresh = bounded_secs_value(
        optional("APEX_CONTROL_KEYCLOAK_JWKS_REFRESH_SECS").as_deref(),
        DEFAULT_JWKS_REFRESH_SECS,
        30,
        3600,
        "APEX_CONTROL_KEYCLOAK_JWKS_REFRESH_SECS must be an integer from 30 through 3600",
    )?;
    let jwks_max_age = bounded_secs_value(
        optional("APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS").as_deref(),
        DEFAULT_JWKS_MAX_AGE_SECS,
        30,
        86_400,
        "APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS must be an integer from 30 through 86400",
    )?;
    Ok(KeycloakEnv {
        issuer,
        audience: required("APEX_CONTROL_KEYCLOAK_AUDIENCE")?,
        ca_file: path("APEX_CONTROL_KEYCLOAK_CA_FILE")?,
        jwks_url,
        jwks_refresh,
        jwks_max_age,
        scope_claim: optional("APEX_CONTROL_KEYCLOAK_SCOPE_CLAIM")
            .unwrap_or_else(|| "apex_control_scopes".to_owned()),
        role_claim: optional("APEX_CONTROL_KEYCLOAK_ROLE_CLAIM")
            .unwrap_or_else(|| "realm_access.roles".to_owned()),
        global_role: optional("APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE"),
        global_subjects: global_subjects_value(
            optional("APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS").as_deref(),
        ),
        max_token_lifetime: bounded_secs_value(
            optional("APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS").as_deref(),
            DEFAULT_MAX_TOKEN_LIFETIME_SECS,
            60,
            86_400,
            "APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS must be an integer from 60 through 86400",
        )?,
        expected_typ: expected_token_typ_value(
            optional("APEX_CONTROL_KEYCLOAK_EXPECTED_TYP").as_deref(),
            optional("APEX_CONTROL_KEYCLOAK_ALLOW_ANY_TOKEN_TYP").as_deref(),
        )?,
    })
}

/// The break-glass subject allow-list: exact `sub` values, comma-separated.
///
/// Deliberately *not* a pattern or prefix language. This list is the one part
/// of the `*` grant that the identity provider does not control, so it has to
/// be something an operator wrote down one identity at a time.
pub(crate) fn global_subjects_value(raw: Option<&str>) -> BTreeSet<String> {
    raw.map(|raw| {
        raw.split(',')
            .map(str::trim)
            .filter(|subject| !subject.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

/// Required payload `typ`, or `None` when the check has been explicitly waived.
///
/// The waiver is its own loudly-named variable rather than a magic value of
/// the first one, and setting both is refused, for the same reason
/// `APEX_CONTROL_ALLOW_NONLOCAL_BIND` is exact-match: turning off
/// ID-token/refresh-token confusion protection should be something someone
/// typed on purpose.
pub(crate) fn expected_token_typ_value(
    expected: Option<&str>,
    waiver: Option<&str>,
) -> Result<Option<String>, io::Error> {
    let waived = waiver == Some("true");
    if waiver.is_some() && !waived {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_KEYCLOAK_ALLOW_ANY_TOKEN_TYP must be exactly 'true' or be unset",
        ));
    }
    if waived && expected.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "set APEX_CONTROL_KEYCLOAK_EXPECTED_TYP or APEX_CONTROL_KEYCLOAK_ALLOW_ANY_TOKEN_TYP, not both",
        ));
    }
    if waived {
        return Ok(None);
    }
    Ok(Some(
        expected
            .unwrap_or(DEFAULT_EXPECTED_TOKEN_TYP)
            .to_owned(),
    ))
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
