//! Where each credential table (operator, agent, agent revocation) comes
//! from.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use super::{bounded_secs_value, optional};

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

/// Where the **agent revocation list** comes from -- a background-refreshed
/// file of certificate fingerprints that are refused regardless of what
/// [`AgentTokenSource`] would otherwise authenticate. See
/// `apex_control_plane_api::AgentRevocationList` for the full reasoning.
///
/// Unlike the credential tables above, there is no inline variant. The whole
/// point of this file, as opposed to the static `APEX_CONTROL_AGENT_TOKENS*`
/// table it sits alongside, is that revoking a compromised agent credential
/// is "edit a file and wait a few seconds", not "redeploy and wait"; an
/// inline env var would still need a process restart to change and would
/// defeat that purpose entirely.
///
/// Entirely optional: unset means `APEX_CONTROL_AGENT_TOKENS*` behaves
/// completely unchanged, which matters for every deployment that predates
/// this feature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentRevocationEnv {
    pub(crate) file: PathBuf,
    pub(crate) refresh: Duration,
    pub(crate) max_age: Duration,
}

/// Default refresh interval for the agent revocation list: **five seconds**.
/// The feature's reason for existing is that revoking a compromised agent
/// credential should be meaningfully faster than an env-var edit plus a
/// redeploy; five seconds keeps "meaningfully faster" true without polling
/// the filesystem hard enough to matter.
const DEFAULT_AGENT_REVOCATION_REFRESH_SECS: u64 = 5;
/// Default staleness ceiling: three refresh intervals, the same ratio
/// `startup::env::keycloak::DEFAULT_JWKS_MAX_AGE_SECS` uses against
/// `startup::env::keycloak::DEFAULT_JWKS_REFRESH_SECS` and for the same
/// reason -- long enough that one or two transient read
/// failures (an editor's non-atomic save, a momentarily-missing file
/// mid-rotation) do not flip every agent credential closed, short enough that
/// a sustained failure to read the file does so within seconds, not minutes.
const DEFAULT_AGENT_REVOCATION_MAX_AGE_SECS: u64 = 15;

pub(crate) fn agent_revocation_env() -> Result<Option<AgentRevocationEnv>, io::Error> {
    agent_revocation_env_value(
        optional("APEX_CONTROL_AGENT_REVOCATION_FILE").as_deref(),
        optional("APEX_CONTROL_AGENT_REVOCATION_REFRESH_SECS").as_deref(),
        optional("APEX_CONTROL_AGENT_REVOCATION_MAX_AGE_SECS").as_deref(),
    )
}

/// The two tuning variables require the file variable to be set too. The same
/// "half-configured reads as a mistake" rule `expected_token_typ_value` and
/// the Keycloak break-glass pair already follow: an operator who set a
/// refresh interval and mistyped (or forgot) the file variable should find
/// out at startup, not conclude after an incident that revocation had been
/// live the whole time.
///
/// The refresh/max-age relationship itself (max age must be at least the
/// refresh interval) is checked in the library's
/// `AgentRevocationList::start`, not here, mirroring where
/// `KeycloakConfig::validate` checks the equivalent JWKS pair rather than
/// `keycloak_env`.
pub(crate) fn agent_revocation_env_value(
    file: Option<&str>,
    refresh: Option<&str>,
    max_age: Option<&str>,
) -> Result<Option<AgentRevocationEnv>, io::Error> {
    let Some(file) = file else {
        if refresh.is_some() || max_age.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_AGENT_REVOCATION_REFRESH_SECS and APEX_CONTROL_AGENT_REVOCATION_MAX_AGE_SECS require APEX_CONTROL_AGENT_REVOCATION_FILE to be set",
            ));
        }
        return Ok(None);
    };
    let refresh = bounded_secs_value(
        refresh,
        DEFAULT_AGENT_REVOCATION_REFRESH_SECS,
        1,
        300,
        "APEX_CONTROL_AGENT_REVOCATION_REFRESH_SECS must be an integer from 1 through 300",
    )?;
    let max_age = bounded_secs_value(
        max_age,
        DEFAULT_AGENT_REVOCATION_MAX_AGE_SECS,
        1,
        3600,
        "APEX_CONTROL_AGENT_REVOCATION_MAX_AGE_SECS must be an integer from 1 through 3600",
    )?;
    Ok(Some(AgentRevocationEnv {
        file: PathBuf::from(file),
        refresh,
        max_age,
    }))
}
