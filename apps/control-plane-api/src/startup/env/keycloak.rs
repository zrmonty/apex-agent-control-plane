//! Everything the production (Keycloak) operator-credential path needs, read
//! from the environment.

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use super::{bounded_secs_value, optional, path, required};

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
