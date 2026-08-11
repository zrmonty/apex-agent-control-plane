//! Keycloak resolver configuration: the validated, redacted-on-error shape
//! [`super::KeycloakOperatorCredentialResolver::start`] takes.

use std::collections::BTreeSet;
use std::time::Duration;

use super::{MAX_CLAIM_PATH_DEPTH, MAX_SUBJECT_CLAIM_BYTES};

/// A refused Keycloak resolver configuration. Carries a static reason and
/// never the configured URL, audience, or any secret material -- startup
/// errors are printed, and this is the one place a misconfiguration could
/// otherwise leak an internal issuer URL into a log aggregator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeycloakConfigError(pub(super) &'static str);

impl std::fmt::Display for KeycloakConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid Keycloak operator credential configuration: {}", self.0)
    }
}

impl std::error::Error for KeycloakConfigError {}

/// Verifier configuration.
///
/// The CA arrives as **PEM bytes**, not a path, on purpose: path confinement
/// under `APEX_CONTROL_TRUSTED_SECRET_BASE` lives in the binary's
/// `startup::secrets`, which is not part of this library crate. Doing the
/// reading there and passing bytes here keeps exactly one implementation of
/// the trusted-secret policy instead of a second, subtly different one.
#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    /// Exact expected `iss`, e.g. `https://sso.example.com/realms/apex`.
    pub issuer: String,
    /// Exact expected member of `aud` -- this gateway's client/audience.
    pub audience: String,
    /// Where the signing keys are fetched from. Defaults to
    /// `{issuer}/protocol/openid-connect/certs` (see
    /// [`KeycloakConfig::default_jwks_url`]).
    pub jwks_url: String,
    /// CA that the JWKS endpoint's server certificate must chain to. The
    /// client trusts *only* this, never a platform root store.
    pub jwks_ca_pem: Vec<u8>,
    /// Background refresh interval. Also the upper bound on how long a key
    /// Keycloak has rotated away keeps validating, while refreshes succeed.
    pub jwks_refresh: Duration,
    /// Hard staleness ceiling. Once the cached JWKS is older than this the
    /// resolver refuses every credential rather than trusting keys of unknown
    /// age -- the bounded window for a *compromised* key, when refreshes are
    /// failing.
    pub jwks_max_age: Duration,
    /// Dotted path to the allow-listed scope claim.
    pub scope_claim: String,
    /// Dotted path to the allow-listed role claim (`realm_access.roles` for a
    /// Keycloak realm role).
    pub role_claim: String,
    /// Role that, together with a `sub` in [`Self::global_subjects`], maps to
    /// the `*` break-glass scope. `None` means `*` is unreachable.
    pub global_role: Option<String>,
    /// Locally-configured `sub` allow-list for the `*` scope. Empty means `*`
    /// is unreachable.
    pub global_subjects: BTreeSet<String>,
    /// Ceiling on `exp - iat`.
    pub max_token_lifetime: Duration,
    /// Required payload `typ`. `None` disables the check (explicitly opting
    /// out of ID-token/refresh-token confusion protection).
    pub expected_typ: Option<String>,
}

impl KeycloakConfig {
    /// The standard Keycloak JWKS location for a realm issuer.
    pub fn default_jwks_url(issuer: &str) -> String {
        format!(
            "{}/protocol/openid-connect/certs",
            issuer.trim_end_matches('/')
        )
    }

    /// Rejects a configuration that could never verify anything, or that would
    /// verify the wrong thing.
    ///
    /// Deliberately **not** a same-origin requirement between the issuer and
    /// the JWKS URL. Split-horizon deployments legitimately publish an
    /// external issuer (`https://sso.example.com/realms/apex`) while resolving
    /// keys over an internal service address, and a same-origin rule would
    /// break that for no gain: an attacker who can rewrite this process's
    /// environment can rewrite the issuer and audience too, so the rule would
    /// only ever catch an operator typo -- which the `iss` check already
    /// catches, because keys from the wrong realm do not carry the right
    /// `kid`, and a token from the wrong realm fails the issuer comparison
    /// regardless. Overriding the JWKS URL is an assertion that it serves the
    /// configured issuer's keys, and is documented as such.
    pub fn validate(&self) -> Result<(), KeycloakConfigError> {
        check_https_url(&self.issuer, "APEX_CONTROL_KEYCLOAK_ISSUER")?;
        check_https_url(&self.jwks_url, "APEX_CONTROL_KEYCLOAK_JWKS_URL")?;
        if self.audience.is_empty()
            || self.audience.len() > 256
            || !self.audience.is_ascii()
            || self.audience.chars().any(char::is_control)
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_AUDIENCE must be non-empty printable ASCII under 256 bytes",
            ));
        }
        // `account` is on the `aud` of essentially every token Keycloak issues
        // in a realm, by default. Configuring it as *this* gateway's expected
        // audience makes the audience check vacuous: any token for any client
        // in the realm would satisfy it. That is not a hypothetical typo --
        // it is the value an operator reads out of a decoded token and copies
        // when they are not sure which of the two entries is theirs.
        if self.audience == "account" {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_AUDIENCE must not be 'account': Keycloak puts that on every token in the realm, so the audience check would accept any client's token",
            ));
        }
        if self.jwks_ca_pem.is_empty() {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_CA_FILE produced no certificate material",
            ));
        }
        check_claim_path(&self.scope_claim, "APEX_CONTROL_KEYCLOAK_SCOPE_CLAIM")?;
        check_claim_path(&self.role_claim, "APEX_CONTROL_KEYCLOAK_ROLE_CLAIM")?;
        if let Some(role) = &self.global_role
            && (role.is_empty() || role.len() > 256 || !role.is_ascii())
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE must be non-empty ASCII under 256 bytes",
            ));
        }
        if self.global_subjects.len() > 64 {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS lists more than 64 break-glass subjects",
            ));
        }
        for subject in &self.global_subjects {
            if subject.is_empty()
                || subject.len() > MAX_SUBJECT_CLAIM_BYTES
                || !subject.is_ascii()
                || subject.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(KeycloakConfigError(
                    "APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS contains a malformed subject",
                ));
            }
        }
        // A `*` grant that nobody can reach is fine and is the default. A
        // half-configured one is not: it reads like break-glass is set up when
        // it is not, and the operator finds out during the incident.
        if self.global_role.is_some() == self.global_subjects.is_empty() {
            return Err(KeycloakConfigError(
                "set APEX_CONTROL_KEYCLOAK_GLOBAL_ROLE and APEX_CONTROL_KEYCLOAK_GLOBAL_SUBJECTS together, or neither",
            ));
        }
        if self.jwks_refresh.is_zero() || self.jwks_max_age < self.jwks_refresh {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_JWKS_MAX_AGE_SECS must be at least the refresh interval",
            ));
        }
        if self.max_token_lifetime.is_zero() {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_MAX_TOKEN_LIFETIME_SECS must be positive",
            ));
        }
        if let Some(typ) = &self.expected_typ
            && (typ.len() > 64 || !typ.is_ascii() || typ.chars().any(char::is_control))
        {
            return Err(KeycloakConfigError(
                "APEX_CONTROL_KEYCLOAK_EXPECTED_TYP must be short printable ASCII",
            ));
        }
        Ok(())
    }
}

fn check_https_url(raw: &str, label: &'static str) -> Result<(), KeycloakConfigError> {
    let _ = label;
    if raw.len() > 512
        || !raw.is_ascii()
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(KeycloakConfigError(
            "issuer/JWKS URL must be printable ASCII under 512 bytes",
        ));
    }
    let url = reqwest::Url::parse(raw)
        .map_err(|_| KeycloakConfigError("issuer/JWKS URL is not a URL"))?;
    // Plaintext is refused with no escape hatch, matching every other
    // transport this crate opens. A JWKS fetched over HTTP is a set of signing
    // keys an on-path attacker chooses.
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(KeycloakConfigError(
            "issuer/JWKS URL must be https with no credentials or fragment",
        ));
    }
    Ok(())
}

fn check_claim_path(path: &str, label: &'static str) -> Result<(), KeycloakConfigError> {
    let _ = label;
    let segments: Vec<&str> = path.split('.').collect();
    if path.is_empty()
        || path.len() > 256
        || !path.is_ascii()
        || segments.len() > MAX_CLAIM_PATH_DEPTH
        || segments.iter().any(|segment| segment.is_empty())
    {
        return Err(KeycloakConfigError(
            "claim path must be 1..=8 non-empty dot-separated ASCII segments",
        ));
    }
    Ok(())
}
