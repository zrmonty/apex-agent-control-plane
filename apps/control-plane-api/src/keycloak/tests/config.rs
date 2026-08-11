//! [`super::support::config`]/[`crate::keycloak::KeycloakConfig::validate`]
//! rejection tests.

use std::time::Duration;

use crate::keycloak::KeycloakConfig;

use super::support::config;

#[test]
fn config_validation_refuses_a_plaintext_or_credentialed_endpoint() {
    for issuer in [
        "http://keycloak.invalid/realms/apex",
        "https://user:pass@keycloak.invalid/realms/apex",
        "https://keycloak.invalid/realms/apex#fragment",
        "not-a-url",
        "",
    ] {
        let mut config = config();
        config.issuer = issuer.to_owned();
        config.jwks_url = KeycloakConfig::default_jwks_url(issuer);
        assert!(
            config.validate().is_err(),
            "{issuer:?} must be refused as an issuer"
        );
    }
}

/// Keycloak puts `account` on the `aud` of essentially every token in a realm.
/// Accepting it as *this* gateway's audience would make the audience check
/// vacuous -- any client's token in the realm would pass -- and it is exactly
/// the value someone copies out of a decoded token when unsure which of the
/// two `aud` entries is theirs.
#[test]
fn config_validation_refuses_keycloaks_universal_account_audience() {
    let mut config = config();
    config.audience = "account".to_owned();
    assert!(config.validate().is_err());
}

#[test]
fn config_validation_refuses_a_staleness_ceiling_below_the_refresh_interval() {
    let mut config = config();
    config.jwks_refresh = Duration::from_secs(600);
    config.jwks_max_age = Duration::from_secs(300);
    assert!(config.validate().is_err());
}

#[test]
fn config_validation_refuses_a_malformed_claim_path() {
    for path in ["", ".", "a..b", "a.b.c.d.e.f.g.h.i"] {
        let mut config = config();
        config.scope_claim = path.to_owned();
        assert!(
            config.validate().is_err(),
            "{path:?} must be refused as a claim path"
        );
    }
}
