//! [`crate::keycloak::KeycloakOperatorCredentialResolver`] tests: the
//! staleness fail-closed contract, and the single indistinguishable rejection
//! reported through the live `OperatorCredentialResolver` trait path (as
//! opposed to [`super::verify`]'s tests, which drive `verify_token` directly).

use std::time::Duration;

use serde_json::json;

use crate::auth::OperatorCredentialResolver;
use crate::keycloak::KeycloakOperatorCredentialResolver;

use super::support::*;

#[test]
fn a_stale_key_cache_fails_closed_rather_than_trusting_keys_of_unknown_age() {
    // A one-second ceiling, not a one-millisecond one. The first attempt below
    // has to land *inside* the window, and a millisecond is not reliably
    // longer than "construct a resolver, then verify an RSA signature" on a
    // loaded CI runner -- which is exactly how this first went red on GitHub
    // Actions while passing locally. One second is orders of magnitude more
    // than the work between the two assertions and still keeps the test fast.
    let mut config = config();
    config.jwks_refresh = Duration::from_secs(1);
    config.jwks_max_age = Duration::from_secs(1);
    let resolver = KeycloakOperatorCredentialResolver::with_static_jwks(config, jwks())
        .expect("resolver must build");
    let token = token();
    assert!(resolver.resolve(&token).is_ok(), "fresh keys must verify");
    std::thread::sleep(Duration::from_millis(1_400));
    assert!(!resolver.keys_are_fresh());
    let error = resolver.resolve(&token).unwrap_err();
    assert_eq!(
        error.code,
        crate::errors::CommandErrorCode::CredentialVerifierUnavailable,
        "a stale key cache must refuse, and must say why rather than claiming the credential is bad"
    );
}

#[test]
fn the_resolver_reports_one_indistinguishable_error_for_every_verification_failure() {
    let resolver = KeycloakOperatorCredentialResolver::with_static_jwks(config(), jwks())
        .expect("resolver must build");
    let mut expired = claims();
    expired["iat"] = json!(now() - 4_000);
    expired["exp"] = json!(now() - 3_700);
    for bad in [
        sign(&header(), &expired, &signing_key()),
        sign(&header(), &claims(), &foreign_key()),
        "not-a-jwt".to_owned(),
    ] {
        let error = resolver.resolve(&bad).unwrap_err();
        assert_eq!(
            error.code,
            crate::errors::CommandErrorCode::Unauthenticated,
            "a prober must not be able to tell verification failures apart"
        );
    }
    // ... and the genuine article still works through the same resolver.
    assert!(resolver.resolve(&token()).is_ok());
}
