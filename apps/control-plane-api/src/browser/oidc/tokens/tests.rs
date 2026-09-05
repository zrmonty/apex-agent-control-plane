use super::*;
use crate::browser::oidc::config::tests::{config, discovery};
use crate::keycloak::tests::support::{header, jwks, sign, signing_key};
use crate::{KeycloakConfig, KeycloakOperatorCredentialResolver};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const NONCE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn verifier() -> IdTokenVerifier {
    IdTokenVerifier::new(
        &config(),
        &serde_json::to_vec(&discovery()).unwrap(),
        &serde_json::to_vec(&jwks()).unwrap(),
    )
    .unwrap()
}
pub(crate) fn resolver() -> KeycloakOperatorCredentialResolver {
    KeycloakOperatorCredentialResolver::with_static_jwks(
        KeycloakConfig {
            issuer: config().issuer,
            audience: "apex-control-gateway".into(),
            jwks_url: config().jwks_uri,
            jwks_ca_pem: vec![1],
            jwks_refresh: Duration::from_secs(60),
            jwks_max_age: Duration::from_secs(120),
            scope_claim: "apex_control_scopes".into(),
            role_claim: "realm_access.roles".into(),
            global_role: None,
            global_subjects: BTreeSet::new(),
            max_token_lifetime: Duration::from_secs(3600),
            expected_typ: Some("Bearer".into()),
        },
        jwks(),
    )
    .unwrap()
}
pub(crate) fn access_claims() -> Value {
    json!({"iss":config().issuer,"aud":"apex-control-gateway","sub":"subject-123","typ":"Bearer","iat":now()-1,"exp":now()+240,"apex_control_scopes":["work/ns"]})
}
pub(crate) fn material(access_claims: Value, id_subject: &str) -> TokenMaterial {
    let access = sign(&header(), &access_claims, &signing_key());
    let id = sign(
        &header(),
        &json!({"iss":config().issuer,"aud":config().client_id,"sub":id_subject,"iat":now(),"exp":now()+300,"nonce":NONCE,"typ":"ID","at_hash":URL_SAFE_NO_PAD.encode(&Sha256::digest(access.as_bytes())[..16])}),
        &signing_key(),
    );
    TokenMaterial {
        access: Zeroizing::new(access),
        refresh: Zeroizing::new("rotated-refresh-canary".into()),
        id_token: Some(Zeroizing::new(id)),
        access_lifetime: 300,
        refresh_lifetime: 1800,
    }
}
fn login(material: TokenMaterial) -> Result<VerifiedProviderTokens, BrowserError> {
    validate_exchange(
        &config(),
        material,
        &verifier(),
        &resolver(),
        IdTokenExpectation::Login { nonce: NONCE },
        now(),
    )
}

#[test]
fn separately_signed_id_and_access_tokens_must_have_the_same_verified_subject() {
    let access = access_claims();
    let expiry = access["exp"].as_i64().unwrap();
    let result = login(material(access, "subject-123")).unwrap();
    assert_eq!(result.subject, "subject-123");
    assert_eq!(result.access_expires_at, expiry);
    assert!(result.refresh_expires_at >= now() + 1799);
    assert_eq!(result.refresh.as_str(), "rotated-refresh-canary");
    assert!(!format!("{result:?}").contains("subject-123"));
    assert!(!format!("{result:?}").contains("canary"));
    assert!(
        resolver()
            .resolve(&result.access)
            .unwrap()
            .allows_scope("work", "ns")
    );
    assert!(login(material(access_claims(), "other-subject")).is_err());
}

#[test]
fn a_valid_id_token_cannot_supply_access_authority_or_widen_scopes() {
    assert!(login(material(access_claims(), "subject-123")).is_ok());
    for (field, value) in [
        ("aud", json!("apex-browser")),
        ("typ", json!("ID")),
        ("iss", json!("https://wrong.example")),
        ("apex_control_scopes", json!(["*"])),
    ] {
        let mut access = access_claims();
        access[field] = value;
        assert!(login(material(access, "subject-123")).is_err(), "{field}");
    }
    let mut absent = access_claims();
    absent
        .as_object_mut()
        .unwrap()
        .remove("apex_control_scopes");
    assert!(login(material(absent, "subject-123")).is_err());
}

#[test]
fn refresh_without_id_token_still_requires_original_subject_and_access_grants() {
    let mut input = material(access_claims(), "subject-123");
    input.id_token = None;
    let result = validate_exchange(
        &config(),
        input,
        &verifier(),
        &resolver(),
        IdTokenExpectation::Refresh {
            subject: "subject-123",
            original_nonce: NONCE,
        },
        now(),
    )
    .unwrap();
    assert_eq!(result.subject, "subject-123");
    let mut input = material(access_claims(), "subject-123");
    input.id_token = None;
    assert!(
        validate_exchange(
            &config(),
            input,
            &verifier(),
            &resolver(),
            IdTokenExpectation::Refresh {
                subject: "other",
                original_nonce: NONCE
            },
            now()
        )
        .is_err()
    );
    let mut input = material(access_claims(), "subject-123");
    input.id_token = None;
    assert!(login(input).is_err());
    let input = material(access_claims(), "other");
    assert!(
        validate_exchange(
            &config(),
            input,
            &verifier(),
            &resolver(),
            IdTokenExpectation::Refresh {
                subject: "subject-123",
                original_nonce: NONCE
            },
            now()
        )
        .is_err()
    );
}

#[test]
fn stored_access_expiry_is_conservative_and_never_uses_resource_server_leeway() {
    let mut input = material(access_claims(), "subject-123");
    input.access_lifetime = 60;
    let started = now() - 5;
    let result = validate_exchange(
        &config(),
        input,
        &verifier(),
        &resolver(),
        IdTokenExpectation::Login { nonce: NONCE },
        started,
    )
    .unwrap();
    assert_eq!(result.access_expires_at, started + 60);
    assert_eq!(result.refresh_expires_at, started + 1800);
    let mut expired = access_claims();
    expired["exp"] = (now() - 1).into();
    expired["iat"] = (now() - 120).into();
    // The independent resource server permits its configured 30-second skew;
    // sessions must not store a token as currently live using that allowance.
    let input = material(expired, "subject-123");
    assert!(resolver().resolve(&input.access).is_ok());
    assert!(login(input).is_err());
}

#[test]
fn invalid_clock_window_and_unusable_material_fail_without_secret_errors() {
    for started in [-1, i64::MAX, now() + 120, now() - 120] {
        assert!(
            validate_exchange(
                &config(),
                material(access_claims(), "subject-123"),
                &verifier(),
                &resolver(),
                IdTokenExpectation::Login { nonce: NONCE },
                started
            )
            .is_err()
        );
    }
    let mut input = material(access_claims(), "subject-123");
    input.access = Zeroizing::new("access-secret-canary".into());
    let error = login(input).unwrap_err();
    assert_eq!(error, BrowserError::Unauthenticated);
    assert!(!format!("{error:?}").contains("canary"));
}

#[test]
fn verifier_outage_is_unavailable_not_a_claim_of_bad_credentials() {
    struct Unavailable;
    impl OperatorCredentialResolver for Unavailable {
        fn resolve(&self, _token: &str) -> Result<crate::OperatorCaller, crate::CommandError> {
            Err(crate::CommandError::credential_verifier_unavailable())
        }
    }
    let error = validate_exchange(
        &config(),
        material(access_claims(), "subject-123"),
        &verifier(),
        &Unavailable,
        IdTokenExpectation::Login { nonce: NONCE },
        now(),
    )
    .unwrap_err();
    assert_eq!(error, BrowserError::Unavailable);
}

#[path = "clock_tests.rs"]
mod clock_tests;
