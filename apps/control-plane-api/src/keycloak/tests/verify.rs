//! Token-verification rejection taxonomy: every way [`super::support::verify`]
//! can refuse a presented credential, exercised offline against locally
//! minted tokens.

use std::collections::BTreeSet;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

use crate::keycloak::*;

use super::support::*;

#[test]
fn a_valid_token_maps_only_to_the_scopes_in_its_allow_listed_claim() {
    let caller = verify(&config(), &token()).expect("a genuine token must verify");
    assert_eq!(caller.subject(), format!("operator:keycloak:{SUBJECT}"));
    assert!(caller.allows_scope("acme", "prod"));
    // Everything not listed stays denied -- the claim grants, it never widens.
    assert!(!caller.allows_scope("acme", "staging"));
    assert!(!caller.allows_scope("other", "prod"));
}

#[test]
fn an_expired_token_is_refused() {
    let issued = now() - 4_000;
    let mut expired = claims();
    expired["iat"] = json!(issued);
    expired["exp"] = json!(issued + 300);
    let token = sign(&header(), &expired, &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "SIGNATURE_OR_REGISTERED_CLAIMS"
    );
}

#[test]
fn a_not_yet_valid_token_is_refused() {
    let mut future = claims();
    future["nbf"] = json!(now() + 3_600);
    let token = sign(&header(), &future, &signing_key());
    assert!(verify(&config(), &token).is_err());
}

#[test]
fn a_token_signed_by_a_different_key_under_the_same_kid_is_refused() {
    // The forgery a JWKS-backed verifier actually has to stop: the `kid`
    // selects the realm's real key, and the signature was made with another.
    let token = sign(&header(), &claims(), &foreign_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "SIGNATURE_OR_REGISTERED_CLAIMS"
    );
}

#[test]
fn a_token_with_an_unknown_kid_is_refused() {
    let mut header = header();
    header.kid = Some("some-other-realm-key".to_owned());
    let token = sign(&header, &claims(), &signing_key());
    assert_eq!(verify(&config(), &token).unwrap_err().reason(), "UNKNOWN_KID");
}

#[test]
fn a_token_without_a_kid_is_refused() {
    let mut header = header();
    header.kid = None;
    let token = sign(&header, &claims(), &signing_key());
    assert_eq!(verify(&config(), &token).unwrap_err().reason(), "MISSING_KID");
}

#[test]
fn alg_none_token_is_refused() {
    // The oldest JWT bug there is. Asserted rather than assumed to be a
    // library property, because "the library rejects it" is exactly the thing
    // that silently changes under a dependency bump.
    let token = forge(
        json!({ "alg": "none", "typ": "JWT", "kid": KID }),
        &claims(),
        "",
    );
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "MALFORMED_HEADER"
    );
    // ... and with a non-empty signature segment, in case emptiness was what
    // did the rejecting.
    let token = forge(
        json!({ "alg": "none", "typ": "JWT", "kid": KID }),
        &claims(),
        "AAAA",
    );
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "MALFORMED_HEADER"
    );
}

#[test]
fn an_hmac_token_signed_with_the_public_modulus_is_refused() {
    // Algorithm confusion: the attacker knows the RSA public key because a
    // JWKS is public, signs HS256 with it, and hopes the verifier picks its
    // algorithm from the token's header.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_owned());
    let token = sign(
        &header,
        &claims(),
        &EncodingKey::from_secret(SIGNING_KEY_MODULUS_B64URL.as_bytes()),
    );
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "HEADER_ALG_DOES_NOT_MATCH_JWK"
    );
}

#[test]
fn a_token_whose_header_alg_disagrees_with_the_jwk_is_refused() {
    // Same key family, different digest. The JWK says RS256; the token says
    // RS512. The JWK wins, and disagreement is a refusal rather than a
    // negotiation.
    let mut header = Header::new(Algorithm::RS512);
    header.kid = Some(KID.to_owned());
    let token = sign(&header, &claims(), &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "HEADER_ALG_DOES_NOT_MATCH_JWK"
    );
}

#[test]
fn a_symmetric_jwk_never_verifies_anything() {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID.to_owned());
    let token = sign(
        &header,
        &claims(),
        &EncodingKey::from_secret(SIGNING_KEY_MODULUS_B64URL.as_bytes()),
    );
    // Even when the key set itself offers a symmetric key under that kid --
    // a misconfigured or attacker-influenced JWKS -- it is refused outright.
    assert_eq!(
        verify_token(&config(), &symmetric_jwks(), &token)
            .unwrap_err()
            .reason(),
        "SYMMETRIC_JWK_REFUSED"
    );
}

#[test]
fn an_encryption_key_never_verifies_a_signature() {
    assert_eq!(
        verify_token(&config(), &encryption_jwks(), &token())
            .unwrap_err()
            .reason(),
        "JWK_NOT_FOR_SIGNATURES"
    );
}

#[test]
fn a_token_from_another_issuer_is_refused() {
    let mut other = claims();
    other["iss"] = json!("https://keycloak.invalid/realms/not-apex");
    let token = sign(&header(), &other, &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "SIGNATURE_OR_REGISTERED_CLAIMS"
    );
}

#[test]
fn a_token_for_another_audience_is_refused() {
    let mut other = claims();
    other["aud"] = json!("some-other-client");
    let token = sign(&header(), &other, &signing_key());
    assert!(verify(&config(), &token).is_err());
}

#[test]
fn a_token_with_no_issuer_or_audience_claim_at_all_is_refused() {
    // `jsonwebtoken`'s default is to validate `iss`/`aud` only when present.
    // Omitting them must not be a way past the check.
    for missing in ["iss", "aud", "sub", "exp"] {
        let mut claims = claims();
        claims
            .as_object_mut()
            .expect("claims object")
            .remove(missing);
        let token = sign(&header(), &claims, &signing_key());
        assert!(
            verify(&config(), &token).is_err(),
            "a token with no {missing} claim must be refused"
        );
    }
}

#[test]
fn an_id_token_is_not_an_operator_credential() {
    // Keycloak signs ID tokens with the same realm key, and an ID token's
    // `aud` is the client id -- which is exactly what this gateway's expected
    // audience is. `typ` is the thing that tells them apart.
    let mut id_token = claims();
    id_token["typ"] = json!("ID");
    let token = sign(&header(), &id_token, &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "UNEXPECTED_TOKEN_TYP"
    );
}

#[test]
fn a_token_living_longer_than_the_configured_ceiling_is_refused() {
    let issued = now();
    let mut long_lived = claims();
    long_lived["iat"] = json!(issued);
    long_lived["exp"] = json!(issued + 86_400);
    let token = sign(&header(), &long_lived, &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "TOKEN_LIFETIME_EXCEEDS_CEILING"
    );
}

#[test]
fn a_token_without_iat_is_refused() {
    let mut no_iat = claims();
    no_iat.as_object_mut().expect("claims object").remove("iat");
    let token = sign(&header(), &no_iat, &signing_key());
    assert_eq!(verify(&config(), &token).unwrap_err().reason(), "MISSING_IAT");
}

#[test]
fn a_wildcard_in_the_scope_claim_rejects_the_whole_token() {
    // The rule that matters. An identity provider claim may never confer the
    // global operator scope, and a wildcard is not silently dropped either --
    // dropping it would hand back a partial grant with nobody aware the
    // mapper is wrong.
    for wildcard in [json!(["*"]), json!(["acme/prod", "*"]), json!(["acme/*"])] {
        let mut over_broad = claims();
        over_broad["apex_control_scopes"] = wildcard.clone();
        let token = sign(&header(), &over_broad, &signing_key());
        assert_eq!(
            verify(&config(), &token).unwrap_err().reason(),
            "WILDCARD_IN_SCOPE_CLAIM",
            "{wildcard} must reject the credential"
        );
    }
}

#[test]
fn a_role_claim_alone_cannot_confer_the_global_scope() {
    // Break-glass role present, local subject allow-list empty: no `*`. This
    // is the over-broad-group-mapping case the local allow-list exists for.
    let mut config = config();
    config.global_role = Some("apex-control-break-glass".to_owned());
    config.global_subjects = BTreeSet::new();
    // Half-configured break-glass is refused at startup rather than silently
    // meaning "disabled", so assert that first...
    assert!(config.validate().is_err());

    // ... and then that with the allow-list configured but *not* containing
    // this subject, the same token still gets only its narrow scopes.
    config.global_subjects = ["99999999-9999-4999-8999-999999999999".to_owned()]
        .into_iter()
        .collect();
    config.validate().expect("fully configured break-glass is valid");
    let mut escalating = claims();
    escalating["realm_access"] = json!({ "roles": ["apex-control-break-glass"] });
    let token = sign(&header(), &escalating, &signing_key());
    let caller = verify(&config, &token).expect("the token is otherwise valid");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(
        !caller.allows_scope("someone-elses-workspace", "prod"),
        "a role claim must not confer the global operator scope on its own"
    );
}

#[test]
fn break_glass_requires_the_role_and_the_local_subject_allow_list_together() {
    let mut config = config();
    config.global_role = Some("apex-control-break-glass".to_owned());
    config.global_subjects = [SUBJECT.to_owned()].into_iter().collect();
    config.validate().expect("valid break-glass configuration");

    // Allow-listed subject, but without the role: narrow scopes only.
    let caller = verify(&config, &token()).expect("valid token");
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));

    // Allow-listed subject *and* the role: global.
    let mut break_glass = claims();
    break_glass["realm_access"] = json!({ "roles": ["apex-control-break-glass"] });
    let token = sign(&header(), &break_glass, &signing_key());
    let caller = verify(&config, &token).expect("valid token");
    assert!(caller.allows_scope("someone-elses-workspace", "prod"));
    assert_eq!(caller.subject(), format!("operator:keycloak:{SUBJECT}"));
}

#[test]
fn a_credential_with_no_mapped_scope_is_refused_rather_than_issued_empty() {
    for empty in [json!([]), json!("")] {
        let mut scopeless = claims();
        scopeless["apex_control_scopes"] = empty;
        let token = sign(&header(), &scopeless, &signing_key());
        assert_eq!(
            verify(&config(), &token).unwrap_err().reason(),
            "NO_MAPPED_SCOPES"
        );
    }
    let mut absent = claims();
    absent
        .as_object_mut()
        .expect("claims object")
        .remove("apex_control_scopes");
    let token = sign(&header(), &absent, &signing_key());
    assert_eq!(
        verify(&config(), &token).unwrap_err().reason(),
        "NO_MAPPED_SCOPES"
    );
}

#[test]
fn a_malformed_scope_claim_is_refused_rather_than_partially_honoured() {
    for malformed in [json!({ "acme": "prod" }), json!([1, 2, 3]), json!(true)] {
        let mut bad = claims();
        bad["apex_control_scopes"] = malformed.clone();
        let token = sign(&header(), &bad, &signing_key());
        assert_eq!(
            verify(&config(), &token).unwrap_err().reason(),
            "MALFORMED_SCOPE_CLAIM",
            "{malformed} must be refused"
        );
    }
}

#[test]
fn a_scope_entry_outside_the_workspace_namespace_grammar_is_refused() {
    for bad in [json!(["not-a-scope"]), json!(["ac me/prod"]), json!(["a/b/c"])] {
        let mut claims = claims();
        claims["apex_control_scopes"] = bad.clone();
        let token = sign(&header(), &claims, &signing_key());
        assert_eq!(
            verify(&config(), &token).unwrap_err().reason(),
            "SCOPE_GRAMMAR",
            "{bad} must be refused"
        );
    }
}

#[test]
fn a_space_separated_scope_claim_is_accepted() {
    // A Keycloak protocol mapper can emit either shape depending on how it is
    // configured; both must map to the same narrow grant.
    let mut claims = claims();
    claims["apex_control_scopes"] = json!("acme/prod acme/staging");
    let token = sign(&header(), &claims, &signing_key());
    let caller = verify(&config(), &token).expect("valid token");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(caller.allows_scope("acme", "staging"));
    assert!(!caller.allows_scope("acme", "dev"));
}

#[test]
fn a_subject_that_could_never_be_an_actor_id_is_refused() {
    for bad in ["has space", "has/slash", "double..dot"] {
        let mut claims = claims();
        claims["sub"] = json!(bad);
        let token = sign(&header(), &claims, &signing_key());
        assert_eq!(
            verify(&config(), &token).unwrap_err().reason(),
            "SCOPE_GRAMMAR",
            "{bad:?} must be refused as an operator subject"
        );
    }
}

#[test]
fn a_nested_role_claim_path_is_resolved() {
    let mut config = config();
    config.role_claim = "resource_access.apex-control-gateway.roles".to_owned();
    config.global_role = Some("break-glass".to_owned());
    config.global_subjects = [SUBJECT.to_owned()].into_iter().collect();
    let mut claims = claims();
    claims["resource_access"] = json!({
        "apex-control-gateway": { "roles": ["break-glass"] },
        "some-other-client": { "roles": ["irrelevant"] },
    });
    let token = sign(&header(), &claims, &signing_key());
    let caller = verify(&config, &token).expect("valid token");
    assert!(caller.allows_scope("anything", "anywhere"));
}

#[test]
fn a_role_claim_at_a_path_that_does_not_exist_confers_nothing() {
    let mut config = config();
    config.role_claim = "resource_access.absent-client.roles".to_owned();
    config.global_role = Some("break-glass".to_owned());
    config.global_subjects = [SUBJECT.to_owned()].into_iter().collect();
    let caller = verify(&config, &token()).expect("valid token");
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));
}

#[test]
fn an_oversized_token_is_refused_before_it_is_parsed() {
    let token = "a".repeat(MAX_TOKEN_BYTES + 1);
    assert_eq!(verify(&config(), &token).unwrap_err().reason(), "TOKEN_SIZE");
}
