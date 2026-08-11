//! Half one: `KeycloakOperatorCredentialResolver` driven directly against
//! the live realm. See the crate root's module doc for the full "why".

use std::time::Duration;

use apex_control_plane_api::{CommandErrorCode, KeycloakConfig, OperatorCredentialResolver};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;

use super::support::*;

#[test]
fn a_real_keycloak_token_maps_to_exactly_the_scopes_its_claim_carries() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let caller = resolver(|_| {})
        .resolve(&token)
        .expect("a genuine, in-date Keycloak token must verify");
    assert_eq!(
        caller.subject(),
        format!("operator:keycloak:{}", subject_of(&token))
    );
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("acme", "staging"));
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));
}

/// Keycloak's JWKS publishes an `RSA-OAEP` / `use: enc` key next to the
/// signing key, in every realm, by default. A verifier that selected a key by
/// `kid` without checking what the key is *for* would be one realm-config
/// change away from verifying signatures with encryption material.
#[test]
fn the_live_jwks_really_does_publish_an_encryption_key_alongside_the_signing_key() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let ca = lab_ca();
    let url = format!(
        "{}/realms/apex/protocol/openid-connect/certs",
        keycloak_base()
    );
    let body = std::thread::spawn(move || {
        apex_control_plane_api::install_rustls_provider();
        reqwest::blocking::Client::builder()
            .use_rustls_tls()
            .tls_certs_only([reqwest::Certificate::from_pem(&ca).expect("lab CA")])
            .timeout(Duration::from_secs(20))
            .build()
            .expect("client")
            .get(&url)
            .send()
            .expect("JWKS must be reachable")
            .text()
            .expect("JWKS body")
    })
    .join()
    .expect("jwks thread");
    let jwks: serde_json::Value = serde_json::from_str(&body).expect("JWKS must be JSON");
    let keys = jwks["keys"].as_array().expect("JWKS carries keys");
    assert!(
        keys.iter().any(|key| key["use"] == "enc"),
        "expected the realm to publish an encryption key; if Keycloak stops doing that, the JWK_NOT_FOR_SIGNATURES guard is still correct but this test no longer proves it: {body}"
    );
    assert!(keys.iter().any(|key| key["use"] == "sig"));
}

#[test]
fn a_genuinely_expired_keycloak_token_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Minted by a client whose access.token.lifespan is one second, so this is
    // a real Keycloak signature over a real payload that has simply aged out
    // -- not a hand-edited `exp`.
    let token = mint_token(
        "apex",
        "apex-control-shortlived",
        "apex-control-lab-shortlived-secret",
    );
    let resolver = resolver(|_| {});
    // Past the one-second lifespan *and* past the 30s clock-skew leeway.
    std::thread::sleep(Duration::from_secs(35));
    let error = resolver.resolve(&token).unwrap_err();
    assert_eq!(error.code, CommandErrorCode::Unauthenticated);
}

#[test]
fn a_keycloak_token_that_is_simply_not_short_lived_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Twelve-hour lifespan, real signature, in date. Nothing about the
    // signature or the registered claims is wrong; it is refused purely
    // because "short-lived" is enforced rather than assumed.
    let token = mint_token(
        "apex",
        "apex-control-longlived",
        "apex-control-lab-longlived-secret",
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
    // ... and it verifies once the deployment's ceiling actually permits that
    // lifetime, which is what proves the refusal above was the ceiling and not
    // something else about the token.
    let permissive = resolver(|config: &mut KeycloakConfig| {
        config.max_token_lifetime = Duration::from_secs(86_400)
    });
    assert!(permissive.resolve(&token).is_ok());
}

#[test]
fn a_token_from_another_realm_on_the_same_keycloak_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Same client id, same audience mapper, different realm -- so the only
    // things that differ are the issuer and the signing key.
    let token = mint_token("other", AUDIENCE, "apex-control-lab-other-realm-secret");
    assert_eq!(
        claims_of(&token)["iss"].as_str(),
        Some(OTHER_ISSUER),
        "the fixture realm must actually be a different issuer"
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn a_real_token_with_a_tampered_signature_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let resolver = resolver(|_| {});
    assert!(resolver.resolve(&token).is_ok(), "control: unmodified");

    let (message, signature) = token.rsplit_once('.').expect("a JWT has three parts");
    let mut bytes = B64URL.decode(signature).expect("signature must be base64url");
    bytes[0] ^= 0x01;
    let tampered = format!("{message}.{}", B64URL.encode(&bytes));
    assert_eq!(
        resolver.resolve(&tampered).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn an_alg_none_token_over_a_real_payload_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = scoped_token();
    let kid = kid_of(&token);
    let resolver = resolver(|_| {});
    for signature in ["", "AAAA"] {
        let forged = forge(
            serde_json::json!({ "alg": "none", "typ": "JWT", "kid": kid }),
            &token,
            signature,
        );
        assert_eq!(
            resolver.resolve(&forged).unwrap_err().code,
            CommandErrorCode::Unauthenticated
        );
    }
}

#[test]
fn an_hmac_token_over_a_real_payload_and_the_realms_own_kid_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    // Algorithm confusion against live material: the attacker has the realm's
    // public key (a JWKS is public) and its `kid`, signs the untouched payload
    // with HS256, and hopes the verifier takes its algorithm from the header.
    let token = scoped_token();
    let kid = kid_of(&token);
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(kid);
    let forged = jsonwebtoken::encode(
        &header,
        &claims_of(&token),
        &jsonwebtoken::EncodingKey::from_secret(b"the realm public key would go here"),
    )
    .expect("forgery must encode");
    assert_eq!(
        resolver(|_| {}).resolve(&forged).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

#[test]
fn a_token_whose_audience_is_another_service_is_refused() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-wrong-audience",
        "apex-control-lab-wrong-audience-secret",
    );
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

/// The rule the vault doc's principle translates to at this boundary: an
/// identity-provider claim can never confer the `*` global operator scope.
#[test]
fn a_real_token_carrying_a_wildcard_scope_claim_is_refused_outright() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-overbroad",
        "apex-control-lab-overbroad-secret",
    );
    assert_eq!(
        claims_of(&token)["apex_control_scopes"],
        serde_json::json!(["*"]),
        "the fixture client must actually emit a wildcard scope claim"
    );
    // Not narrowed to nothing, not partially honoured: refused.
    assert_eq!(
        resolver(|_| {}).resolve(&token).unwrap_err().code,
        CommandErrorCode::Unauthenticated
    );
}

/// Break-glass needs the role *and* the locally-configured subject
/// allow-list. The role alone is the realistic failure -- an over-broad
/// group-to-role mapping in Keycloak -- and it must not be enough.
#[test]
fn the_break_glass_role_alone_does_not_confer_the_global_scope() {
    if !live_enabled() {
        eprintln!("skip live Keycloak: set APEX_CONTROL_LIVE_KEYCLOAK=1");
        return;
    }
    let token = mint_token(
        "apex",
        "apex-control-break-glass",
        "apex-control-lab-break-glass-secret",
    );
    let roles = claims_of(&token)["realm_access"]["roles"].clone();
    assert!(
        roles
            .as_array()
            .expect("realm_access.roles must be an array")
            .iter()
            .any(|role| role == "apex-control-break-glass"),
        "the fixture client must actually carry the break-glass realm role: {roles}"
    );
    let subject = subject_of(&token);

    // Role present, subject not allow-listed: narrow scopes only.
    let not_allow_listed = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = ["00000000-0000-4000-8000-000000000000".to_owned()]
            .into_iter()
            .collect();
    });
    let caller = not_allow_listed
        .resolve(&token)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(
        !caller.allows_scope("someone-elses-workspace", "prod"),
        "a Keycloak role must not confer the global operator scope on its own"
    );

    // Role present and subject allow-listed: global.
    let allow_listed = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = [subject.clone()].into_iter().collect();
    });
    let caller = allow_listed
        .resolve(&token)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("someone-elses-workspace", "prod"));

    // Allow-listed but the role withdrawn in Keycloak: back to narrow scopes.
    // This is the revocation path -- removing the role has to be sufficient.
    let scoped = scoped_token();
    let scoped_subject = subject_of(&scoped);
    let both_configured = resolver(|config| {
        config.global_role = Some("apex-control-break-glass".to_owned());
        config.global_subjects = [scoped_subject].into_iter().collect();
    });
    let caller = both_configured
        .resolve(&scoped)
        .expect("the token is otherwise valid");
    assert!(caller.allows_scope("acme", "prod"));
    assert!(!caller.allows_scope("someone-elses-workspace", "prod"));
}

