use super::*;
use crate::browser::oidc::config::tests::{config, discovery};
use crate::keycloak::tests::support::{KID, foreign_key, header, jwks, sign, signing_key};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const NONCE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const ACCESS: &str = "real-signed-access-token-requires-separate-authority-check";
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn claims() -> Value {
    let now = now();
    json!({"iss":config().issuer,"aud":config().client_id,"sub":"subject-123","iat":now,"exp":now+300,
        "nonce":NONCE,"typ":"ID","at_hash":URL_SAFE_NO_PAD.encode(&Sha256::digest(ACCESS.as_bytes())[..16])})
}
fn verifier() -> IdTokenVerifier {
    IdTokenVerifier::new(
        &config(),
        &serde_json::to_vec(&discovery()).unwrap(),
        &serde_json::to_vec(&jwks()).unwrap(),
    )
    .unwrap()
}
fn signed(claims: &Value) -> String {
    sign(&header(), claims, &signing_key())
}
fn check(value: &Value) -> Result<VerifiedLogin, BrowserError> {
    verifier().verify(
        &signed(value),
        ACCESS,
        IdTokenExpectation::Login { nonce: NONCE },
    )
}

#[test]
fn validates_real_rsa_signature_nonce_browser_audience_and_access_hash() {
    let value = claims();
    let result = check(&value).unwrap();
    assert_eq!(result.subject, "subject-123");
    assert_eq!(result.expires_at, value["exp"].as_i64().unwrap());
    assert!(!format!("{result:?}").contains("subject-123"));
    assert!(!format!("{:?}", verifier()).contains("identity.example"));
    let mut without_hash = value;
    without_hash.as_object_mut().unwrap().remove("at_hash");
    assert!(check(&without_hash).is_ok());
}

#[test]
fn issuer_is_exact_and_id_token_cannot_substitute_an_access_token() {
    assert!(check(&claims()).is_ok());
    for (field, bad) in [
        ("iss", "https://IDENTITY.example/realms/apex"),
        ("iss", "https://identity.example:443/realms/apex"),
        ("iss", "https://other.example/realms/apex"),
        ("aud", "apex-control-gateway"),
        ("sub", ""),
        ("sub", "bad/subject"),
        ("nonce", "wrong"),
        ("typ", "Bearer"),
        ("typ", "Refresh"),
    ] {
        let mut value = claims();
        value[field] = bad.into();
        assert!(check(&value).is_err(), "{field}: {bad}");
    }
    let mut missing = claims();
    missing.as_object_mut().unwrap().remove("nonce");
    assert!(check(&missing).is_err());
}

#[test]
fn signature_algorithm_kid_and_public_signing_key_are_pinned() {
    let verifier = verifier();
    let original = claims();
    assert!(
        verifier
            .verify(
                &sign(&header(), &original, &foreign_key()),
                ACCESS,
                IdTokenExpectation::Login { nonce: NONCE }
            )
            .is_err()
    );
    let mut wrong = header();
    wrong.kid = Some("unknown-key".into());
    assert!(
        verifier
            .verify(
                &sign(&wrong, &original, &signing_key()),
                ACCESS,
                IdTokenExpectation::Login { nonce: NONCE }
            )
            .is_err()
    );
    wrong.kid = None;
    assert!(
        verifier
            .verify(
                &sign(&wrong, &original, &signing_key()),
                ACCESS,
                IdTokenExpectation::Login { nonce: NONCE }
            )
            .is_err()
    );
    let mut hs = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    hs.kid = Some(KID.into());
    let token = jsonwebtoken::encode(
        &hs,
        &original,
        &jsonwebtoken::EncodingKey::from_secret(b"known-public-bytes"),
    )
    .unwrap();
    assert!(
        verifier
            .verify(&token, ACCESS, IdTokenExpectation::Login { nonce: NONCE })
            .is_err()
    );
    let mut wrong = header();
    wrong.typ = Some("at+jwt".into());
    assert!(
        verifier
            .verify(
                &sign(&wrong, &original, &signing_key()),
                ACCESS,
                IdTokenExpectation::Login { nonce: NONCE }
            )
            .is_err()
    );
}

#[test]
fn rejects_missing_expired_future_or_excessive_lifetimes() {
    assert!(check(&claims()).is_ok());
    for field in ["iss", "aud", "sub", "iat", "exp"] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(field);
        assert!(check(&value).is_err(), "{field}");
    }
    let now = now();
    // Exact 30/31-second boundaries belong to the deterministic temporal tests.
    for (iat, exp) in [
        (now - 300, now),
        (now + 120, now + 300),
        (now, now + 3601),
        (now, now - 1),
        (-1, now + 300),
    ] {
        let mut value = claims();
        value["iat"] = iat.into();
        value["exp"] = exp.into();
        assert!(check(&value).is_err());
    }
}

#[test]
fn additional_audiences_are_rejected_even_with_correct_authorized_party() {
    let mut value = claims();
    value["aud"] = json!(["apex-browser", "other"]);
    assert!(check(&value).is_err());
    value["azp"] = "other".into();
    assert!(check(&value).is_err());
    value["azp"] = "apex-browser".into();
    assert!(check(&value).is_err());
    value["aud"] = "apex-browser".into();
    value["azp"] = "other".into();
    assert!(check(&value).is_err());
}

#[test]
fn malformed_hash_is_not_treated_as_an_absent_hash() {
    assert!(check(&claims()).is_ok());
    for hash in [
        "",
        "not-base64",
        "AAAAAAAAAAAAAAAAAAAAAA",
        "AQEBAQEBAQEBAQEBAQEBAQ==",
    ] {
        let mut value = claims();
        value["at_hash"] = hash.into();
        assert!(check(&value).is_err());
    }
    assert!(
        verifier()
            .verify(
                &signed(&claims()),
                "other-access-token",
                IdTokenExpectation::Login { nonce: NONCE }
            )
            .is_err()
    );
}

#[test]
fn refresh_preserves_subject_and_checks_nonce_if_provider_returns_it() {
    let verifier = verifier();
    let mut value = claims();
    value.as_object_mut().unwrap().remove("nonce");
    assert!(
        verifier
            .verify(
                &signed(&value),
                ACCESS,
                IdTokenExpectation::Refresh {
                    subject: "subject-123",
                    original_nonce: NONCE
                }
            )
            .is_ok()
    );
    assert!(
        verifier
            .verify(
                &signed(&value),
                ACCESS,
                IdTokenExpectation::Refresh {
                    subject: "other",
                    original_nonce: NONCE
                }
            )
            .is_err()
    );
    value["nonce"] = "bad".into();
    assert!(
        verifier
            .verify(
                &signed(&value),
                ACCESS,
                IdTokenExpectation::Refresh {
                    subject: "subject-123",
                    original_nonce: NONCE
                }
            )
            .is_err()
    );
    value["nonce"] = NONCE.into();
    assert!(
        verifier
            .verify(
                &signed(&value),
                ACCESS,
                IdTokenExpectation::Refresh {
                    subject: "subject-123",
                    original_nonce: NONCE
                }
            )
            .is_ok()
    );
}

#[test]
fn jwks_rejects_duplicate_ids_private_symmetric_and_oversized_material() {
    let doc = serde_json::to_vec(&discovery()).unwrap();
    assert!(IdTokenVerifier::new(&config(), &doc, &serde_json::to_vec(&jwks()).unwrap()).is_ok());
    let original = serde_json::to_value(jwks()).unwrap();
    for field in ["d", "p", "q", "dp", "dq", "qi", "k"] {
        let mut value = original.clone();
        value["keys"][0][field] = "secret-canary".into();
        assert!(
            IdTokenVerifier::new(&config(), &doc, &serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
    let key = original["keys"][0].clone();
    for value in [
        json!({"keys":[]}),
        json!({"keys":[key.clone(),key]}),
        json!({"keys":[{"kid":"sym","kty":"oct","use":"sig","alg":"HS256","k":"secret"}]}),
    ] {
        assert!(
            IdTokenVerifier::new(&config(), &doc, &serde_json::to_vec(&value).unwrap()).is_err()
        );
    }
    let mut encryption = original.clone();
    encryption["keys"][0]["use"] = "enc".into();
    assert!(
        IdTokenVerifier::new(&config(), &doc, &serde_json::to_vec(&encryption).unwrap()).is_err()
    );
    let mut huge = original;
    huge["keys"][0]["n"] = "x".repeat(1400).into();
    assert!(IdTokenVerifier::new(&config(), &doc, &serde_json::to_vec(&huge).unwrap()).is_err());
}

#[test]
fn invalid_or_oversized_tokens_return_only_closed_errors() {
    let verifier = verifier();
    for token in [
        "secret-canary".to_owned(),
        "x".repeat(16385),
        "a.b.c.d".to_owned(),
    ] {
        let error = verifier
            .verify(&token, ACCESS, IdTokenExpectation::Login { nonce: NONCE })
            .unwrap_err();
        assert_eq!(error, BrowserError::Unauthenticated);
        assert!(!format!("{error} {error:?}").contains("secret-canary"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[path = "claim_tests.rs"]
mod claim_tests;
#[path = "jose_tests.rs"]
mod jose_tests;
#[path = "key_tests.rs"]
mod key_tests;
#[path = "temporal_tests.rs"]
mod temporal_tests;
