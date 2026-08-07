//! Offline verification tests for [`super`].
//!
//! Every rejection the resolver has to make is exercised here against locally
//! minted tokens, so the whole taxonomy is covered in ordinary unit CI with no
//! network. `tests/live_control_keycloak.rs` then proves the same code path
//! against a *real* Keycloak's real JWKS and real issued tokens, because a
//! hand-rolled JWT mock can agree with a hand-rolled verifier while both
//! disagree with the identity provider.
//!
//! ## About the key material below
//!
//! `SIGNING_KEY_PKCS1_DER_B64` and `FOREIGN_KEY_PKCS1_DER_B64` are throwaway
//! RSA-2048 keypairs generated once for these tests. They authenticate nothing,
//! are never loaded by the binary, and exist only so the positive path can be
//! signed and the "signed by a different key" path can be forged. They are
//! stored as bare base64 DER rather than PEM so a repository secret scanner
//! does not have to decide whether a `-----BEGIN RSA PRIVATE KEY-----` block in
//! a `#[cfg(test)]` module is a leak; the encoding is not a security measure
//! and is not treated as one.

use std::collections::BTreeSet;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;

use super::*;

const SIGNING_KEY_PKCS1_DER_B64: &str = concat!(
    "MIIEpAIBAAKCAQEAlPt733Fp39LRjB0mg1rdduYnO6Kpcu0E0iRr4X60nxqR5l9WA5NE+Zibs+",
    "8J5LxEWhSjffD407qzrCWqIazDr+1YTIdUw1aca8x2fo4J3AFCmN+p0i52nxMXmtvvdOd3g4tG",
    "4zqxupentq5WFuyovjAG/pBWlO9I/sk4P9VX3LPNI91x2ZBi/AmyZNyqS2D6GL3N7BWbbbsy25",
    "0pl0HprObv4CXVHDtYDG7yYNO6dRWsMPH9eG+BIFQ9hPRqUqlK5uhlBLqitmQz1/c2douBAsC9",
    "PTBN9dSPn0XlAwBfHobX+0yBiWUVbfmb+CF4KuHJt7Y9KvsKY/7mwtTXuYhlUwIDAQABAoIBAB",
    "Qd/0SVSnAcRgpu9z/eebAv9NVDKjFoGvILU/vvgZFIY7IhZnp2HOa9Oi0qVoIp/+rQBaGgc+EX",
    "QWK59Ua1zvjHCljPH11/KQEPa2K8aE1qaCU/cm18s6zYRaQ2FZgKF2POX0SYrN4e01lCIkLXMx",
    "P3ZUJjmCVlSEyLPEq2UrZs5iqq8tHdyFMF4aWVqk/P5GKT6d/Q1M7tmEx+nnFqToNzg0RrppDv",
    "AdzlH8hyTIs/Nti7n4ULK0PvCuvJpXrrayGz7h57N3f5ekdhVyxdEcogGVyj7x9gNmzPXD+M6f",
    "nHVNzVvKdAtRaFW3CXm9uvVgT2t77865Q6H3dZH3Z9tn0CgYEAz+GgqhKA99GsNDdPE74nU3NY",
    "bX6KPDT3IygUgE/kOjRhLa41l9UhLMsaFleCeybL8Vt0AguSz/MBvQeUazabE2XD9wR/tvIA7m",
    "Re9J5P62jJWDJ8oTe0y/xZm0F2wnVzpEODnW/MrfbMDjxhIWMBiryNy73G7emLoqO5HS9poq0C",
    "gYEAt3exgYfkf4WoGAErD8pUgUz35jqGC6ts8AIEtQXLAdJm0EVDzH+vAqhF1zQOcBs458aCGN",
    "rXcnjjZJfqJllI9Dp7wSwIPX+KTXRMz5nxfq9GdK9d8/R0u2fbm/ypfXSxDx5yr3NzR4ljy43t",
    "e5zAvMCOnIJYYp/6jsHP9O2DJ/8CgYANDxp9tJ3fc4+C1DqmfdqQln1mm31pnNYtojXvfZVTxr",
    "iYGwqI2D22R6gC4Up0HBLRvbIC8uEtKRHh4xkCxzJkvI7b9K9lObyvPSTt7wgMPM/xN3K22f4E",
    "lny2kR05yBEUr50UBdLw1sEo38gmRcbyBThPJUPa7EH2XJyjZbgYHQKBgQCV+N29CJycMWGK3c",
    "mZiscxOv2Z0VUpzOOr/bpjT2z2/ErXDQey7tzcyzjsBb2XnmkR7Y8DSkC7bl5TKGtbFbkxC22G",
    "JrxFqTAgyGTRfwGNkTGCyKeAd9/EIc2+4PabevwRY85T5Yfifkh5aHcsiKJ0qOLqxRIC7MsgTw",
    "XzLQP9eQKBgQCLao6IDwE26pefzp1Umg9cmqQckUrJAjHA6zTN6lGQZkmzH51hl2GzXLfvzAFK",
    "WW/IG4GfxC/d6ZOBcLbhS+XblyHwhSir9ejeISMlwoa4bxjzl7od4m2nUHWoAtpvYTRzIQ04xk",
    "Wcg0+NR5wh3b8EKnZb3tJxRWpmFsiADbzigA==",
);

const FOREIGN_KEY_PKCS1_DER_B64: &str = concat!(
    "MIIEpAIBAAKCAQEAxoaLoeYHfslrRFM/6UjxVRe9pdF5C91nz52u4vUWPw+B0Ej7hZTslHRmAd",
    "Eg2oOpgv05At6FLIbJkbpHXomRF51Ld6EkpckwJHQqTHM8HIygAGnrhczk+y5tNcHiFkFjEojW",
    "61HxQqG7G6cQKhOl2857e8xhKeDSNyAeEosf/LpfKfSBhiyQxq9hpx4Br5pGO9cVeYxa1elL+P",
    "xuuZ7FD1y54PBAQLfVyKalJQfVLXEiNxjWOjM85l9i5iNk0OTBepZBtLUgiOkLaFGhCCMMe1Td",
    "UkJR1qeJ2pXXxQzE9VU1te6s1qZRHuHEx2uETKxhl8FqfnLi13EuW4M5VigaJQIDAQABAoIBAA",
    "NmeYzH1lgHFiXA8UbLH4sQEYj+Cf84hxcowb6UaRGib9xD677xeo3eYoLkdJYZjDU4phnU+t30",
    "3w32bVOCsq//WzQM2AZY6FCvhqvxi1WH2RO4vLZ5eHCO7oLts7Qi4ZIHMvsr16CHCZ/jICVAWe",
    "ZmZnoL2ZwwhBk6nRk/NciL1uxY2AwuqegcalqCI7yMw/kiJDWoSRVCN1eCD3GV7DRkgVL8rBjW",
    "MAmQn5LbA281u4RXk6JQcmQvLdRPhfAG656zoTEIkv+Q/N5kYJr+qYy35ihtoYQsmYiB2OgcLD",
    "XxqTnXdJPiKuNVsLFlFm4lzVdM9bUb/u4Gb0MpVRsBns8CgYEA6RCh6Br/WwfUdVJ/sDB4Vcyi",
    "h9F3RAKwJbWPzzHok+hp2mxhsr2UQraGNcUTIHTIVbxA/2OeZ7ehMaSbqfXVPDgftjj9dzqEka",
    "Q6Vfrh0cGcTsewzF4R9TfkCwWuILyFH+Lwd/riyd/zxHSWtYpn/D/GeVQqa1k8g9ky+WqATBcC",
    "gYEA2g/MEQgJCrFwp3kcJyXYf3Pau4sBa8SsTEx0gJgpo65744/s1mBLZm1Qo33tHR96OOgQSk",
    "M8EdE4qKYjqv5xU2Zwo7wVnaSabV0twgP1C+LIqdWI+09HTtL0+9omH3aIb1aLKtxHLCJncCsy",
    "zylMYXF0Yid//bPyAZtg845wxSMCgYEA1BRigEcw3rD9T9VGhBlXJxwTOewNz0Fy8J2Kw0vzC8",
    "SNrki5jmCcrShScFNo2DvsoLexnbQUzOR4NihHzhz5cNbRZIvvebMyNyVuQBcPrkOz7Kwh4ZYo",
    "WTAGv1Dn5rolmaJ0l3khLfowZDCDg6bygMO342gHQa/uNTxL+lJDdPkCgYAvIncDv27k5tHpAV",
    "66f426jvpay4M1Hj/4BhawrTNi9BZHbBbPh+UEcOCbVl7oiqNKpa7PvpS/bTAIFFFlZrZsRppW",
    "ahNqDehrd1aqt1xCg3TIcSW43LwXJ7ZYsiDHcEGxf015qD+iJJWjQ1MqQE0ISxPTG6Ko3jqTal",
    "icjM+HbQKBgQDoIYXOWfXy3Xxku1MStw7KiG5dG8IdC6bSadnC2c3Q3edP8EeKiATSNClPTGKF",
    "Sj6gj2zf1Mn9IpIHWIfGfs0hdVQIC2qKVY07BXFGaPnJE70CLKzr2HrXWlXB41/TewLOxOrBbm",
    "X0+uKooNyNC+A7CaEQqPJTZTrvzwv4pYTbag==",
);

const SIGNING_KEY_MODULUS_B64URL: &str = concat!(
    "lPt733Fp39LRjB0mg1rdduYnO6Kpcu0E0iRr4X60nxqR5l9WA5NE-Zibs-",
    "8J5LxEWhSjffD407qzrCWqIazDr-1YTIdUw1aca8x2fo4J3AFCmN-",
    "p0i52nxMXmtvvdOd3g4tG4zqxupentq5WFuyovjAG_pBWlO9I_sk4P9VX3LPNI91x2ZBi_AmyZ",
    "NyqS2D6GL3N7BWbbbsy250pl0HprObv4CXVHDtYDG7yYNO6dRWsMPH9eG-",
    "BIFQ9hPRqUqlK5uhlBLqitmQz1_c2douBAsC9PTBN9dSPn0XlAwBfHobX-0yBiWUVbfmb-",
    "CF4KuHJt7Y9KvsKY_7mwtTXuYhlUw",
);

const KID: &str = "apex-control-test-sig";
const ISSUER: &str = "https://keycloak.invalid/realms/apex";
const AUDIENCE: &str = "apex-control-gateway";
const SUBJECT: &str = "11111111-2222-4333-8444-555555555555";

fn signing_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&B64.decode(SIGNING_KEY_PKCS1_DER_B64).expect("fixture DER"))
}

fn foreign_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&B64.decode(FOREIGN_KEY_PKCS1_DER_B64).expect("fixture DER"))
}

/// The realm's published signing key, in the shape Keycloak publishes it.
fn jwks() -> JwkSet {
    serde_json::from_value(json!({
        "keys": [{
            "kid": KID,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": SIGNING_KEY_MODULUS_B64URL,
            "e": "AQAB",
        }]
    }))
    .expect("fixture JWKS must parse")
}

/// A JWKS carrying the realm's *encryption* key under the same `kid`, which is
/// how a "just use the key with this kid" verifier gets pointed at material it
/// must not verify with.
fn encryption_jwks() -> JwkSet {
    serde_json::from_value(json!({
        "keys": [{
            "kid": KID,
            "kty": "RSA",
            "alg": "RSA-OAEP",
            "use": "enc",
            "n": SIGNING_KEY_MODULUS_B64URL,
            "e": "AQAB",
        }]
    }))
    .expect("fixture JWKS must parse")
}

/// A symmetric JWK published under the signing `kid`. The whole point of the
/// algorithm-confusion class of bug.
fn symmetric_jwks() -> JwkSet {
    serde_json::from_value(json!({
        "keys": [{
            "kid": KID,
            "kty": "oct",
            "alg": "HS256",
            "use": "sig",
            "k": SIGNING_KEY_MODULUS_B64URL,
        }]
    }))
    .expect("fixture JWKS must parse")
}

fn config() -> KeycloakConfig {
    KeycloakConfig {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        jwks_url: KeycloakConfig::default_jwks_url(ISSUER),
        jwks_ca_pem: b"-----BEGIN CERTIFICATE-----\nunused-in-offline-tests\n-----END CERTIFICATE-----\n".to_vec(),
        jwks_refresh: Duration::from_secs(300),
        jwks_max_age: Duration::from_secs(900),
        scope_claim: "apex_control_scopes".to_owned(),
        role_claim: "realm_access.roles".to_owned(),
        global_role: None,
        global_subjects: BTreeSet::new(),
        max_token_lifetime: Duration::from_secs(3600),
        expected_typ: Some("Bearer".to_owned()),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Claims in the shape a Keycloak access token carries them.
fn claims() -> serde_json::Value {
    let issued = now();
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUBJECT,
        "typ": "Bearer",
        "iat": issued,
        "exp": issued + 300,
        "apex_control_scopes": ["acme/prod"],
        "realm_access": { "roles": ["apex-control-operator"] },
    })
}

fn header() -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header
}

fn sign(header: &Header, claims: &serde_json::Value, key: &EncodingKey) -> String {
    jsonwebtoken::encode(header, claims, key).expect("fixture token must sign")
}

fn token() -> String {
    sign(&header(), &claims(), &signing_key())
}

/// Assembles an arbitrary `header.payload.signature` triple, for the shapes a
/// well-behaved signing library refuses to produce.
fn forge(header: serde_json::Value, claims: &serde_json::Value, signature: &str) -> String {
    format!(
        "{}.{}.{}",
        B64URL.encode(serde_json::to_vec(&header).expect("header")),
        B64URL.encode(serde_json::to_vec(claims).expect("claims")),
        signature
    )
}

fn verify(config: &KeycloakConfig, token: &str) -> Result<OperatorCaller, KeycloakRejection> {
    verify_token(config, &jwks(), token)
}

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
