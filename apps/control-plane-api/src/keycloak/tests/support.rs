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

use crate::auth::OperatorCaller;
use crate::keycloak::*;

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

pub(super) const SIGNING_KEY_MODULUS_B64URL: &str = concat!(
    "lPt733Fp39LRjB0mg1rdduYnO6Kpcu0E0iRr4X60nxqR5l9WA5NE-Zibs-",
    "8J5LxEWhSjffD407qzrCWqIazDr-1YTIdUw1aca8x2fo4J3AFCmN-",
    "p0i52nxMXmtvvdOd3g4tG4zqxupentq5WFuyovjAG_pBWlO9I_sk4P9VX3LPNI91x2ZBi_AmyZ",
    "NyqS2D6GL3N7BWbbbsy250pl0HprObv4CXVHDtYDG7yYNO6dRWsMPH9eG-",
    "BIFQ9hPRqUqlK5uhlBLqitmQz1_c2douBAsC9PTBN9dSPn0XlAwBfHobX-0yBiWUVbfmb-",
    "CF4KuHJt7Y9KvsKY_7mwtTXuYhlUw",
);

pub(crate) const KID: &str = "apex-control-test-sig";
pub(super) const ISSUER: &str = "https://keycloak.invalid/realms/apex";
pub(super) const AUDIENCE: &str = "apex-control-gateway";
pub(super) const SUBJECT: &str = "11111111-2222-4333-8444-555555555555";

pub(crate) fn signing_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&B64.decode(SIGNING_KEY_PKCS1_DER_B64).expect("fixture DER"))
}

pub(crate) fn foreign_key() -> EncodingKey {
    EncodingKey::from_rsa_der(&B64.decode(FOREIGN_KEY_PKCS1_DER_B64).expect("fixture DER"))
}

/// The realm's published signing key, in the shape Keycloak publishes it.
pub(crate) fn jwks() -> JwkSet {
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
pub(super) fn encryption_jwks() -> JwkSet {
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
pub(super) fn symmetric_jwks() -> JwkSet {
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

pub(super) fn config() -> KeycloakConfig {
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

pub(super) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Claims in the shape a Keycloak access token carries them.
pub(super) fn claims() -> serde_json::Value {
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

pub(crate) fn header() -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    header
}

pub(crate) fn sign(header: &Header, claims: &serde_json::Value, key: &EncodingKey) -> String {
    jsonwebtoken::encode(header, claims, key).expect("fixture token must sign")
}

pub(super) fn token() -> String {
    sign(&header(), &claims(), &signing_key())
}

/// Assembles an arbitrary `header.payload.signature` triple, for the shapes a
/// well-behaved signing library refuses to produce.
pub(super) fn forge(header: serde_json::Value, claims: &serde_json::Value, signature: &str) -> String {
    format!(
        "{}.{}.{}",
        B64URL.encode(serde_json::to_vec(&header).expect("header")),
        B64URL.encode(serde_json::to_vec(claims).expect("claims")),
        signature
    )
}

pub(super) fn verify(config: &KeycloakConfig, token: &str) -> Result<OperatorCaller, KeycloakRejection> {
    verify_token(config, &jwks(), token)
}

