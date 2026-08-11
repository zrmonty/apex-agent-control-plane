//! Token verification: the pure, network-free routine
//! [`super::KeycloakOperatorCredentialResolver::resolve`] runs a presented
//! bearer token through, plus its claim-mapping helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::auth::OperatorCaller;

use super::config::KeycloakConfig;
use super::{
    CLOCK_SKEW_LEEWAY_SECS, KeycloakRejection, MAX_CLAIM_ROLES, MAX_CLAIM_SCOPES, MAX_KID_BYTES,
    MAX_SUBJECT_CLAIM_BYTES, MAX_TOKEN_BYTES,
};

/// The single verification routine. Pure over `(config, keys, token)` plus the
/// system clock, so every rejection case below is unit-testable without a
/// network or a live Keycloak.
pub(crate) fn verify_token(
    config: &KeycloakConfig,
    keys: &JwkSet,
    token: &str,
) -> Result<OperatorCaller, KeycloakRejection> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(reject!("TOKEN_SIZE"));
    }
    // `decode_header` refuses `alg: none` on its own: `jsonwebtoken::Algorithm`
    // has no `none` variant, so the header fails to deserialize. Asserted by
    // `alg_none_token_is_refused` rather than assumed.
    let header = decode_header(token).map_err(|_| reject!("MALFORMED_HEADER"))?;
    let Some(kid) = header.kid.as_deref() else {
        // Without a `kid` the only options are "try every key" (which turns a
        // key set into an oracle and costs one signature verification per key
        // per bad token) or "guess". Keycloak always publishes one.
        return Err(reject!("MISSING_KID"));
    };
    if kid.is_empty() || kid.len() > MAX_KID_BYTES {
        return Err(reject!("KID_SIZE"));
    }
    let jwk = keys.find(kid).ok_or(reject!("UNKNOWN_KID"))?;
    let algorithm = signing_algorithm_for(jwk)?;
    // The token does not get to choose. The JWK does, and the header must
    // agree with it.
    if header.alg != algorithm {
        return Err(reject!("HEADER_ALG_DOES_NOT_MATCH_JWK"));
    }
    let key = DecodingKey::from_jwk(jwk).map_err(|_| reject!("UNUSABLE_JWK"))?;

    let mut validation = Validation::new(algorithm);
    // Exactly one permitted algorithm, taken from the JWK.
    validation.algorithms = vec![algorithm];
    validation.set_issuer(&[config.issuer.as_str()]);
    validation.set_audience(&[config.audience.as_str()]);
    // `Validation` only checks `iss`/`aud` when the claim is *present*. Making
    // them required is what turns those from advisory into enforced.
    validation.required_spec_claims = ["exp", "iss", "aud", "sub"]
        .iter()
        .map(|claim| (*claim).to_owned())
        .collect();
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.validate_aud = true;
    validation.leeway = CLOCK_SKEW_LEEWAY_SECS;

    let data = decode::<serde_json::Value>(token, &key, &validation)
        .map_err(|_| reject!("SIGNATURE_OR_REGISTERED_CLAIMS"))?;
    let claims = data
        .claims
        .as_object()
        .ok_or(reject!("CLAIMS_NOT_AN_OBJECT"))?;

    if let Some(expected) = &config.expected_typ {
        let typ = claims.get("typ").and_then(serde_json::Value::as_str);
        if typ != Some(expected.as_str()) {
            // An ID token or a refresh token carries the same realm signature
            // and, for an ID token, an `aud` equal to the client id.
            return Err(reject!("UNEXPECTED_TOKEN_TYP"));
        }
    }

    let now = unix_now();
    let exp = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or(reject!("MISSING_EXP"))?;
    let iat = claims
        .get("iat")
        .and_then(serde_json::Value::as_i64)
        .ok_or(reject!("MISSING_IAT"))?;
    if exp <= iat {
        return Err(reject!("NONSENSICAL_LIFETIME"));
    }
    if iat.saturating_sub(now) > CLOCK_SKEW_LEEWAY_SECS as i64 {
        return Err(reject!("IAT_IN_THE_FUTURE"));
    }
    if exp.saturating_sub(iat) as u64 > config.max_token_lifetime.as_secs() {
        return Err(reject!("TOKEN_LIFETIME_EXCEEDS_CEILING"));
    }

    let subject_claim = claims
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .ok_or(reject!("MISSING_SUB"))?;
    if subject_claim.is_empty() || subject_claim.len() > MAX_SUBJECT_CLAIM_BYTES {
        return Err(reject!("SUB_SIZE"));
    }
    // Prefixed so the audit trail distinguishes a Keycloak-issued operator
    // from a static table entry (`operator:static:<n>`) at a glance.
    // `OperatorCaller` enforces the ingest actor-identifier grammar on the
    // result, so a `sub` containing a space or a slash is refused here rather
    // than turning every command that operator sends into INVALID_COMMAND.
    let subject = format!("operator:keycloak:{subject_claim}");

    let scopes = scope_grants(config, claims)?;
    let roles = role_grants(config, claims)?;
    let global = match (&config.global_role, config.global_subjects.is_empty()) {
        (Some(role), false) => {
            config.global_subjects.contains(subject_claim)
                && roles.iter().any(|held| held == role)
        }
        _ => false,
    };

    if global {
        return OperatorCaller::global(subject).map_err(|_| reject!("SUBJECT_GRAMMAR"));
    }
    if scopes.is_empty() {
        // A credential that can act nowhere is a configuration failure, and
        // saying so at the credential boundary beats every command coming back
        // SCOPE_DENIED with no hint why.
        return Err(reject!("NO_MAPPED_SCOPES"));
    }
    OperatorCaller::scoped(subject, scopes).map_err(|_| reject!("SCOPE_GRAMMAR"))
}

/// The one algorithm this JWK may be used with, or a rejection.
fn signing_algorithm_for(jwk: &Jwk) -> Result<Algorithm, KeycloakRejection> {
    // Keycloak publishes an encryption key (RSA-OAEP) alongside the signing
    // key in the same JWKS. `use: enc` must never verify a token.
    if let Some(usage) = &jwk.common.public_key_use
        && *usage != PublicKeyUse::Signature
    {
        return Err(reject!("JWK_NOT_FOR_SIGNATURES"));
    }
    // A symmetric entry in a signing JWKS is the algorithm-confusion attack in
    // its most direct form: the verifier is handed key material it will treat
    // as an HMAC secret, and the attacker knows it because a JWKS is public.
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(reject!("SYMMETRIC_JWK_REFUSED"));
    }
    let Some(key_algorithm) = jwk.common.key_algorithm else {
        // Without `alg` on the JWK there is nothing to pin the token's header
        // against except the token itself, which is the thing being checked.
        return Err(reject!("JWK_WITHOUT_ALG"));
    };
    match key_algorithm {
        KeyAlgorithm::RS256 => Ok(Algorithm::RS256),
        KeyAlgorithm::RS384 => Ok(Algorithm::RS384),
        KeyAlgorithm::RS512 => Ok(Algorithm::RS512),
        KeyAlgorithm::PS256 => Ok(Algorithm::PS256),
        KeyAlgorithm::PS384 => Ok(Algorithm::PS384),
        KeyAlgorithm::PS512 => Ok(Algorithm::PS512),
        KeyAlgorithm::ES256 => Ok(Algorithm::ES256),
        KeyAlgorithm::ES384 => Ok(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Ok(Algorithm::EdDSA),
        // HS* and the RSA encryption algorithms are enumerated as refusals
        // rather than caught by a `_` arm, so adding a variant upstream is a
        // compile error here instead of a silent widening.
        KeyAlgorithm::HS256
        | KeyAlgorithm::HS384
        | KeyAlgorithm::HS512
        | KeyAlgorithm::RSA1_5
        | KeyAlgorithm::RSA_OAEP
        | KeyAlgorithm::RSA_OAEP_256 => Err(reject!("DISALLOWED_JWK_ALG")),
    }
}

/// Allow-listed `workspace/namespace` grants from the configured scope claim.
///
/// Accepts a JSON array of strings or a single space-separated string (the
/// OAuth `scope` shape), because a Keycloak protocol mapper can produce
/// either. Anything else is a rejection, not an empty result.
fn scope_grants(
    config: &KeycloakConfig,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>, KeycloakRejection> {
    let raw = match claim_at(claims, &config.scope_claim) {
        None => return Ok(Vec::new()),
        Some(value) => value,
    };
    let mut scopes: Vec<String> = Vec::new();
    match raw {
        serde_json::Value::Array(items) => {
            if items.len() > MAX_CLAIM_SCOPES {
                return Err(reject!("TOO_MANY_SCOPE_CLAIMS"));
            }
            for item in items {
                let entry = item.as_str().ok_or(reject!("MALFORMED_SCOPE_CLAIM"))?;
                scopes.push(entry.to_owned());
            }
        }
        serde_json::Value::String(raw) => {
            for entry in raw.split_whitespace() {
                if scopes.len() >= MAX_CLAIM_SCOPES {
                    return Err(reject!("TOO_MANY_SCOPE_CLAIMS"));
                }
                scopes.push(entry.to_owned());
            }
        }
        _ => return Err(reject!("MALFORMED_SCOPE_CLAIM")),
    }
    // The load-bearing rule. A wildcard in an IdP-controlled claim rejects the
    // whole credential; it never widens, and it is never quietly dropped.
    // Dropping it would hand back a narrower grant than the token asked for
    // and leave nobody aware the mapper is wrong.
    if scopes.iter().any(|scope| scope.contains('*')) {
        return Err(reject!("WILDCARD_IN_SCOPE_CLAIM"));
    }
    scopes.retain(|scope| !scope.is_empty());
    Ok(scopes)
}

fn role_grants(
    config: &KeycloakConfig,
    claims: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>, KeycloakRejection> {
    let Some(raw) = claim_at(claims, &config.role_claim) else {
        return Ok(Vec::new());
    };
    let serde_json::Value::Array(items) = raw else {
        return Err(reject!("MALFORMED_ROLE_CLAIM"));
    };
    if items.len() > MAX_CLAIM_ROLES {
        return Err(reject!("TOO_MANY_ROLE_CLAIMS"));
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or(reject!("MALFORMED_ROLE_CLAIM"))
        })
        .collect()
}

/// Resolves a dotted claim path against the token's claim object.
///
/// Only JSON *objects* are traversed. A claim whose own name contains a `.`
/// is therefore unaddressable, which is documented at the config surface --
/// the alternative (trying both interpretations) would make which claim is
/// consulted depend on the token's own shape.
fn claim_at<'a>(
    claims: &'a serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut segments = path.split('.');
    let mut current = claims.get(segments.next()?)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}
