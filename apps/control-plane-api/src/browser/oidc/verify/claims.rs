use super::*;
use crate::{auth::OperatorCaller, browser::security::OpaqueToken};
use openid::{Claims, StandardClaims, validation};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub(super) fn verify(
    verifier: &IdTokenVerifier,
    payload: &[u8],
    access: &str,
    expectation: IdTokenExpectation<'_>,
) -> Result<VerifiedLogin, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    let value = crate::contract_json::parse_unique_json(payload).map_err(|_| invalid)?;
    // URL normalization must not turn a different literal issuer into ours.
    if value.get("iss").and_then(Value::as_str) != Some(verifier.issuer.as_str())
        || value
            .get("typ")
            .is_some_and(|kind| kind.as_str() != Some("ID"))
    {
        return Err(invalid);
    }
    let subject = value.get("sub").and_then(Value::as_str).ok_or(invalid)?;
    // Only validates the event-compatible subject grammar, grants no authority.
    OperatorCaller::scoped(
        format!("operator:keycloak:{subject}"),
        std::iter::empty::<String>(),
    )
    .map_err(|_| invalid)?;
    if subject.is_empty() {
        return Err(invalid);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid)?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| invalid)?;
    let exp = temporal::validate(&value, now)?;
    // This profile trusts only the configured browser audience, not additional
    // audiences merely accompanied by a matching authorized party.
    let audience = match value.get("aud") {
        Some(Value::String(audience)) => Some(audience.as_str()),
        Some(Value::Array(audiences)) => match audiences.as_slice() {
            [audience] => audience.as_str(),
            _ => None,
        },
        _ => None,
    };
    if audience != Some(verifier.client_id.as_str())
        || value
            .get("azp")
            .is_some_and(|azp| azp.as_str() != Some(verifier.client_id.as_str()))
    {
        return Err(invalid);
    }
    let expected_nonce = match expectation {
        IdTokenExpectation::Login { nonce } => Some(nonce),
        IdTokenExpectation::Refresh {
            subject: original,
            original_nonce,
        } => {
            if original != subject {
                return Err(invalid);
            }
            OpaqueToken::parse(original_nonce).map_err(|_| invalid)?;
            value.get("nonce").map(|_| original_nonce)
        }
    };
    if let Some(nonce) = expected_nonce {
        OpaqueToken::parse(nonce).map_err(|_| invalid)?;
    }
    let claims: StandardClaims = serde_json::from_value(value.clone()).map_err(|_| invalid)?;
    validation::validate_token_issuer(&claims, &verifier.discovery).map_err(|_| invalid)?;
    validation::validate_token_nonce(&claims, expected_nonce).map_err(|_| invalid)?;
    validation::validate_token_aud(&claims, &verifier.client_id).map_err(|_| invalid)?;
    validation::validate_token_exp(&claims, None).map_err(|_| invalid)?;
    if value.get("at_hash").is_some() {
        let hash = claims.at_hash().ok_or(invalid)?;
        if hash.len() != 22 {
            return Err(invalid);
        }
        let mut actual = [0_u8; 16];
        if URL_SAFE_NO_PAD
            .decode_slice(hash, &mut actual)
            .map_err(|_| invalid)?
            != actual.len()
        {
            return Err(invalid);
        }
        if !bool::from(
            actual
                .as_slice()
                .ct_eq(&Sha256::digest(access.as_bytes())[..16]),
        ) {
            return Err(invalid);
        }
    }
    Ok(VerifiedLogin {
        subject: subject.to_owned(),
        expires_at: exp,
    })
}
