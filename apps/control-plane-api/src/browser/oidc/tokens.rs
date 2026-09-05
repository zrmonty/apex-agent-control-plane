//! Join separately verified OIDC login identity and operator access authority.
use super::{
    config::OidcConfig,
    protocol::TokenMaterial,
    verify::{IdTokenExpectation, IdTokenVerifier},
};
use crate::browser::security::OpaqueToken;
use crate::{OperatorCredentialResolver, browser::errors::BrowserError};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub struct VerifiedProviderTokens {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub subject: String,
    pub access_expires_at: i64,
    pub refresh_expires_at: i64,
}
impl std::fmt::Debug for VerifiedProviderTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedProviderTokens([REDACTED])")
    }
}
pub(super) fn validate_exchange(
    config: &OidcConfig,
    material: TokenMaterial,
    id_verifier: &IdTokenVerifier,
    resolver: &dyn OperatorCredentialResolver,
    expectation: IdTokenExpectation<'_>,
    started_at: i64,
) -> Result<VerifiedProviderTokens, BrowserError> {
    validate_exchange_with_clock(
        config,
        material,
        id_verifier,
        resolver,
        expectation,
        started_at,
        unix_now,
    )
}
fn validate_exchange_with_clock(
    config: &OidcConfig,
    material: TokenMaterial,
    id_verifier: &IdTokenVerifier,
    resolver: &dyn OperatorCredentialResolver,
    expectation: IdTokenExpectation<'_>,
    started_at: i64,
    clock: impl Fn() -> Result<i64, BrowserError>,
) -> Result<VerifiedProviderTokens, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    let now = clock()?;
    if started_at < 0
        || now
            .checked_sub(started_at)
            .is_none_or(|elapsed| !(0..=10).contains(&elapsed))
        || !(1..=3600).contains(&material.access_lifetime)
        || !(1..=86400).contains(&material.refresh_lifetime)
    {
        return Err(invalid);
    }
    for value in [&material.access, &material.refresh] {
        if value.is_empty()
            || value.len() > 4096
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(invalid);
        }
    }
    let caller = resolver
        .resolve(&material.access)
        .map_err(|error| BrowserError::from_credential_error(&error))?;
    let subject = match expectation {
        IdTokenExpectation::Login { nonce } => {
            id_verifier
                .verify(
                    material.id_token.as_deref().ok_or(invalid)?,
                    &material.access,
                    IdTokenExpectation::Login { nonce },
                )?
                .subject
        }
        IdTokenExpectation::Refresh {
            subject,
            original_nonce,
        } => {
            OpaqueToken::parse(original_nonce).map_err(|_| invalid)?;
            if let Some(id_token) = material.id_token.as_deref() {
                id_verifier.verify(
                    id_token,
                    &material.access,
                    IdTokenExpectation::Refresh {
                        subject,
                        original_nonce,
                    },
                )?;
            }
            subject.to_owned()
        }
    };
    if caller.subject() != format!("operator:keycloak:{subject}") {
        return Err(invalid);
    }
    // The existing resolver already authenticated these bytes. Parse the same
    // payload strictly to bind identity and cap storage expiry; never use this
    // parsing step as signature verification or as a source of permission grants.
    let parts: Vec<_> = material.access.split('.').take(4).collect();
    if parts.len() != 3 {
        return Err(invalid);
    }
    let payload = Zeroizing::new(URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid)?);
    let claims = crate::contract_json::parse_unique_json(&payload).map_err(|_| invalid)?;
    if claims.get("iss").and_then(serde_json::Value::as_str) != Some(config.issuer.as_str())
        || claims.get("sub").and_then(serde_json::Value::as_str) != Some(subject.as_str())
        || claims.get("typ").and_then(serde_json::Value::as_str) != Some("Bearer")
    {
        return Err(invalid);
    }
    let signed_expiry = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .ok_or(invalid)?;
    let access_expires_at = started_at
        .checked_add(i64::try_from(material.access_lifetime).map_err(|_| invalid)?)
        .ok_or(invalid)?
        .min(signed_expiry);
    let refresh_expires_at = started_at
        .checked_add(i64::try_from(material.refresh_lifetime).map_err(|_| invalid)?)
        .ok_or(invalid)?;
    // Verification may consume the remaining lifetime. Check a fresh sample
    // without reanchoring either copied lifetime or the signed expiry cap.
    let finished_at = clock()?;
    if finished_at < now
        || finished_at
            .checked_sub(started_at)
            .is_none_or(|elapsed| !(0..=10).contains(&elapsed))
        || access_expires_at <= finished_at
        || refresh_expires_at <= finished_at
    {
        return Err(invalid);
    }
    Ok(VerifiedProviderTokens {
        access: material.access,
        refresh: material.refresh,
        subject,
        access_expires_at,
        refresh_expires_at,
    })
}

pub(super) fn unix_now() -> Result<i64, BrowserError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BrowserError::Unavailable)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| BrowserError::Unavailable)
}

#[cfg(test)]
pub(crate) mod tests;
