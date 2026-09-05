use super::BrowserError;
use serde_json::Value;

/// Checks authenticated integer time claims against one caller-supplied epoch
/// second and returns expiration. `nbf` is optional, but when present must be an
/// i64 integer no later than `now`; it receives no extra skew allowance.
///
/// # Errors
/// Returns `Unauthenticated` for malformed dates, disallowed timing/lifetime,
/// or arithmetic overflow. The caller must authenticate the payload first.
pub(super) fn validate(claims: &Value, now: i64) -> Result<i64, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    let iat = claims.get("iat").and_then(Value::as_i64).ok_or(invalid)?;
    let exp = claims.get("exp").and_then(Value::as_i64).ok_or(invalid)?;
    let lifetime = exp.checked_sub(iat).ok_or(invalid)?;
    let latest_issuance = now.checked_add(30).ok_or(invalid)?;
    if iat < 0 || iat > latest_issuance || !(1..=3600).contains(&lifetime) || exp <= now {
        return Err(invalid);
    }
    // Inspect presence before conversion: null must not become an absent nbf.
    if let Some(nbf) = claims.get("nbf") {
        let nbf = nbf.as_i64().ok_or(invalid)?;
        if nbf > now {
            return Err(invalid);
        }
    }
    Ok(exp)
}
