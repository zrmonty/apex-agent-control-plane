use super::*;
use openid::biscuit::{Empty, jwk::{AlgorithmParameters, JWK}};
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) fn signing_keys(raw: &[u8]) -> Result<BTreeMap<String, RSAKeyParameters>, BrowserError> {
    let invalid = BrowserError::Unavailable;
    if raw.len() > 65536 { return Err(invalid); }
    let value = crate::contract_json::parse_unique_json(raw).map_err(|_| invalid)?;
    let entries = value.get("keys").and_then(Value::as_array).ok_or(invalid)?;
    if entries.is_empty() || entries.len() > 64 { return Err(invalid); }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeMap::new();
    for entry in entries {
        let object = entry.as_object().ok_or(invalid)?;
        // Never accept private or shared-secret material from a public JWKS,
        // including a null private parameter that serde would treat as absent.
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"].iter().any(|field| object.contains_key(*field))
            || entry.get("kty").and_then(Value::as_str) == Some("oct") {
            return Err(invalid);
        }
        let kid = entry.get("kid").and_then(Value::as_str).ok_or(invalid)?;
        if kid.is_empty() || kid.len() > 128 || !kid.bytes().all(|byte| byte.is_ascii_graphic())
            || !ids.insert(kid.to_owned()) { return Err(invalid); }
        // This deployment profile deliberately supports only RS256 signing.
        if entry.get("kty").and_then(Value::as_str) != Some("RSA")
            || entry.get("use").and_then(Value::as_str) != Some("sig")
            || entry.get("alg").and_then(Value::as_str) != Some("RS256") { continue; }
        if let Some(operations) = entry.get("key_ops") {
            let operations = operations.as_array().ok_or(invalid)?;
            if operations.len() != 1 || operations[0].as_str() != Some("verify") { return Err(invalid); }
        }
        let modulus = public_integer(entry.get("n").and_then(Value::as_str).ok_or(invalid)?, 1024)?;
        let bits = modulus.len() * 8 - modulus[0].leading_zeros() as usize;
        if !(2048..=8192).contains(&bits) { return Err(invalid); }
        let exponent = public_integer(entry.get("e").and_then(Value::as_str).ok_or(invalid)?, 8)?;
        let exponent = exponent.iter().fold(0_u64, |value, byte| (value << 8) | u64::from(*byte));
        if exponent < 3 || exponent % 2 == 0 { return Err(invalid); }
        let jwk: JWK<Empty> = serde_json::from_value(entry.clone()).map_err(|_| invalid)?;
        let AlgorithmParameters::RSA(parameters) = jwk.algorithm else { return Err(invalid); };
        keys.insert(kid.to_owned(), parameters);
    }
    if keys.is_empty() { return Err(invalid); }
    Ok(keys)
}

fn public_integer(encoded: &str, limit: usize) -> Result<Vec<u8>, BrowserError> {
    let invalid = BrowserError::Unavailable;
    if encoded.is_empty() || encoded.len() > (limit * 4).div_ceil(3) { return Err(invalid); }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid)?;
    if bytes.len() > limit || bytes.first().is_none_or(|byte| *byte == 0) { return Err(invalid); }
    Ok(bytes)
}
