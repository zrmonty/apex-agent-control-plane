use serde_json::Value;

use super::convert::prost_struct_to_json;
use crate::GatewayError;

pub(crate) fn contains_secret_like_data(data: &prost_types::Struct) -> Result<bool, GatewayError> {
    Ok(contains_secret_like_value(&prost_struct_to_json(data)?))
}

pub(crate) fn contains_secret_like_value(value: &Value) -> bool {
    contains_secret_like_value_with_context(value, false, false)
}

/// Control injection is valid untrusted text, so only high-confidence
/// credential shapes are rejected there. This still catches credentials
/// embedded in otherwise harmless prose without treating ordinary words such
/// as "secret_hash" as secrets.
pub(crate) fn contains_secret_like_control_data(
    data: &prost_types::Struct,
) -> Result<bool, GatewayError> {
    Ok(contains_secret_like_value_with_context(
        &prost_struct_to_json(data)?,
        true,
        false,
    ))
}

fn contains_secret_like_value_with_context(
    value: &Value,
    control_text: bool,
    hash_like_field: bool,
) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let sensitive_key = is_sensitive_key(key);
            let hash_like = is_hash_like_key(key);
            (sensitive_key && has_sensitive_value(value))
                || contains_secret_like_value_with_context(value, control_text, hash_like)
        }),
        Value::Array(values) => values.iter().any(|value| {
            contains_secret_like_value_with_context(value, control_text, hash_like_field)
        }),
        Value::String(text) => {
            high_confidence_secret(text)
                || (!control_text
                    && (!hash_like_field || !is_hash_reference(text))
                    && looks_like_encoded_secret(text))
        }
        _ => false,
    }
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    if normalized.ends_with("hash") || normalized.ends_with("digest") || normalized.ends_with("id")
    {
        return false;
    }
    matches!(
        normalized.as_str(),
        "authorization"
            | "apikey"
            | "password"
            | "secret"
            | "privatekey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "clientsecret"
            | "secretkey"
            | "credential"
            | "credentials"
            | "bearertoken"
    ) || ["apikey", "password", "secret", "privatekey", "credential"]
        .iter()
        .any(|name| normalized.starts_with(name) || normalized.ends_with(name))
}

fn is_hash_like_key(key: &str) -> bool {
    let normalized = normalized_key(key);
    normalized.ends_with("hash")
        || normalized.ends_with("digest")
        || normalized.ends_with("ref")
        || normalized.ends_with("id")
}

fn is_hash_reference(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn has_sensitive_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(values) => values.iter().any(has_sensitive_value),
        Value::Object(object) => object.values().any(has_sensitive_value),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

fn high_confidence_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if lower.contains("-----begin ") && lower.contains("private key-----") {
        return true;
    }
    if lower.contains("bearer ") {
        let token = lower
            .split_once("bearer ")
            .map(|(_, token)| token.trim())
            .unwrap_or_default();
        if token.len() >= 20
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~+/=".contains(&byte))
        {
            return true;
        }
    }
    if text.starts_with("eyJ") && text.split('.').count() == 3 {
        let parts = text.split('.').collect::<Vec<_>>();
        if parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        }) {
            return true;
        }
    }
    text.match_indices("sk-").any(|(index, _)| {
        let suffix = text[index + 3..].chars().take(20).collect::<Vec<_>>();
        suffix.len() == 20
            && suffix.iter().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
    }) || text.match_indices("AKIA").any(|(index, _)| {
        text[index + 4..].chars().take(16).count() == 16
            && text[index + 4..]
                .chars()
                .take(16)
                .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
    }) || text.match_indices("ASIA").any(|(index, _)| {
        text[index + 4..].chars().take(16).count() == 16
            && text[index + 4..]
                .chars()
                .take(16)
                .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
    }) || text.match_indices("AIza").any(|(index, _)| {
        text[index + 4..].chars().take(20).count() >= 20
            && text[index + 4..].chars().take(20).all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
    }) || text.match_indices("ghp_").any(|(index, _)| {
        let suffix = text[index + 4..].chars().take(20).collect::<Vec<_>>();
        suffix.len() == 20
            && suffix
                .iter()
                .all(|character| character.is_ascii_alphanumeric() || *character == '_')
    }) || text.match_indices("xoxb-").any(|(index, _)| {
        let suffix = text[index + 5..].chars().take(12).collect::<Vec<_>>();
        suffix.len() == 12
            && suffix
                .iter()
                .all(|character| character.is_ascii_alphanumeric() || *character == '-')
    })
}

fn looks_like_encoded_secret(text: &str) -> bool {
    let compact = text.trim();
    if compact.len() < 32 || compact.len() > 512 {
        return false;
    }
    let base64ish = compact
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"+/=_-".contains(&byte));
    let hexish = compact.bytes().all(|byte| byte.is_ascii_hexdigit());
    base64ish && (hexish || compact.len() >= 48)
}
