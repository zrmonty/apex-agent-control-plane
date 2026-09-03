use serde_json::Value;

#[cfg(test)]
use super::convert::prost_struct_to_json;
#[cfg(test)]
use crate::GatewayError;

/// Struct-input twin of [`contains_secret_like_value`], kept for test
/// coverage of the conversion+detection combination. Production admission
/// (`validation::request::from_validated_transport_ref`) converts `data` to
/// JSON once itself and calls `contains_secret_like_value` directly so that
/// conversion is not repeated for the canonical hash.
#[cfg(test)]
pub(crate) fn contains_secret_like_data(data: &prost_types::Struct) -> Result<bool, GatewayError> {
    Ok(contains_secret_like_value(&prost_struct_to_json(data)?))
}

pub(crate) fn contains_secret_like_value(value: &Value) -> bool {
    contains_secret_like_value_with_context(value, false, false)
}

/// Struct-input twin of [`contains_secret_like_control_value`], kept for
/// test coverage of the conversion+detection combination; see
/// [`contains_secret_like_data`]'s doc comment for why production code
/// calls the JSON-input form directly instead.
#[cfg(test)]
pub(crate) fn contains_secret_like_control_data(
    data: &prost_types::Struct,
) -> Result<bool, GatewayError> {
    Ok(contains_secret_like_control_value(&prost_struct_to_json(
        data,
    )?))
}

/// Control injection is valid untrusted text, so only high-confidence
/// credential shapes are rejected there. This still catches credentials
/// embedded in otherwise harmless prose without treating ordinary words such
/// as "secret_hash" as secrets. JSON-input twin of
/// [`contains_secret_like_control_data`], for callers that already
/// converted `data` to JSON for another purpose on the same request and
/// want to avoid doing that conversion a second time. See
/// `validation::request::from_validated_transport_ref`.
pub(crate) fn contains_secret_like_control_value(value: &Value) -> bool {
    contains_secret_like_value_with_context(value, true, false)
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
            // A hash/digest/id-suffixed key (e.g. "password_hash", "api_key_id")
            // only escapes the blanket "any non-empty value is a secret" rule
            // when its value itself looks like an opaque hash/id reference, not
            // when the key name alone ends in a suffix that merely *sounds*
            // like one. Otherwise a live credential stashed under a
            // conveniently-suffixed key name (e.g. `db_credential_hash =
            // "postgres://admin:hunter2@db.internal/prod"`) would be admitted
            // outright.
            let exempt_by_value_shape = hash_like && is_plausible_hash_or_id_value(value);
            (sensitive_key && !exempt_by_value_shape && has_sensitive_value(value))
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

/// Whether a value looks like a plausible hash/digest or opaque identifier
/// reference rather than a credential. Used to decide whether a hash/digest/
/// id-suffixed key (see `is_hash_like_key`) may skip the blanket "any
/// non-empty value under a sensitive key is a secret" rule.
///
/// Deliberately conservative: opaque tokens (hex digests, UUIDs, short
/// alphanumeric ids) are exempt, but anything containing credential/URL
/// punctuation such as "://", "@", or whitespace is not, so it still falls
/// through to the ordinary content-based secret heuristics.
fn is_plausible_hash_or_id_value(value: &Value) -> bool {
    match value {
        // Non-string scalars (numeric ids, booleans) are never
        // credential-shaped.
        Value::Bool(_) | Value::Number(_) | Value::Null => true,
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return true;
            }
            is_hash_reference(trimmed)
                || (trimmed.len() <= 128
                    && trimmed.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    }))
        }
        Value::Array(values) => values.iter().all(is_plausible_hash_or_id_value),
        Value::Object(object) => object.values().all(is_plausible_hash_or_id_value),
    }
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
    if looks_like_credentialed_url(text) {
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

/// Whether `text` contains a URL/connection-string with embedded userinfo
/// credentials, e.g. `postgres://admin:hunter2@db.internal:5432/prod`.
/// This is a high-confidence secret shape independent of the field name it
/// is stored under, which is what actually closes the `db_credential_hash`
/// bypass: that key name does not match any sensitive-name pattern at all,
/// so detection must come from the value's own shape.
fn looks_like_credentialed_url(text: &str) -> bool {
    let Some(scheme_end) = text.find("://") else {
        return false;
    };
    let after_scheme = &text[scheme_end + 3..];
    let Some(at_index) = after_scheme.find('@') else {
        return false;
    };
    let authority = &after_scheme[..at_index];
    // Reject if the "authority" segment isn't actually userinfo (e.g. no `/`
    // should appear before the `@`, which would mean the `@` is later in the
    // path rather than a credential separator).
    if authority.contains('/') || authority.is_empty() {
        return false;
    }
    let Some(colon_index) = authority.find(':') else {
        return false;
    };
    let user = &authority[..colon_index];
    let password = &authority[colon_index + 1..];
    !user.is_empty() && !password.is_empty()
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


