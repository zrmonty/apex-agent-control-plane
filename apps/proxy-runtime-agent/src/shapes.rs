//! Pure lexical checks. No identifier, hash or image shape grants authority.

pub(super) fn scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

pub(super) fn uuid_v7(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.get_version_num() == 7
            && id.get_variant() == uuid::Variant::RFC4122
            && id.hyphenated().to_string() == value
    })
}

pub(super) fn hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn image_id(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(hex_hash)
}

pub(super) fn instance_name(value: &str) -> Option<&str> {
    value.strip_prefix("apex-runtime-").filter(|id| uuid_v7(id))
}

pub(super) fn image_ref(value: &str) -> bool {
    if value.len() > 512 {
        return false;
    }
    let Some((name, digest)) = value.split_once('@') else {
        return false;
    };
    let Some((registry, repository)) = name.split_once('/') else {
        return false;
    };
    image_id(digest)
        && registry_shape(registry)
        && repository.split('/').all(|part| {
            !part.is_empty()
                && !part.contains("..")
                && part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
        })
}

// Same bounded HTTPS parse/origin relation as the v1 compiler's image check.
// URL parsing is lexical only: no DNS lookup, image approval or application dep.
fn registry_shape(registry: &str) -> bool {
    let value = format!("https://{registry}/");
    if !registry.contains('.')
        || value.len() > 512
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    let Ok(url) = url::Url::parse(&value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.origin().ascii_serialization() == format!("https://{registry}")
}
