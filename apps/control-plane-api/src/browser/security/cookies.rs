use super::{
    LookupDigest, MAX_COOKIE_BYTES, MAX_COOKIE_COUNT, MAX_COOKIE_HEADERS,
    MAX_LOGIN_COOKIE_AGE_SECS, MAX_SESSION_COOKIE_AGE_SECS, OpaqueToken, SecurityError,
};
use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use zeroize::Zeroizing;

/// The only cookie names these helpers can create or delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppCookie {
    /// `__Host-apex_session`.
    Session,
    /// `__Host-apex_login`, independent of the session ID and OAuth state.
    Login,
}

/// Parsed application cookies contain only lookup digests, not plaintext IDs.
#[derive(Debug)]
pub struct ParsedCookies {
    pub session: Option<LookupDigest>,
    pub login: Option<LookupDigest>,
}

/// Parse all Cookie fields under aggregate byte/count bounds. Duplicate app
/// names, malformed app values and ambiguous syntax fail the entire parse.
/// Valid unrelated cookies, including duplicate unrelated names, are ignored.
pub fn parse_app_cookies(headers: &HeaderMap) -> Result<ParsedCookies, SecurityError> {
    let mut byte_count = 0_usize;
    // Complete the aggregate bound check before scanning or decoding any value.
    for (index, value) in headers.get_all(COOKIE).iter().enumerate() {
        if index >= MAX_COOKIE_HEADERS {
            return Err(SecurityError::CookieLimit);
        }
        byte_count = byte_count
            .checked_add(value.as_bytes().len())
            .filter(|total| *total <= MAX_COOKIE_BYTES)
            .ok_or(SecurityError::CookieLimit)?;
    }
    let mut parsed = ParsedCookies {
        session: None,
        login: None,
    };
    let mut pair_count = 0_usize;
    for value in headers.get_all(COOKIE).iter() {
        let wire = value.to_str().map_err(|_| SecurityError::InvalidCookie)?;
        if !wire.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
            return Err(SecurityError::InvalidCookie);
        }
        for pair in wire.split(';') {
            pair_count += 1;
            if pair_count > MAX_COOKIE_COUNT {
                return Err(SecurityError::CookieLimit);
            }
            // Only separators may have leading spaces. Never trim a value:
            // doing so would accept a noncanonical application cookie token.
            let (name, value) = pair
                .trim_start_matches(' ')
                .split_once('=')
                .ok_or(SecurityError::InvalidCookie)?;
            if name.is_empty() || !name.bytes().all(is_cookie_name_byte) {
                return Err(SecurityError::InvalidCookie);
            }
            let slot = match name {
                "__Host-apex_session" => &mut parsed.session,
                "__Host-apex_login" => &mut parsed.login,
                _ => {
                    if !valid_unrelated_value(value) {
                        return Err(SecurityError::InvalidCookie);
                    }
                    continue;
                }
            };
            if slot.is_some() {
                return Err(SecurityError::DuplicateCookie);
            }
            *slot = Some(
                OpaqueToken::parse(value)
                    .map_err(|_| SecurityError::InvalidCookie)?
                    .lookup_digest(),
            );
        }
    }
    Ok(parsed)
}

fn is_cookie_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn valid_unrelated_value(value: &str) -> bool {
    let octets = if let Some(quoted) = value.strip_prefix('"') {
        let Some(unquoted) = quoted.strip_suffix('"') else {
            return false;
        };
        unquoted
    } else {
        value
    };
    // RFC 6265 cookie-octet excludes quotes, commas, semicolons, backslashes,
    // whitespace and control bytes, including inside a quoted value.
    octets
        .bytes()
        .all(|byte| matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e))
}

/// Emit a sensitive Set-Cookie value with Secure/HttpOnly/Lax/Path=/, no Domain.
/// Max-Age must be 1..=the kind's maximum; zero requires `clear_cookie`.
pub fn set_cookie(
    kind: AppCookie,
    token: &OpaqueToken,
    max_age_secs: u64,
) -> Result<HeaderValue, SecurityError> {
    let (name, maximum) = match kind {
        AppCookie::Session => ("__Host-apex_session", MAX_SESSION_COOKIE_AGE_SECS),
        AppCookie::Login => ("__Host-apex_login", MAX_LOGIN_COOKIE_AGE_SECS),
    };
    if max_age_secs == 0 || max_age_secs > maximum {
        return Err(SecurityError::InvalidMaxAge);
    }
    let wire = Zeroizing::new(format!(
        "{name}={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age_secs}",
        token.expose_secret()
    ));
    let mut header =
        HeaderValue::from_str(wire.as_str()).map_err(|_| SecurityError::Unavailable)?;
    header.set_sensitive(true);
    Ok(header)
}

/// Delete the fixed cookie with matching attributes, Max-Age=0 and past Expires.
pub fn clear_cookie(kind: AppCookie) -> HeaderValue {
    let mut header = HeaderValue::from_static(match kind {
        AppCookie::Session => {
            "__Host-apex_session=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        }
        AppCookie::Login => {
            "__Host-apex_login=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        }
    });
    header.set_sensitive(true);
    header
}
