use super::{MAX_ORIGIN_BYTES, SecurityError};
use axum::http::{HeaderMap, header::ORIGIN};
use std::fmt;
use url::{Origin, Url};

/// Configured HTTPS authority with no path (even `/`), userinfo, query or fragment.
/// Its private URL origin stores the normalized scheme, host and effective port.
pub struct ConfiguredOrigin(Origin);

impl ConfiguredOrigin {
    /// Parse bounded deployment configuration; malformed/non-HTTPS input fails.
    /// Host input is ASCII DNS/IPv4/bracketed IPv6; IDNs must use punycode.
    pub fn parse(value: &str) -> Result<Self, SecurityError> {
        parse_origin(value)
            .map(Self)
            .map_err(|_| SecurityError::InvalidConfiguredOrigin)
    }

    /// Require exactly one well-formed Origin matching scheme/host/effective port.
    /// Never consult Host, Referer or forwarded headers. No session side effects.
    pub fn verify(&self, headers: &HeaderMap) -> Result<(), SecurityError> {
        let mut values = headers.get_all(ORIGIN).iter();
        let value = values.next().ok_or(SecurityError::InvalidOrigin)?;
        if values.next().is_some() || value.as_bytes().len() > MAX_ORIGIN_BYTES {
            return Err(SecurityError::InvalidOrigin);
        }
        let wire = value.to_str().map_err(|_| SecurityError::InvalidOrigin)?;
        if self.0 == parse_origin(wire)? {
            Ok(())
        } else {
            Err(SecurityError::UnexpectedOrigin)
        }
    }
}

impl fmt::Debug for ConfiguredOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfiguredOrigin([REDACTED])")
    }
}

fn parse_origin(value: &str) -> Result<Origin, SecurityError> {
    if value.is_empty() || value.len() > MAX_ORIGIN_BYTES {
        return Err(SecurityError::InvalidOrigin);
    }
    let (scheme, authority) = value
        .split_once("://")
        .ok_or(SecurityError::InvalidOrigin)?;
    // URL parsing alone normalizes away tabs, newlines, extra slashes and
    // dot paths. Reject everything beyond an explicit HTTPS authority first.
    // Percent escapes, userinfo, lists, wildcard hosts and backslashes cannot
    // enter the URL parser; bracket/port syntax is then checked by `url`.
    if !scheme.eq_ignore_ascii_case("https")
        || authority.is_empty()
        || authority.ends_with(':')
        || !authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b':' | b'[' | b']')
        })
    {
        return Err(SecurityError::InvalidOrigin);
    }
    let url = Url::parse(value).map_err(|_| SecurityError::InvalidOrigin)?;
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.port_or_known_default(), Some(1..=u16::MAX))
    {
        return Err(SecurityError::InvalidOrigin);
    }
    Ok(url.origin())
}
