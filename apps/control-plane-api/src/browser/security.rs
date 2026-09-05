//! Browser cookie, Origin and CSRF primitives; these confer no access authority.
//!
//! Intended call order: verify configured Origin, parse cookie lookup digests,
//! read durable session status without touching it, verify its CSRF binding,
//! then perform any session touch/refresh or authorized RPC work. The callback
//! uses its separately checked login binding, not the POST Origin/CSRF rule.
//!
//! Digests are SHA-256 of canonical token ASCII wire bytes. Plain opaque IDs
//! must not be persisted. CSRF disclosure is only for the authenticated session
//! response. Explicit secret accessors and header bytes must never be logged.

use std::fmt;

mod cookies;
mod csrf;
mod origin;
mod tokens;

pub use cookies::{AppCookie, ParsedCookies, clear_cookie, parse_app_cookies, set_cookie};
pub use csrf::{CsrfBinding, CsrfToken, verify_csrf};
pub use origin::ConfiguredOrigin;
pub use tokens::{LookupDigest, OpaqueToken};

/// Maximum combined Cookie header value bytes, including unrelated cookies.
pub const MAX_COOKIE_BYTES: usize = 8192;
/// Maximum cookie pairs across all Cookie headers, including unrelated cookies.
pub const MAX_COOKIE_COUNT: usize = 64;
/// Maximum Cookie header fields, independently of byte and pair ceilings.
pub const MAX_COOKIE_HEADERS: usize = 16;
/// Maximum configured or request Origin length, before any URL parsing.
pub const MAX_ORIGIN_BYTES: usize = 2048;
/// Session cookies may last at most 24 hours; durable expiry still takes priority.
pub const MAX_SESSION_COOKIE_AGE_SECS: u64 = 86_400;
/// Login binding cookies may last at most ten minutes.
pub const MAX_LOGIN_COOKIE_AGE_SECS: u64 = 600;

/// Bounded, value-free errors suitable for safe mapping at the HTTP boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    InvalidConfiguredOrigin,
    InvalidOrigin,
    UnexpectedOrigin,
    InvalidToken,
    InvalidCookie,
    DuplicateCookie,
    CookieLimit,
    InvalidMaxAge,
    MissingCsrf,
    InvalidCsrf,
    CsrfMismatch,
    /// Fail closed on unavailable primitives, including entropy failure.
    Unavailable,
}

impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("browser security validation failed")
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod cookie_tests;
#[cfg(test)]
mod csrf_tests;
#[cfg(test)]
mod origin_tests;
#[cfg(test)]
mod token_tests;
