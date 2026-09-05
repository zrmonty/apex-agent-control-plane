//! Strict OAuth callback query boundary; parsing grants no authentication.
//!
//! A handler must claim the one-use login using both this state lookup AND its
//! separately checked browser binding, then compare the untrusted issuer.
//! Valid provider errors retain state so that the same claim precedes failure.

use super::{
    errors::BrowserError,
    security::{LookupDigest, OpaqueToken},
};
use std::fmt;
use zeroize::Zeroizing;

const MAX_QUERY_BYTES: usize = 4096;
const MAX_PAIRS: usize = 8;
const MAX_KEY_BYTES: usize = 17; // error_description
const MAX_VALUE_BYTES: usize = 2048;

/// Parsed callback data. Provider error details are deliberately not retained.
pub struct CallbackRequest {
    /// SHA-256 lookup of canonical state; not proof of browser binding.
    pub state: LookupDigest,
    /// Opaque authorization code; owned plaintext is zeroized on drop.
    pub code: Option<Zeroizing<String>>,
    /// Untrusted issuer text, to compare only after claiming the bound login.
    pub issuer: Option<String>,
    /// A syntactically valid provider error, pending the same bound login claim.
    pub denied: bool,
}

impl CallbackRequest {
    /// Parse an optional raw form query without I/O or authentication policy.
    ///
    /// # Errors
    /// Returns only [`BrowserError::InvalidRequest`] for invalid input. The
    /// contract caps raw input at 4096 ASCII bytes and eight pairs before any
    /// allocation, requires strict percent decoding and UTF-8, and rejects
    /// duplicate decoded keys. Ignored error metadata may contain valid Unicode.
    pub fn parse(query: Option<&str>) -> Result<Self, BrowserError> {
        let query = query.ok_or(BrowserError::InvalidRequest)?;
        // Borrowed scans only: even percent decoding and fixed scratch buffers
        // come after these checks. Counting raw pairs includes empty segments.
        if query.is_empty()
            || query.len() > MAX_QUERY_BYTES
            || !query.is_ascii()
            || query.split('&').take(MAX_PAIRS + 1).count() > MAX_PAIRS
        {
            return Err(BrowserError::InvalidRequest);
        }

        let mut seen = 0_u8;
        let mut state = None;
        let mut code = None;
        let mut issuer = None;
        let mut denied = false;
        for pair in query.split('&') {
            // Split before decoding, once only: encoded '&' and '=' are data.
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            let mut key_buffer = Zeroizing::new([0_u8; MAX_KEY_BYTES]);
            let key = decode_component(raw_key, key_buffer.as_mut_slice())?;
            let field = Field::from_key(key)?;
            if seen & field.bit() != 0 {
                return Err(BrowserError::InvalidRequest);
            }
            seen |= field.bit();

            // No input-sized allocation or lossy decoding. Enforce each field's
            // decoded byte ceiling while writing into zeroized stack storage.
            let mut value_buffer = Zeroizing::new([0_u8; MAX_VALUE_BYTES]);
            let value = decode_component(raw_value, &mut value_buffer[..field.max_bytes()])?;
            match field {
                Field::State => {
                    state = Some(
                        OpaqueToken::parse(value)
                            .map_err(|_| BrowserError::InvalidRequest)?
                            .lookup_digest(),
                    );
                }
                Field::Code => {
                    require_graphic(value)?;
                    code = Some(Zeroizing::new(value.to_owned()));
                }
                Field::Issuer => {
                    require_graphic(value)?;
                    issuer = Some(value.to_owned());
                }
                Field::SessionState => require_graphic(value)?,
                Field::Error => {
                    if value.is_empty()
                        || !value
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                    {
                        return Err(BrowserError::InvalidRequest);
                    }
                    denied = true;
                }
                // Bounded, valid UTF-8 (including Unicode and empty strings).
                // Never retain descriptions, interpret URIs, or return raw errors.
                Field::ErrorDescription | Field::ErrorUri => {}
            }
        }

        let has_error_metadata =
            seen & (Field::ErrorDescription.bit() | Field::ErrorUri.bit()) != 0;
        if code.is_some() == denied || (has_error_metadata && !denied) {
            return Err(BrowserError::InvalidRequest);
        }
        Ok(Self {
            state: state.ok_or(BrowserError::InvalidRequest)?,
            code,
            issuer,
            denied,
        })
    }
}

impl fmt::Debug for CallbackRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallbackRequest([REDACTED])")
    }
}

#[derive(Clone, Copy)]
enum Field {
    State,
    Code,
    Issuer,
    SessionState,
    Error,
    ErrorDescription,
    ErrorUri,
}

impl Field {
    fn from_key(key: &str) -> Result<Self, BrowserError> {
        match key {
            "state" => Ok(Self::State),
            "code" => Ok(Self::Code),
            "iss" => Ok(Self::Issuer),
            "session_state" => Ok(Self::SessionState),
            "error" => Ok(Self::Error),
            "error_description" => Ok(Self::ErrorDescription),
            "error_uri" => Ok(Self::ErrorUri),
            _ => Err(BrowserError::InvalidRequest),
        }
    }

    fn bit(self) -> u8 {
        // Seven closed variants, numbered 0..=6; no input-dependent shift.
        1_u8 << self as u8
    }

    fn max_bytes(self) -> usize {
        match self {
            // Canonical unpadded base64url for exactly 32 bytes.
            Self::State => 43,
            Self::SessionState | Self::Error => 128,
            Self::Code | Self::Issuer | Self::ErrorDescription | Self::ErrorUri => MAX_VALUE_BYTES,
        }
    }
}

fn require_graphic(value: &str) -> Result<(), BrowserError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(BrowserError::InvalidRequest);
    }
    Ok(())
}

/// Decode URL form serialization exactly once into caller-bounded storage.
/// UTF-8 errors are rejected, including for metadata that will be discarded.
fn decode_component<'a>(raw: &str, output: &'a mut [u8]) -> Result<&'a str, BrowserError> {
    let mut bytes = raw.bytes();
    let mut length = 0;
    while let Some(byte) = bytes.next() {
        let decoded = match byte {
            b'+' => b' ',
            b'%' => {
                let high = hex_digit(bytes.next())?;
                let low = hex_digit(bytes.next())?;
                (high << 4) | low
            }
            byte => byte,
        };
        *output.get_mut(length).ok_or(BrowserError::InvalidRequest)? = decoded;
        length += 1;
    }
    std::str::from_utf8(&output[..length]).map_err(|_| BrowserError::InvalidRequest)
}

fn hex_digit(byte: Option<u8>) -> Result<u8, BrowserError> {
    match byte {
        Some(byte @ b'0'..=b'9') => Ok(byte - b'0'),
        Some(byte @ b'a'..=b'f') => Ok(byte - b'a' + 10),
        Some(byte @ b'A'..=b'F') => Ok(byte - b'A' + 10),
        _ => Err(BrowserError::InvalidRequest),
    }
}

#[cfg(test)]
mod tests;
