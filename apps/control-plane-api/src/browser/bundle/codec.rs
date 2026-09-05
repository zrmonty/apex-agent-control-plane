//! Versioned binary framing avoids non-zeroizing JSON token strings and accepts
//! exactly one bounded layout. This is serialization, never custom cryptography.
use super::*;

const MAX_BYTES: usize = 1 + 24 + 86 + 4 + 8192;

pub(super) fn encode(payload: &SessionBundle) -> Result<Zeroizing<Vec<u8>>, BrowserError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES));
    bytes.push(1);
    bytes.extend_from_slice(&payload.generation.to_be_bytes());
    bytes.extend_from_slice(&payload.access_expires_at.to_be_bytes());
    bytes.extend_from_slice(&payload.refresh_expires_at.to_be_bytes());
    bytes.extend_from_slice(payload.nonce.expose_secret().as_bytes());
    bytes.extend_from_slice(payload.csrf.expose_secret().as_bytes());
    push_secret(&mut bytes, &payload.access)?;
    push_secret(&mut bytes, &payload.refresh)?;
    Ok(bytes)
}

pub(super) fn decode(bytes: &[u8]) -> Result<SessionBundle, BrowserError> {
    let invalid = BrowserError::Unauthenticated;
    if bytes.len() > MAX_BYTES {
        return Err(invalid);
    }
    let mut reader = Reader::new(bytes);
    reader.version()?;
    let generation = u64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| invalid)?);
    let access_expires_at = i64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| invalid)?);
    let refresh_expires_at = i64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| invalid)?);
    if generation > i64::MAX as u64 || access_expires_at <= 0 || refresh_expires_at <= 0 {
        return Err(invalid);
    }
    let nonce = OpaqueToken::parse(reader.text(43)?).map_err(|_| invalid)?;
    let csrf = CsrfToken::parse(reader.text(43)?).map_err(|_| invalid)?;
    let access = reader.secret()?;
    let refresh = reader.secret()?;
    reader.finish()?;
    Ok(SessionBundle {
        access,
        refresh,
        nonce,
        csrf,
        generation,
        access_expires_at,
        refresh_expires_at,
    })
}

pub(super) fn remaining(expiry: i64, now: i64, max: i64) -> Result<(), BrowserError> {
    if now < 0
        || expiry
            .checked_sub(now)
            .is_none_or(|seconds| !(1..=max).contains(&seconds))
    {
        return Err(BrowserError::Unavailable);
    }
    Ok(())
}

fn check_secret(value: &str) -> Result<(), BrowserError> {
    if value.is_empty() || value.len() > 4096 || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(BrowserError::Unauthenticated);
    }
    Ok(())
}

fn push_secret(bytes: &mut Vec<u8>, value: &str) -> Result<(), BrowserError> {
    check_secret(value)?;
    let length = u16::try_from(value.len()).map_err(|_| BrowserError::Unavailable)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

pub(super) struct Reader<'a> {
    rest: &'a [u8],
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], BrowserError> {
        let (head, tail) = self
            .rest
            .split_at_checked(count)
            .ok_or(BrowserError::Unauthenticated)?;
        self.rest = tail;
        Ok(head)
    }
    pub(super) fn text(&mut self, length: usize) -> Result<&'a str, BrowserError> {
        std::str::from_utf8(self.take(length)?).map_err(|_| BrowserError::Unauthenticated)
    }
    pub(super) fn version(&mut self) -> Result<(), BrowserError> {
        if self.take(1)? != [1] {
            return Err(BrowserError::Unauthenticated);
        }
        Ok(())
    }
    fn secret(&mut self) -> Result<Zeroizing<String>, BrowserError> {
        let size = u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| BrowserError::Unauthenticated)?,
        ) as usize;
        if size > 4096 {
            return Err(BrowserError::Unauthenticated);
        }
        let value = self.text(size)?;
        check_secret(value)?;
        Ok(Zeroizing::new(value.to_owned()))
    }
    pub(super) fn finish(self) -> Result<(), BrowserError> {
        if !self.rest.is_empty() {
            return Err(BrowserError::Unauthenticated);
        }
        Ok(())
    }
}
