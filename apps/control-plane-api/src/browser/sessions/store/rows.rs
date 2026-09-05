use super::*;
use postgres::Row;

pub(super) fn envelope(row: &Row) -> Result<TokenEnvelope, BrowserError> {
    let version: i32 = field(row, "token_version")?;
    let key: &str = field(row, "token_key_id")?;
    let nonce: &[u8] = field(row, "token_nonce")?;
    let ciphertext: &[u8] = field(row, "token_ciphertext")?;
    TokenEnvelope::from_storage(
        u32::try_from(version).map_err(|_| BrowserError::Unavailable)?,
        key,
        nonce,
        ciphertext,
    )
    .map_err(|_| BrowserError::Unavailable)
}

pub(super) fn login(row: Row) -> Result<NewLoginAttempt, BrowserError> {
    let input = NewLoginAttempt {
        state: digest(&row, "state_digest")?,
        browser: digest(&row, "browser_digest")?,
        issuer: field(&row, "issuer")?,
        client_id: field(&row, "client_id")?,
        expires_at: field(&row, "expires_at")?,
        envelope: envelope(&row)?,
    };
    super::login::validate(&input)?;
    Ok(input)
}

pub(super) fn session(row: Row) -> Result<StoredSession, BrowserError> {
    let identity = SessionIdentity {
        digest: digest(&row, "session_digest")?,
        issuer: field(&row, "issuer")?,
        client_id: field(&row, "client_id")?,
        subject: field(&row, "subject")?,
        absolute_expires_at: field(&row, "absolute_expires_at")?,
    };
    identity.token_binding()?;
    let csrf: &[u8] = field(&row, "csrf_binding")?;
    let generation: i64 = field(&row, "generation")?;
    Ok(StoredSession {
        identity,
        csrf_binding: CsrfBinding::from_bytes(
            csrf.try_into().map_err(|_| BrowserError::Unavailable)?,
        ),
        envelope: envelope(&row)?,
        access_expires_at: field(&row, "access_expires_at")?,
        refresh_expires_at: field(&row, "refresh_expires_at")?,
        idle_expires_at: field(&row, "idle_expires_at")?,
        generation: u64::try_from(generation).map_err(|_| BrowserError::Unavailable)?,
        refresh_deadline: field(&row, "refresh_deadline")?,
    })
}

fn digest(row: &Row, name: &str) -> Result<LookupDigest, BrowserError> {
    let bytes: &[u8] = field(row, name)?;
    Ok(LookupDigest::from_bytes(
        bytes.try_into().map_err(|_| BrowserError::Unavailable)?,
    ))
}

fn field<'a, T: postgres::types::FromSql<'a>>(row: &'a Row, name: &str) -> Result<T, BrowserError> {
    row.try_get(name).map_err(|_| BrowserError::Unavailable)
}
