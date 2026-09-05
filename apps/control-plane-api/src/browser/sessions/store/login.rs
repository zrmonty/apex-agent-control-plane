use super::*;
use crate::browser::crypto::{EnvelopePurpose, RecordDigest, TokenBinding};

pub(super) fn validate(input: &NewLoginAttempt) -> Result<(), BrowserError> {
    TokenBinding::new(
        EnvelopePurpose::LoginAttempt,
        RecordDigest::from_sha256(input.state.as_bytes())
            .map_err(|_| BrowserError::InvalidRequest)?,
        &input.issuer,
        &input.client_id,
        None,
        input.expires_at,
    )
    .map_err(|_| BrowserError::InvalidRequest)?;
    Ok(())
}

impl PostgresSessionStore {
    pub fn create_login(&mut self, input: NewLoginAttempt) -> Result<(), BrowserError> {
        validate(&input)?;
        self.prune_expired()?;
        self.operation(|client| {
            let mut tx = transaction(client)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&CAPACITY_LOCK])
                .map_err(|_| BrowserError::Unavailable)?;
            let envelope = &input.envelope;
            let version = i32::try_from(envelope.version()).map_err(|_| BrowserError::Unavailable)?;
            let affected=tx.execute("INSERT INTO apex_browser_login_attempts (state_digest,browser_digest,issuer,client_id,expires_at,
                token_version,token_key_id,token_nonce,token_ciphertext)
                SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9
                WHERE (SELECT count(*) FROM apex_browser_login_attempts)<1000
                AND $5>floor(extract(epoch FROM clock_timestamp()))::bigint
                AND $5-floor(extract(epoch FROM clock_timestamp()))::bigint<=600",
                &[&input.state.as_bytes().as_slice(),&input.browser.as_bytes().as_slice(),&input.issuer,&input.client_id,&input.expires_at,
                    &version,&envelope.key_id(),&envelope.nonce().as_slice(),&envelope.ciphertext()]).map_err(|_|BrowserError::Unavailable)?;
            if affected != 1 {
                return Err(BrowserError::Unavailable);
            }
            tx.commit().map_err(|_| BrowserError::Unavailable)
        })
    }

    /// DELETE RETURNING is the one-use claim; exchange failure does not restore it.
    pub fn take_login(
        &mut self,
        state: LookupDigest,
        browser: LookupDigest,
    ) -> Result<Option<NewLoginAttempt>, BrowserError> {
        let row = self.operation(|client| {
            let mut tx = transaction(client)?;
            // A predicate on DELETE alone can be evaluated before waiting for a
            // row lock. Lock first, then check the database clock in a new statement.
            let locked = tx
                .query_opt(
                    "SELECT state_digest FROM apex_browser_login_attempts
                WHERE state_digest=$1 AND browser_digest=$2 FOR UPDATE",
                    &[&state.as_bytes().as_slice(), &browser.as_bytes().as_slice()],
                )
                .map_err(|_| BrowserError::Unavailable)?;
            if locked.is_none() {
                tx.commit().map_err(|_| BrowserError::Unavailable)?;
                return Ok(None);
            }
            let row=tx.query_opt("DELETE FROM apex_browser_login_attempts
                WHERE state_digest=$1 AND browser_digest=$2 AND expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint RETURNING *",
                &[&state.as_bytes().as_slice(),&browser.as_bytes().as_slice()]).map_err(|_|BrowserError::Unavailable)?;
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            Ok(row)
        })?;
        row.map(rows::login).transpose()
    }
}
