use super::*;

impl PostgresSessionStore {
    pub fn create_session(&mut self, input: NewSession) -> Result<(), BrowserError> {
        input.identity.token_binding()?;
        let idle = idle_secs(input.idle_timeout_secs)?;
        self.prune_expired()?;
        self.operation(|client| {
            let mut tx = transaction(client)?;
            tx.execute("SELECT pg_advisory_xact_lock($1)", &[&CAPACITY_LOCK])
                .map_err(|_| BrowserError::Unavailable)?;
            let identity = &input.identity;
            let envelope = &input.envelope;
            let version = i32::try_from(envelope.version()).map_err(|_| BrowserError::Unavailable)?;
            let affected=tx.execute("INSERT INTO apex_browser_sessions (session_digest,issuer,client_id,subject,absolute_expires_at,
                csrf_binding,token_version,token_key_id,token_nonce,token_ciphertext,access_expires_at,refresh_expires_at,idle_expires_at)
                SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,LEAST($5,floor(extract(epoch FROM clock_timestamp()))::bigint+$13)
                WHERE (SELECT count(*) FROM apex_browser_sessions)<10000
                AND $5>floor(extract(epoch FROM clock_timestamp()))::bigint
                AND $5-floor(extract(epoch FROM clock_timestamp()))::bigint<=86400
                AND $11>floor(extract(epoch FROM clock_timestamp()))::bigint
                AND $12>floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[&identity.digest.as_bytes().as_slice(),&identity.issuer,&identity.client_id,&identity.subject,&identity.absolute_expires_at,
                    &input.csrf_binding.as_bytes().as_slice(),&version,&envelope.key_id(),&envelope.nonce().as_slice(),&envelope.ciphertext(),
                    &input.access_expires_at,&input.refresh_expires_at,&idle]).map_err(|_|BrowserError::Unavailable)?;
            if affected != 1 {
                return Err(BrowserError::Unavailable);
            }
            tx.commit().map_err(|_| BrowserError::Unavailable)
        })
    }

    pub fn touch(
        &mut self,
        digest: LookupDigest,
        expected: u64,
        idle_timeout_secs: u32,
    ) -> Result<bool, BrowserError> {
        let expected = generation(expected)?;
        let idle = idle_secs(idle_timeout_secs)?;
        self.operation(|client| {
            let Some(mut tx) = Self::lock_session(client, digest)? else {
                return Ok(false);
            };
            let changed=tx.execute(&format!("UPDATE apex_browser_sessions
                SET idle_expires_at=LEAST(absolute_expires_at,floor(extract(epoch FROM clock_timestamp()))::bigint+$3)
                WHERE session_digest=$1 AND generation=$2 AND state='active' AND {LIVE}"),
                &[&digest.as_bytes().as_slice(),&expected,&idle]).map_err(|_|BrowserError::Unavailable)?;
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    pub fn claim_refresh(
        &mut self,
        digest: LookupDigest,
        expected: u64,
    ) -> Result<Option<StoredSession>, BrowserError> {
        let expected = generation(expected)?;
        let row = self.operation(|client| {
            let Some(mut tx) = Self::lock_session(client, digest)? else {
                return Ok(None);
            };
            let row=tx.query_opt(&format!("UPDATE apex_browser_sessions
                SET state='refreshing',generation=generation+1,refresh_deadline=LEAST(absolute_expires_at,idle_expires_at,refresh_expires_at,
                    floor(extract(epoch FROM clock_timestamp()))::bigint+15)
                WHERE session_digest=$1 AND generation=$2 AND generation<9223372036854775807 AND state='active' AND {LIVE}
                AND access_expires_at<=floor(extract(epoch FROM clock_timestamp()))::bigint+30 RETURNING *"),
                &[&digest.as_bytes().as_slice(),&expected]).map_err(|_|BrowserError::Unavailable)?;
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            Ok(row)
        })?;
        row.map(rows::session).transpose()
    }

    /// The provider result has already been verified by the caller. Never revoke
    /// or retry a different generation if this conditional write loses to logout.
    pub fn finish_refresh(&mut self, input: RefreshCommit) -> Result<bool, BrowserError> {
        let generation = generation(input.generation)?;
        let envelope = &input.envelope;
        let version = i32::try_from(envelope.version()).map_err(|_| BrowserError::Unavailable)?;
        self.operation(|client| {
            let Some(mut tx) = Self::lock_session(client, input.digest)? else {
                return Ok(false);
            };
            let changed=tx.execute(&format!("UPDATE apex_browser_sessions SET state='active',refresh_deadline=NULL,
                token_version=$3,token_key_id=$4,token_nonce=$5,token_ciphertext=$6,access_expires_at=$7,refresh_expires_at=$8
                WHERE session_digest=$1 AND generation=$2 AND state='refreshing' AND {LIVE}
                AND $7>floor(extract(epoch FROM clock_timestamp()))::bigint
                AND $8>floor(extract(epoch FROM clock_timestamp()))::bigint"),
                &[&input.digest.as_bytes().as_slice(),&generation,&version,&envelope.key_id(),&envelope.nonce().as_slice(),&envelope.ciphertext(),
                    &input.access_expires_at,&input.refresh_expires_at]).map_err(|_|BrowserError::Unavailable)?;
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    // Do not filter by time here: acquire the lock before any expiry check.
    // The following statement rechecks clock, state, and generation while this
    // transaction owns the row. No provider call occurs inside this transaction.
    fn lock_session(
        client: &mut PostgresConnection,
        digest: LookupDigest,
    ) -> Result<Option<PostgresTransaction<'_>>, BrowserError> {
        let mut tx = transaction(client)?;
        let row = tx.query_opt(
            "SELECT session_digest FROM apex_browser_sessions WHERE session_digest=$1 FOR UPDATE",
            &[&digest.as_bytes().as_slice()],
        ).map_err(|_| BrowserError::Unavailable)?;
        if row.is_none() {
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            return Ok(None);
        }
        Ok(Some(tx))
    }

    pub fn revoke(&mut self, digest: LookupDigest) -> Result<bool, BrowserError> {
        self.operation(|client| {
            let changed = client
                .execute(
                    "UPDATE apex_browser_sessions SET state='revoked',refresh_deadline=NULL,
            token_version=NULL,token_key_id=NULL,token_nonce=NULL,token_ciphertext=NULL
            WHERE session_digest=$1",
                    &[&digest.as_bytes().as_slice()],
                )
                .map_err(|_| BrowserError::Unavailable)?;
            Ok(changed == 1)
        })
    }
}
