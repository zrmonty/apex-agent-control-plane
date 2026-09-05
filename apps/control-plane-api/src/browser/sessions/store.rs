use super::*;
use apex_durability::{PostgresClientOps, PostgresConnection, PostgresTransaction};
use zeroize::Zeroizing;

mod admission;
mod login;
mod mutations;
mod rows;
mod schema;

const SCHEMA_LOCK: i64 = 0x0A9E_1DE3_0000_0050;
const CAPACITY_LOCK: i64 = 0x0A9E_1DE3_0000_0051;
const LIVE: &str = "state<>'revoked'
    AND absolute_expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint
    AND idle_expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint
    AND refresh_expires_at>floor(extract(epoch FROM clock_timestamp()))::bigint
    AND (state='active' OR refresh_deadline>floor(extract(epoch FROM clock_timestamp()))::bigint)";

/// Single-owner synchronous store. Construct/use/drop on its blocking worker.
/// No provider request runs while this connection holds a transaction or lease lock.
pub struct PostgresSessionStore {
    client: Option<PostgresConnection>,
    connection_string: Zeroizing<String>,
}

impl PostgresSessionStore {
    pub fn connect(connection_string: &str) -> Result<Self, BrowserError> {
        require_blocking_thread()?;
        let mut client = apex_durability::connect_postgres_for_worker(connection_string)
            .map_err(|_| BrowserError::Unavailable)?;
        configure(&mut client)?;
        schema::ensure(&mut client, true)?;
        Ok(Self {
            client: Some(client),
            connection_string: Zeroizing::new(connection_string.to_owned()),
        })
    }

    fn client(&mut self) -> Result<&mut PostgresConnection, BrowserError> {
        require_blocking_thread()?;
        if self
            .client
            .as_ref()
            .is_none_or(PostgresConnection::is_closed)
        {
            drop(self.client.take());
            let mut next = apex_durability::connect_postgres_for_worker(&self.connection_string)
                .map_err(|_| BrowserError::Unavailable)?;
            configure(&mut next)?;
            // A reconnect is validation-only: missing or drifted storage must
            // not turn into a fresh store or receive even a read operation.
            schema::ensure(&mut next, false)?;
            self.client = Some(next);
        }
        // Reconnect only before an operation. Never replay uncertain transactions.
        self.client.as_mut().ok_or(BrowserError::Unavailable)
    }

    fn operation<T>(
        &mut self,
        operation: impl FnOnce(&mut PostgresConnection) -> Result<T, BrowserError>,
    ) -> Result<T, BrowserError> {
        let result = operation(self.client()?);
        if result.is_err() {
            // A fatal response can reach its caller before the current-thread
            // driver observes EOF and updates is_closed(). Retire on failure,
            // after the closure's transaction guards have finished cleanup.
            // Never retry this operation, even when its commit is uncertain.
            drop(self.client.take());
        }
        result
    }

    /// Read-only: no idle extension or refresh before the HTTP CSRF check.
    pub fn load(&mut self, digest: LookupDigest) -> Result<Option<StoredSession>, BrowserError> {
        let row = self.operation(|client| {
            client
                .query_opt(
                    &format!(
                        "SELECT * FROM apex_browser_sessions WHERE session_digest=$1 AND {LIVE}"
                    ),
                    &[&digest.as_bytes().as_slice()],
                )
                .map_err(|_| BrowserError::Unavailable)
        })?;
        row.map(rows::session).transpose()
    }

    /// Bounded maintenance. Revoked and abandoned-refresh sessions are disposable;
    /// no later refresh may resurrect their deleted row.
    pub fn prune_expired(&mut self) -> Result<u64, BrowserError> {
        self.operation(|client| {
            let sessions=client.execute(&format!("DELETE FROM apex_browser_sessions WHERE session_digest IN (
                SELECT session_digest FROM apex_browser_sessions WHERE NOT ({LIVE}) LIMIT 100 FOR UPDATE SKIP LOCKED)"), &[])
                .map_err(|_|BrowserError::Unavailable)?;
            let logins=client.execute("DELETE FROM apex_browser_login_attempts WHERE state_digest IN (
                SELECT state_digest FROM apex_browser_login_attempts
                WHERE expires_at<=floor(extract(epoch FROM clock_timestamp()))::bigint LIMIT 100 FOR UPDATE SKIP LOCKED)", &[])
                .map_err(|_|BrowserError::Unavailable)?;
            Ok(sessions + logins)
        })
    }
}

fn require_blocking_thread() -> Result<(), BrowserError> {
    if tokio::runtime::Handle::try_current().is_ok() {
        Err(BrowserError::Unavailable)
    } else {
        Ok(())
    }
}

fn configure(client: &mut PostgresConnection) -> Result<(), BrowserError> {
    client
        .batch_execute("SET statement_timeout='5s'; SET lock_timeout='2s'")
        .map_err(|_| BrowserError::Unavailable)
}

fn transaction(client: &mut PostgresConnection) -> Result<PostgresTransaction<'_>, BrowserError> {
    let mut tx = client
        .transaction()
        .map_err(|_| BrowserError::Unavailable)?;
    // This must precede the first query (including an advisory-lock query).
    // Startup options and role/database defaults may otherwise retain a stale
    // Repeatable Read snapshot across a lock wait.
    tx.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED", &[])
        .map_err(|_| BrowserError::Unavailable)?;
    Ok(tx)
}

fn idle_secs(value: u32) -> Result<i64, BrowserError> {
    if !(60..=3600).contains(&value) {
        return Err(BrowserError::InvalidRequest);
    }
    Ok(i64::from(value))
}

fn generation(value: u64) -> Result<i64, BrowserError> {
    i64::try_from(value).map_err(|_| BrowserError::InvalidRequest)
}
