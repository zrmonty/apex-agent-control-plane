//! One deployment-global durable GCRA bucket: burst 60, one token per second.
//! The singleton never expires, and uncertain admissions are never refunded.
use super::*;

const TOKEN_US: i64 = 1_000_000;
const BURST_US: i64 = 60_000_000;

impl PostgresSessionStore {
    /// Admit before provider work and preserve the returned expiry throughout login.
    ///
    /// Quota denial is `RateLimited`; database, clock or malformed debt is
    /// `Unavailable`. Neither failure permits a retry of an uncertain admission.
    pub fn admit_login(&mut self) -> Result<LoginAdmission, BrowserError> {
        self.admit_with_clock(|tx| {
            tx.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint",
                &[],
            )
            .map(|row| row.get(0))
            .map_err(|_| BrowserError::Unavailable)
        })
    }

    // Private test seam: the production caller above always uses the DB clock.
    // The sampler runs only after acquiring the shared singleton row lock.
    fn admit_with_clock(
        &mut self,
        clock: impl FnOnce(&mut PostgresTransaction<'_>) -> Result<i64, BrowserError>,
    ) -> Result<LoginAdmission, BrowserError> {
        let admission = self.operation(|client| {
            let mut tx = transaction(client)?;
            let row = tx.query_one(
                "SELECT tat_us,clock_us FROM apex_browser_login_admission WHERE singleton=1 FOR UPDATE",
                &[],
            )
            .map_err(|_| BrowserError::Unavailable)?;
            let tat: i64 = row.get(0);
            let previous_clock: i64 = row.get(1);
            // The row lock precedes the fresh sample; another replica's commit
            // cannot be evaluated using time captured before a lock wait.
            let sampled = clock(&mut tx)?;
            if tat < 0 || previous_clock < 0 || sampled < 0 || sampled < previous_clock {
                return Err(BrowserError::Unavailable);
            }
            let previous_limit = previous_clock
                .checked_add(BURST_US)
                .ok_or(BrowserError::Unavailable)?;
            if tat > previous_limit {
                return Err(BrowserError::Unavailable);
            }
            let limit = sampled
                .checked_add(BURST_US)
                .ok_or(BrowserError::Unavailable)?;
            let candidate = tat
                .max(sampled)
                .checked_add(TOKEN_US)
                .ok_or(BrowserError::Unavailable)?;
            if candidate > limit {
                // Ordinary rejection is not a connection failure. Release the
                // lock without modifying debt or advancing the accepted clock.
                tx.commit().map_err(|_| BrowserError::Unavailable)?;
                return Ok(None);
            }
            let expires_at = (sampled / TOKEN_US)
                .checked_add(600)
                .ok_or(BrowserError::Unavailable)?;
            let affected = tx.execute(
                "UPDATE apex_browser_login_admission SET tat_us=$1,clock_us=$2 WHERE singleton=1",
                &[&candidate, &sampled],
            ).map_err(|_| BrowserError::Unavailable)?;
            if affected != 1 {
                return Err(BrowserError::Unavailable);
            }
            tx.commit().map_err(|_| BrowserError::Unavailable)?;
            Ok(Some(LoginAdmission { expires_at }))
        })?;
        // Keep quota denial outside operation(): its error path retires the
        // connection for uncertain database failures, not expected throttling.
        admission.ok_or(BrowserError::RateLimited)
    }
}

#[cfg(test)]
mod tests;
