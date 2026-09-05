//! One durable claim precedes one provider exchange. An uncertain exchange is
//! never retried: the claimed row remains non-serving until its lease expires.
//! There is deliberately no detached cleanup task or reclaim of an old token.
use super::{
    BrowserError, BrowserState,
    budget::Budget,
    session::{Loaded, now},
};
use crate::browser::{
    bundle::SessionBundle,
    sessions::RefreshCommit,
    telemetry::{RequestContext, Stage},
};

pub(super) async fn ensure_fresh(
    state: &BrowserState,
    loaded: Loaded,
    budget: Budget,
    trace: &RequestContext,
) -> Result<Loaded, BrowserError> {
    budget.check()?;
    if loaded.row.refresh_deadline.is_some() {
        return Err(BrowserError::Unavailable);
    }
    if loaded.bundle.access_expires_at > now()?.checked_add(30).ok_or(BrowserError::Unavailable)? {
        return Ok(loaded);
    }
    let digest = loaded.row.identity.digest;
    let claimed = trace
        .stage(
            Stage::RefreshClaim,
            state
                .dependencies
                .sessions
                .claim_refresh(digest, loaded.row.generation),
        )
        .await?
        .ok_or(BrowserError::Unavailable)?;
    // The store has committed and released its transaction before provider I/O.
    // A cancelled/failed claim acknowledgement also never triggers a retry.
    budget.check()?;
    let old = trace.stage_sync(Stage::Crypto, || {
        SessionBundle::open(
            &claimed,
            state.dependencies.provider.config(),
            &state.dependencies.keys,
            now()?,
        )
    })?;
    budget.check()?;
    let tokens = trace
        .stage(
            Stage::Provider,
            state.dependencies.provider.refresh(
                &old.refresh,
                &claimed.identity.subject,
                old.nonce.expose_secret(),
            ),
        )
        .await?;
    budget.check()?;
    if tokens.subject != claimed.identity.subject {
        return Err(BrowserError::Unauthenticated);
    }
    let bundle = SessionBundle {
        access: tokens.access,
        refresh: tokens.refresh,
        nonce: old.nonce,
        csrf: old.csrf,
        generation: claimed.generation,
        access_expires_at: tokens.access_expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
    };
    let envelope = trace.stage_sync(Stage::Crypto, || {
        bundle.seal(&claimed.identity, &state.dependencies.keys, now()?)
    })?;
    budget.check()?;
    if !trace
        .stage(
            Stage::RefreshCommit,
            state.dependencies.sessions.finish_refresh(RefreshCommit {
                digest,
                generation: claimed.generation,
                envelope,
                access_expires_at: bundle.access_expires_at,
                refresh_expires_at: bundle.refresh_expires_at,
            }),
        )
        .await?
    {
        // Logout/expiry wins over a late provider response. Do not insert a new
        // session, retry the old token, or revoke a different generation here.
        return Err(BrowserError::Unauthenticated);
    }
    budget.check()?;
    let row = trace
        .stage(Stage::SessionLoad, state.dependencies.sessions.load(digest))
        .await?
        .ok_or(BrowserError::Unauthenticated)?;
    budget.check()?;
    if row.generation != claimed.generation || row.refresh_deadline.is_some() {
        return Err(BrowserError::Unavailable);
    }
    let bundle = trace.stage_sync(Stage::Crypto, || {
        SessionBundle::open(
            &row,
            state.dependencies.provider.config(),
            &state.dependencies.keys,
            now()?,
        )
    })?;
    // The caller re-verifies access authority, then touches this exact active
    // generation before forwarding. No recursive refresh for short-lived tokens.
    Ok(Loaded { row, bundle })
}
