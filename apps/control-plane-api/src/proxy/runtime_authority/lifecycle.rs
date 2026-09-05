//! Shared stop and metadata only. No database owner crosses a thread boundary.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use super::{
    RuntimeAuthorityError,
    policy::{PolicyState, SelectedPolicy},
};

pub(super) struct Shared {
    #[cfg(feature = "test-support")]
    pub observations: Arc<super::observations::Counters>,
    pub policy: Mutex<PolicyState>,
    stopped: AtomicBool,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "test-support")]
            observations: Arc::default(),
            policy: Mutex::new(PolicyState::new()),
            stopped: AtomicBool::new(false),
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
    }
    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub fn current(&self) -> Result<Arc<SelectedPolicy>, RuntimeAuthorityError> {
        if self.stopped() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let selected = self
            .policy
            .try_lock()
            .map_err(|_| RuntimeAuthorityError::Unavailable)?
            .current(Instant::now())?;
        valid_wall_time(&selected)?;
        Ok(selected)
    }

    pub fn recheck(&self, selected: &SelectedPolicy) -> Result<(), RuntimeAuthorityError> {
        if self.stopped() {
            return Err(RuntimeAuthorityError::Cancelled);
        }
        self.policy
            .try_lock()
            .map_err(|_| RuntimeAuthorityError::Unavailable)?
            .recheck(selected, Instant::now())?;
        valid_wall_time(selected)
    }
}

pub(super) fn valid_wall_time(selected: &SelectedPolicy) -> Result<(), RuntimeAuthorityError> {
    let now = selected
        .peer
        .check_current()
        .map_err(|_| RuntimeAuthorityError::Unavailable)?;
    if now < selected.enrollment.valid_from_unix_us()
        || now >= selected.enrollment.expires_at_unix_us()
    {
        return Err(RuntimeAuthorityError::Unavailable);
    }
    Ok(())
}

pub(super) struct StopOnExit(pub Arc<Shared>);

impl Drop for StopOnExit {
    fn drop(&mut self) {
        self.0.stop();
    }
}

// Independent monotonic checks will be used at admission, dispatch and handoff.
pub(super) fn check_elapsed(
    started: Instant,
    budget: std::time::Duration,
) -> Result<(), RuntimeAuthorityError> {
    if Instant::now()
        .checked_duration_since(started)
        .is_none_or(|elapsed| elapsed >= budget)
    {
        return Err(RuntimeAuthorityError::Deadline);
    }
    Ok(())
}
