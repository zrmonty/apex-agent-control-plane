//! One fixed-path reader; no per-request I/O or replacement thread.
use super::{
    RuntimeAuthorityError, RuntimeAuthorityPolicyFiles,
    lifecycle::{Shared, StopOnExit, valid_wall_time},
    material::read_document,
};
use std::{
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(super) struct Reader {
    pub handle: JoinHandle<()>,
    pub initial: mpsc::Receiver<Result<(), RuntimeAuthorityError>>,
}

pub(super) fn spawn(
    files: RuntimeAuthorityPolicyFiles,
    shared: Arc<Shared>,
) -> Result<Reader, RuntimeAuthorityError> {
    let (ready, initial) = mpsc::sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("apex-runtime-policy".into())
        .spawn(move || {
            let _stop = StopOnExit(Arc::clone(&shared));
            let first = read_pair(&files, &shared);
            let failed = first.is_err();
            if ready.send(first).is_err() || failed {
                return;
            }
            while !shared.stopped() {
                let until = Instant::now() + Duration::from_secs(1);
                while !shared.stopped() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(25));
                }
                if shared.stopped() {
                    break;
                }
                // Invalid/missing metadata disables the pair but does not create a
                // replacement reader. A later valid read may recover a new generation.
                let _ = read_pair(&files, &shared);
            }
        })
        .map_err(|_| RuntimeAuthorityError::Unavailable)?;
    Ok(Reader { handle, initial })
}

fn read_pair(
    files: &RuntimeAuthorityPolicyFiles,
    shared: &Shared,
) -> Result<(), RuntimeAuthorityError> {
    let started = Instant::now(); // Includes BOTH file reads, not time after I/O.
    let result = (|| {
        if shared.stopped() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let peer = read_document(&files.trusted_base, &files.peer_policy_file)?;
        if shared.stopped() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let enrollment = read_document(&files.trusted_base, &files.enrollment_file)?;
        if shared.stopped() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let mut state = shared
            .policy
            .lock()
            .map_err(|_| RuntimeAuthorityError::Unavailable)?;
        state.publish(&peer, &enrollment, started, Instant::now())?;
        valid_wall_time(state.current(Instant::now())?.as_ref())
    })();
    if result.is_err()
        && let Ok(mut state) = shared.policy.lock()
    {
        state.disable();
    }
    result
}
