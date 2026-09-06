use super::*;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

/// Synchronous startup-root owner; dropping it closes authentication and joins
/// its one physical reader. Never drop this owner on a Tokio worker.
pub struct ManagedEvidenceOwner {
    stop: mpsc::Sender<()>,
    active: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl ManagedEvidenceOwner {
    /// Start the protected reader outside any Tokio runtime, and await the
    /// first complete valid snapshot. Linux production only; no ACL waiver.
    /// # Errors
    /// Refuses invalid/prohibited paths, profiles, platforms or thread startup.
    pub fn start(
        path: &Path,
        trusted_base: &Path,
    ) -> Result<(Self, ManagedEvidenceResolver), EnrollmentError> {
        let path: PathBuf = path.into();
        let base: PathBuf = trusted_base.into();
        Self::start_reader(move || super::protected::read(&path, &base))
    }

    pub(super) fn start_reader(
        mut read: impl FnMut() -> Result<Vec<u8>, EnrollmentError> + Send + 'static,
    ) -> Result<(Self, ManagedEvidenceResolver), EnrollmentError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(EnrollmentError);
        }
        let (stop, stopped) = mpsc::channel();
        let (ready, first) = mpsc::sync_channel(1);
        let active = Arc::new(AtomicBool::new(true));
        let snapshot = Arc::new(RwLock::new(None));
        let resolver = ManagedEvidenceResolver {
            snapshot: snapshot.clone(),
            active: active.clone(),
        };
        let alive = active.clone();
        let reader = thread::Builder::new()
            .name("apex-evidence-enrollment".into())
            .spawn(move || {
                let mut first = Some(ready);
                loop {
                    if !alive.load(Ordering::Acquire) {
                        break;
                    }
                    let read_started = Instant::now();
                    let refreshed = read()
                        .and_then(|bytes| profile::Profile::parse(&bytes))
                        .and_then(|profile| {
                            let now = now_us()?;
                            if read_started.elapsed() >= Duration::from_secs(5)
                                || now < profile.valid_from
                                || now >= profile.expires
                            {
                                return Err(EnrollmentError);
                            }
                            Ok(Snapshot {
                                profile,
                                read_started,
                            })
                        });
                    let valid = refreshed.is_ok();
                    if let Ok(mut snapshot) = snapshot.write() {
                        // Invalid replacement/removal is a revocation, never a
                        // reason to retain the previous authorization snapshot.
                        *snapshot = refreshed.ok();
                    } else {
                        break;
                    }
                    if let Some(ready) = first.take() {
                        let _ = ready.send(valid);
                        if !valid {
                            break;
                        }
                    }
                    match stopped.recv_timeout(Duration::from_secs(1)) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        _ => break,
                    }
                }
                alive.store(false, Ordering::Release);
            })
            .map_err(|_| EnrollmentError)?;
        // Ownership exists before waiting: failed first read or a panic joins
        // the physical reader just as partial construction and shutdown do.
        let owner = Self {
            stop,
            active,
            reader: Some(reader),
        };
        if first.recv() != Ok(true) {
            return Err(EnrollmentError);
        }
        Ok((owner, resolver))
    }
}

impl Drop for ManagedEvidenceOwner {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let _ = self.stop.send(());
        if let Some(reader) = self.reader.take() {
            // Intentionally no timeout/replacement/detach for a physically
            // stuck read. The synchronous root remains its owner until exit.
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
mod tests;
