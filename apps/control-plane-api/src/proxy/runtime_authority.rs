//! PostgreSQL-only current-operation callback, never an execution permit.
//!
//! The synchronous root retains the reader and dedicated database worker.

use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

use zeroize::Zeroizing;

mod enrollment;
mod error;
mod executor;
mod lifecycle;
mod material;
#[cfg(feature = "test-support")]
mod observations;
mod owner;
mod policy;
mod refresh;
mod request;
mod service;

pub use error::RuntimeAuthorityError;
#[cfg(feature = "test-support")]
pub use observations::RuntimeAuthorityObservations;
pub use service::{RuntimeAuthorityService, bounded_runtime_authority_service_server};

/// Fixed deployment paths; no RPC-selected file or implicit enrollment source.
/// The deployment owner must protect these files and their ancestor directories.
#[derive(Clone)]
pub struct RuntimeAuthorityPolicyFiles {
    trusted_base: PathBuf,
    peer_policy_file: PathBuf,
    enrollment_file: PathBuf,
}

impl RuntimeAuthorityPolicyFiles {
    /// Prepare explicit settings without I/O; relative files use the trusted base.
    ///
    /// # Errors
    /// Refuses empty paths and a trusted base that is not absolute.
    pub fn new(
        trusted_base: PathBuf,
        peer_policy_file: PathBuf,
        enrollment_file: PathBuf,
    ) -> Result<Self, RuntimeAuthorityError> {
        let files = Self {
            trusted_base,
            peer_policy_file,
            enrollment_file,
        };
        files.validate()?;
        Ok(files)
    }

    fn validate(&self) -> Result<(), RuntimeAuthorityError> {
        if !self.trusted_base.is_absolute()
            || self.peer_policy_file.as_os_str().is_empty()
            || self.enrollment_file.as_os_str().is_empty()
        {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        Ok(())
    }
}

impl fmt::Debug for RuntimeAuthorityPolicyFiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityPolicyFiles { [redacted] }")
    }
}

/// Synchronous root owner, to be retained through partial startup and shutdown.
///
/// The accepted implementation contract uses a 15-second initial observation
/// and one shared 15-second shutdown observation, both outside entered Tokio.
/// These are observation budgets, not physical OS I/O preemption guarantees.
pub struct RuntimeAuthorityOwner {
    files: RuntimeAuthorityPolicyFiles,
    database_url: Option<Zeroizing<String>>,
    workers: owner::Workers,
}

impl RuntimeAuthorityOwner {
    /// Read-only bounded scheduling witness, unavailable in production builds.
    #[cfg(feature = "test-support")]
    pub fn observations(&self) -> RuntimeAuthorityObservations {
        RuntimeAuthorityObservations(Arc::clone(&self.workers.shared.observations))
    }

    /// Construct outside entered Tokio without I/O; never infer a DSN or identity.
    ///
    /// # Errors
    /// Refuses entered Tokio, invalid settings or an empty database setting.
    pub fn new(
        files: RuntimeAuthorityPolicyFiles,
        database_url: &str,
    ) -> Result<Self, RuntimeAuthorityError> {
        if tokio::runtime::Handle::try_current().is_ok() || database_url.trim().is_empty() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        files.validate()?;
        Ok(Self {
            files,
            database_url: Some(Zeroizing::new(database_url.to_owned())),
            workers: owner::Workers::new(),
        })
    }

    /// Start on an existing root owner, retaining it on every partial failure.
    ///
    /// # Errors
    /// Refuses reentry, invalid initial policy, unavailable PG or expired startup.
    pub fn start(&mut self) -> Result<RuntimeAuthorityService, RuntimeAuthorityError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        let database_url = self
            .database_url
            .take()
            .ok_or(RuntimeAuthorityError::Unavailable)?;
        let files = self.files.clone();
        let client = self.workers.start(
            move |shared| refresh::spawn(files, shared),
            move || {
                crate::proxy::PostgresProxyStore::connect(&database_url)
                    .map_err(|_| RuntimeAuthorityError::Unavailable)
            },
            Duration::from_secs(15),
        )?;
        Ok(RuntimeAuthorityService::new(
            client,
            Arc::clone(&self.workers.shared),
        ))
    }

    /// Signal both workers without waiting or joining on an async thread.
    pub fn request_shutdown(&self) {
        self.workers.request_shutdown();
    }

    /// Observe actual cleanup outside Tokio within one shared 15-second budget.
    pub fn shutdown(&mut self) -> RuntimeAuthorityShutdown {
        self.workers.shutdown(Duration::from_secs(15))
    }
}

impl fmt::Debug for RuntimeAuthorityOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RuntimeAuthorityOwner { [redacted] }")
    }
}

/// Completion observations, not deadline-based assertions that a worker exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAuthorityShutdown {
    /// Actual refresh-reader cleanup and join were observed.
    pub reader_complete: bool,
    /// Actual dedicated-store cleanup and worker join were observed.
    pub postgres_complete: bool,
    /// Both actual worker cleanups were observed within the shared budget.
    pub cleanup_complete: bool,
}

#[cfg(test)]
mod tests;
