//! Root-retained thread slots and a private component factory seam.
//! Thread handles remain observable after partial startup or bounded shutdown.

use super::{
    RuntimeAuthorityError, RuntimeAuthorityShutdown,
    executor::{self, Backend, Client},
    lifecycle::{Shared, StopOnExit},
    refresh::Reader,
};
use std::{
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const MAX_OBSERVATION: Duration = Duration::from_secs(15);

pub(super) struct Workers {
    pub shared: Arc<Shared>,
    reader: Option<JoinHandle<()>>,
    postgres: Option<JoinHandle<()>>,
    attempted: bool,
    reader_complete: bool,
    postgres_complete: bool,
}

impl Workers {
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(Shared::new()),
            reader: None,
            postgres: None,
            attempted: false,
            reader_complete: false,
            postgres_complete: false,
        }
    }

    // Private factories allow !Send component ownership probes and controlled
    // initial/cleanup stalls. Root will supply refresh::spawn and the real PG
    // constructor. Observation can only shorten the production 15-second cap.
    pub(super) fn start<B: Backend>(
        &mut self,
        reader: impl FnOnce(Arc<Shared>) -> Result<Reader, RuntimeAuthorityError>,
        connect: impl FnOnce() -> Result<B, RuntimeAuthorityError> + Send + 'static,
        observation: Duration,
    ) -> Result<Client<B::Snapshot>, RuntimeAuthorityError> {
        if self.attempted || self.shared.stopped() || tokio::runtime::Handle::try_current().is_ok()
        {
            return Err(RuntimeAuthorityError::Unavailable);
        }
        self.attempted = true;
        let started = Instant::now();
        let remaining = || {
            observation
                .min(MAX_OBSERVATION)
                .checked_sub(started.elapsed())
                .filter(|remaining| !remaining.is_zero())
                .ok_or(RuntimeAuthorityError::Unavailable)
        };
        let result = (|| {
            let source = reader(Arc::clone(&self.shared))?;
            self.reader = Some(source.handle);
            source
                .initial
                .recv_timeout(remaining()?)
                .map_err(|_| RuntimeAuthorityError::Unavailable)??;
            remaining()?;
            self.shared.current()?;
            let (client, receiver) = executor::channel(Arc::clone(&self.shared));
            let shared = Arc::clone(&self.shared);
            let (ready, initial) = mpsc::sync_channel(1);
            self.postgres = Some(
                thread::Builder::new()
                    .name("apex-runtime-authority".into())
                    .spawn(move || {
                        let _stop = StopOnExit(Arc::clone(&shared));
                        if shared.stopped() {
                            return;
                        }
                        let backend = match connect() {
                            Ok(backend) => backend,
                            Err(error) => {
                                let _ = ready.send(Err(error));
                                return;
                            }
                        };
                        if shared.stopped() || ready.send(Ok(())).is_err() {
                            return;
                        }
                        executor::run(backend, receiver, &shared);
                    })
                    .map_err(|_| RuntimeAuthorityError::Unavailable)?,
            );
            initial
                .recv_timeout(remaining()?)
                .map_err(|_| RuntimeAuthorityError::Unavailable)??;
            remaining()?;
            self.shared.current()?;
            Ok(client)
        })();
        if result.is_err() {
            self.request_shutdown();
        }
        result
    }

    pub(super) fn request_shutdown(&self) {
        self.shared.stop();
    }

    pub(super) fn shutdown(&mut self, observation: Duration) -> RuntimeAuthorityShutdown {
        self.request_shutdown();
        if tokio::runtime::Handle::try_current().is_err() {
            let started = Instant::now();
            loop {
                observe(&mut self.reader, &mut self.reader_complete);
                observe(&mut self.postgres, &mut self.postgres_complete);
                if (self.reader_complete && self.postgres_complete)
                    || started.elapsed() >= observation.min(MAX_OBSERVATION)
                {
                    break;
                }
                thread::sleep(
                    Duration::from_millis(5).min(
                        observation
                            .min(MAX_OBSERVATION)
                            .saturating_sub(started.elapsed()),
                    ),
                );
            }
        }
        RuntimeAuthorityShutdown {
            reader_complete: self.reader_complete,
            postgres_complete: self.postgres_complete,
            cleanup_complete: self.reader_complete && self.postgres_complete,
        }
    }
}

fn observe(slot: &mut Option<JoinHandle<()>>, complete: &mut bool) {
    if slot.as_ref().is_some_and(JoinHandle::is_finished)
        && let Some(handle) = slot.take()
    {
        // A joined panic is physically cleaned up, not a successful request.
        let _ = handle.join();
    }
    *complete = slot.is_none();
}

impl Drop for Workers {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}
