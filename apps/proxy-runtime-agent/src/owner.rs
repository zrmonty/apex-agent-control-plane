//! One owned blocking refresh reader; immutable snapshots are never permits.
use crate::launch::LaunchCatalog;
use apex_auth::RuntimePeerPolicy;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

pub(crate) const FRESHNESS: Duration = Duration::from_secs(2);
pub(crate) const REFRESH: Duration = Duration::from_millis(250);
pub(crate) const UNAVAILABLE: &str = "RUNTIME_POLICY_UNAVAILABLE";

pub(crate) struct Metadata {
    pub policy: RuntimePeerPolicy,
    pub catalog: LaunchCatalog,
    #[cfg(target_os = "linux")]
    pub execution: Option<crate::execution::metadata::Catalogs>,
    #[cfg(target_os = "linux")]
    pub network: Option<crate::network_catalog::NetworkCatalog>,
    from: u64,
    until: u64,
    digest: [u8; 32],
}
impl Metadata {
    #[cfg(target_os = "linux")]
    pub(crate) fn digest(&self) -> String {
        self.digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    pub(crate) fn parse(policy: &[u8], catalog: &[u8]) -> Result<Self, &'static str> {
        let parsed = LaunchCatalog::parse(catalog).map_err(|_| UNAVAILABLE)?;
        // LaunchCatalog has already rejected duplicate/unknown/positional fields.
        // Extract its exact integer interval for an independent LOCAL-clock check.
        // Task 1's pure authority-time preparation semantics remain unchanged.
        let value: serde_json::Value = serde_json::from_slice(catalog).map_err(|_| UNAVAILABLE)?;
        let metadata = Self {
            policy: RuntimePeerPolicy::parse_json(policy).map_err(|_| UNAVAILABLE)?,
            catalog: parsed,
            #[cfg(target_os = "linux")]
            execution: None,
            #[cfg(target_os = "linux")]
            network: None,
            from: value["valid_from_unix_us"].as_u64().ok_or(UNAVAILABLE)?,
            until: value["expires_at_unix_us"].as_u64().ok_or(UNAVAILABLE)?,
            digest: Sha256::digest(
                [
                    Sha256::digest(policy).as_slice(),
                    Sha256::digest(catalog).as_slice(),
                ]
                .concat(),
            )
            .into(),
        };
        metadata.current()?;
        Ok(metadata)
    }
    pub(crate) fn current(&self) -> Result<(), &'static str> {
        let now = self.policy.check_current().map_err(|_| UNAVAILABLE)?;
        #[cfg(target_os = "linux")]
        if let Some(execution) = &self.execution {
            execution.current(now)?;
        }
        #[cfg(target_os = "linux")]
        if let Some(network) = &self.network {
            network.current(now)?;
        }
        if now < self.from || now >= self.until {
            return Err(UNAVAILABLE);
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn with_execution(
        mut self,
        image: &[u8],
        authority: &[u8],
        tools: &[u8],
    ) -> Result<Self, &'static str> {
        self.execution = Some(crate::execution::metadata::Catalogs::parse(
            image, authority, tools,
        )?);
        let mut hash = Sha256::new();
        hash.update(self.digest);
        for bytes in [image, authority, tools] {
            hash.update(Sha256::digest(bytes));
        }
        self.digest = hash.finalize().into();
        self.current()?;
        Ok(self)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn with_network(
        mut self,
        bytes: &[u8],
        installation: &str,
        host_policy: &str,
    ) -> Result<Self, &'static str> {
        let network = crate::network_catalog::NetworkCatalog::parse(bytes)?;
        if network.installation_id() != installation || network.host_policy_version() != host_policy
        {
            return Err(UNAVAILABLE);
        }
        network.join_images(&self.execution.as_ref().ok_or(UNAVAILABLE)?.images)?;
        let mut hash = Sha256::new();
        hash.update(self.digest);
        hash.update(Sha256::digest(bytes));
        self.digest = hash.finalize().into();
        self.network = Some(network);
        self.current()?;
        Ok(self)
    }
}

pub(crate) struct State {
    pub metadata: Option<Arc<Metadata>>,
    pub read_started: Instant,
    pub stopped: bool,
}
pub(crate) type Shared = Arc<Mutex<State>>;

pub(crate) struct Reader {
    pub shared: Shared,
    pub publication: tokio::sync::watch::Receiver<bool>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}
impl Reader {
    // Internal function only. Production always supplies the protected directory reader.
    pub(crate) fn start(
        mut load: impl FnMut() -> Result<Metadata, &'static str> + Send + 'static,
    ) -> Result<Self, &'static str> {
        let shared = Arc::new(Mutex::new(State {
            metadata: None,
            read_started: Instant::now(),
            stopped: false,
        }));
        let worker = Arc::clone(&shared);
        let (published, publication) = tokio::sync::watch::channel(false);
        let mut published = Some(published);
        let (stop, stopped) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("runtime-config-reader".into())
            .spawn(move || {
                loop {
                    let started = Instant::now();
                    let result = load(); // Exactly one physical reader, no timeout replacements.
                    let Ok(mut state) = worker.lock() else {
                        break;
                    };
                    if state.stopped {
                        break;
                    }
                    match result {
                        Ok(metadata) if started.elapsed() < FRESHNESS => {
                            if state
                                .metadata
                                .as_ref()
                                .is_none_or(|old| old.digest != metadata.digest)
                            {
                                state.metadata = Some(Arc::new(metadata));
                            }
                            state.read_started = started;
                        }
                        _ => {
                            state.metadata = None;
                        }
                    }
                    drop(state);
                    // A loader's deployment notification is not publication.
                    // Release the one-shot latch only after the first result is
                    // visible under the metadata lock (including poisoned results).
                    if let Some(published) = published.take() {
                        published.send_replace(true);
                    }
                    if stopped.recv_timeout(REFRESH) != Err(mpsc::RecvTimeoutError::Timeout) {
                        break;
                    }
                }
            })
            .map_err(|_| UNAVAILABLE)?;
        Ok(Self {
            shared,
            publication,
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}
impl Drop for Reader {
    fn drop(&mut self) {
        if let Ok(mut state) = self.shared.lock() {
            state.stopped = true;
            state.metadata = None;
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub(crate) fn snapshot(shared: &Shared) -> Result<Arc<Metadata>, &'static str> {
    let state = shared.lock().map_err(|_| UNAVAILABLE)?;
    if state.stopped || state.read_started.elapsed() >= FRESHNESS {
        return Err(UNAVAILABLE);
    }
    let metadata = state.metadata.as_ref().ok_or(UNAVAILABLE)?;
    metadata.current()?;
    Ok(Arc::clone(metadata))
}

#[cfg(test)]
pub(crate) mod tests;
