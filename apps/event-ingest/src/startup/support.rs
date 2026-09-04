use std::io;
use std::sync::{Arc, Mutex};
#[cfg(feature = "postgres")]
use std::time::Duration;

#[cfg(feature = "valkey")]
use super::super::env::{path, required};

/// Periodically reclaims Postgres idempotency reservations stuck `pending`
/// past any realistic fanout window (a crash between `reserve()` committing
/// and `commit()`/`abort()` running leaves a row nothing else can release,
/// since the reservation's in-process handle dies with the process). A no-op
/// when the file/memory idempotency backends are in use, since those never
/// persist a `pending` state that could outlive their own process. Uses a
/// dedicated connection so the reaper cannot starve or race the main store's
/// connection.
#[cfg(feature = "postgres")]
pub(super) fn spawn_idempotency_reaper(
    capacity: usize,
) -> Result<Option<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    let Ok(url) = std::env::var("APEX_POSTGRES_URL") else {
        return Ok(None);
    };
    if url.trim().is_empty() {
        return Ok(None);
    }
    let interval_secs: u64 = std::env::var("APEX_IDEMPOTENCY_REAP_INTERVAL_SECS")
        .unwrap_or_else(|_| "60".to_owned())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_REAP_INTERVAL_SECS must be a positive integer",
            )
        })?;
    let max_age_secs: u64 = std::env::var("APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS")
        .unwrap_or_else(|_| "600".to_owned())
        .parse()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS must be a positive integer",
            )
        })?;
    if interval_secs == 0 || max_age_secs == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_IDEMPOTENCY_REAP_INTERVAL_SECS and APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS must be positive",
        )
        .into());
    }
    // The reaper's connection is established lazily inside the loop, not
    // here, so a transient Postgres hiccup at startup (or any time later)
    // can never fail or block the whole gateway coming up -- this is a
    // best-effort maintenance task, not core request-serving functionality.
    Ok(Some(tokio::task::spawn_blocking(move || {
        let mut store: Option<apex_event_ingest::PostgresIdempotencyStore> = None;
        loop {
            std::thread::sleep(Duration::from_secs(interval_secs));
            let active_store = match &mut store {
                Some(store) => store,
                None => {
                    match apex_event_ingest::PostgresIdempotencyStore::connect(&url, capacity) {
                        Ok(connected) => store.insert(connected),
                        Err(error) => {
                            eprintln!(
                                "event-ingest idempotency reaper: connect deferred: {}: {}",
                                error.code.public_code(),
                                error.summary
                            );
                            continue;
                        }
                    }
                }
            };
            match active_store.reap_expired(Duration::from_secs(max_age_secs)) {
                Ok(0) => {}
                Ok(count) => eprintln!(
                    "event-ingest idempotency reaper: reclaimed {count} stuck pending reservation(s)"
                ),
                Err(error) => {
                    eprintln!(
                        "event-ingest idempotency reaper: reap attempt failed: {}: {}",
                        error.code.public_code(),
                        error.summary
                    );
                    // The connection may be poisoned; drop it and reconnect
                    // fresh next cycle rather than retrying indefinitely
                    // against a connection that can never recover on its own.
                    store = None;
                }
            }
        }
    })))
}

#[cfg(not(feature = "postgres"))]
pub(super) fn spawn_idempotency_reaper(
    _capacity: usize,
) -> Result<Option<tokio::task::JoinHandle<()>>, Box<dyn std::error::Error>> {
    Ok(None)
}

pub(super) type SharedEphemeralStore = Arc<Mutex<Box<dyn apex_event_ingest::EphemeralStore>>>;

pub(super) fn build_ephemeral_store(
    trusted_base: &std::path::Path,
) -> Result<SharedEphemeralStore, Box<dyn std::error::Error>> {
    #[cfg(feature = "valkey")]
    use apex_event_ingest::FallbackEphemeralStore;
    use apex_event_ingest::{EphemeralStore, InMemoryEphemeralStore};

    // Always install a process-local store. When Valkey is configured and the
    // binary is built with `--features valkey`, prefer the remote accelerator
    // and fall back to memory only on Unavailable.
    let memory = InMemoryEphemeralStore::new();

    #[cfg(feature = "valkey")]
    {
        if std::env::var("APEX_VALKEY_HOST")
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
        {
            let config = apex_event_ingest::ValkeyConfig {
                host: required("APEX_VALKEY_HOST")?,
                port: std::env::var("APEX_VALKEY_PORT")
                    .unwrap_or_else(|_| "6379".to_owned())
                    .parse()
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "APEX_VALKEY_PORT must be a TCP port",
                        )
                    })?,
                username: std::env::var("APEX_VALKEY_USERNAME")
                    .unwrap_or_else(|_| "apex-ingest".to_owned()),
                password_file: path("APEX_VALKEY_PASSWORD_FILE")?,
                ca_file: path("APEX_VALKEY_CA_FILE")?,
                client_cert_file: path("APEX_VALKEY_CLIENT_CERT_FILE")?,
                client_key_file: path("APEX_VALKEY_CLIENT_KEY_FILE")?,
                trusted_base: trusted_base.to_path_buf(),
            };
            let valkey = apex_event_ingest::ValkeyEphemeralStore::connect(&config)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
            let store: Box<dyn EphemeralStore> =
                Box::new(FallbackEphemeralStore::new(valkey, memory));
            return Ok(Arc::new(Mutex::new(store)));
        }
    }

    #[cfg(not(feature = "valkey"))]
    {
        let _ = trusted_base;
        if std::env::var("APEX_VALKEY_HOST")
            .ok()
            .filter(|value| !value.is_empty())
            .is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_VALKEY_HOST is set but this binary was not built with --features valkey",
            )
            .into());
        }
    }

    let store: Box<dyn EphemeralStore> = Box::new(memory);
    Ok(Arc::new(Mutex::new(store)))
}
