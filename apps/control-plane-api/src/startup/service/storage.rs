//! Opens the durable outbox and inbox backends (file or Postgres, selected
//! the same way for both), and the optional cross-replica admission
//! accelerator (Valkey) they sit alongside.

use std::io;
use std::path::{Path, PathBuf};

use apex_control_plane_api::{
    ControlInboxBackend, ControlOutboxBackend, FileCommandInbox, SharedEphemeralStore,
};
#[cfg(feature = "postgres")]
use apex_control_plane_api::{RecoveringPostgresCommandInbox, RecoveringPostgresOutbox};

#[cfg(feature = "postgres")]
use super::super::env::postgres_pool_size;
use super::super::env::{control_postgres_url, control_valkey_env, inbox_scope_quota};

const OUTBOX_CAPACITY: usize = 1_000_000;

/// Opens the durable command inbox -- the delivery-state store `PollCommands`
/// reads and the accept path writes. It follows the outbox backend selection:
/// a Postgres outbox gets a Postgres inbox, so every replica sees the same
/// delivery state; otherwise both remain on the operator-owned file volume.
pub(super) fn open_inbox() -> Result<ControlInboxBackend, Box<dyn std::error::Error>> {
    // Validated eagerly, before either backend is opened, and against the
    // same capacity both backends are about to be constructed with: a
    // misconfigured per-scope quota is a startup failure, not something
    // discovered later on the first `record()` call.
    let scope_quota = inbox_scope_quota(OUTBOX_CAPACITY)?;
    #[cfg(feature = "postgres")]
    {
        if let Some(url) = control_postgres_url()? {
            let pool_size = postgres_pool_size()?;
            let mut inboxes = Vec::with_capacity(pool_size);
            for _ in 0..pool_size {
                let inbox =
                    RecoveringPostgresCommandInbox::connect(&url, OUTBOX_CAPACITY, scope_quota)
                        .map_err(|error| {
                            format!("failed to open control inbox: {}", error.code.as_str())
                        })?;
                inboxes
                    .push(Box::new(inbox) as Box<dyn apex_control_plane_api::CommandInbox + Send>);
            }
            println!("apex-control-plane-api inbox backend: postgres");
            println!(
                "apex-control-plane-api inbox per-scope quota: {scope_quota} command(s) per workspace/namespace"
            );
            return ControlInboxBackend::new_pool(inboxes)
                .map_err(|_| io::Error::other("failed to create control inbox pool").into());
        }
    }
    let base = inbox_base();
    std::fs::create_dir_all(&base)?;
    let inbox_file = base.join(
        std::env::var("APEX_CONTROL_INBOX_FILE").unwrap_or_else(|_| "inbox.jsonl".to_owned()),
    );
    let inbox = FileCommandInbox::open(&inbox_file, &base, OUTBOX_CAPACITY, scope_quota)
        .map_err(|error| format!("failed to open control inbox: {}", error.code.as_str()))?;
    println!("apex-control-plane-api inbox backend: file");
    println!(
        "apex-control-plane-api inbox per-scope quota: {scope_quota} command(s) per workspace/namespace"
    );
    Ok(ControlInboxBackend::new(Box::new(inbox)))
}

/// Where the file outbox lives.
fn outbox_base() -> PathBuf {
    PathBuf::from(
        std::env::var("APEX_CONTROL_OUTBOX_BASE")
            .unwrap_or_else(|_| "./data/control-outbox".to_owned()),
    )
}

/// Where the command inbox lives.
///
/// Defaults to the outbox base, because for a file-backed deployment they are
/// the same durability volume and splitting them by default would be a way to
/// lose one of them. It remains separately configurable for deployments that
/// intentionally choose a local file inbox.
fn inbox_base() -> PathBuf {
    match std::env::var("APEX_CONTROL_INBOX_BASE") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => outbox_base(),
    }
}

/// Builds the optional cross-replica admission accelerator.
///
/// Structurally `event-ingest`'s `build_ephemeral_store`, with one deliberate
/// difference: an unreachable Valkey **does not stop this gateway starting**.
///
/// `event-ingest` refuses to come up if `ValkeyEphemeralStore::connect` fails,
/// which is defensible for the ingest data path. Doing the same here would
/// make an explicitly non-authoritative accelerator a hard startup dependency
/// of the out-of-band control channel -- the exact coupling ADR-0006 exists to
/// remove, and the same mistake the JetStream publisher already had to avoid.
/// So the split is the same one used there: **configuration errors abort
/// startup loudly, an unreachable instance does not.** A refused *config*
/// (`EphemeralErrorCode::InvalidKey` -- a path outside the trusted base, a
/// key readable beyond its owner, a malformed host) is a misconfiguration;
/// `Unavailable` is an outage, and an outage means the process runs on its
/// process-local ceiling, which is the hard floor either way.
///
/// The connection is also re-established lazily by [`LazyValkeyStore`] rather
/// than only at startup, so a Valkey that was down when this process booted is
/// picked up without a restart -- and `FallbackEphemeralStore`'s circuit
/// breaker is what keeps that retry from becoming a per-request stall.
pub(super) fn build_ephemeral_store(
    trusted_base: &Path,
) -> Result<Option<SharedEphemeralStore>, Box<dyn std::error::Error>> {
    let configured = control_valkey_env()?;
    #[cfg(feature = "valkey")]
    {
        use apex_auth::{EphemeralStore, FallbackEphemeralStore, InMemoryEphemeralStore};

        if let Some(settings) = configured {
            let config = apex_auth::ValkeyConfig {
                host: settings.host,
                port: settings.port,
                username: settings.username,
                password_file: settings.password_file,
                ca_file: settings.ca_file,
                client_cert_file: settings.client_cert_file,
                client_key_file: settings.client_key_file,
                trusted_base: trusted_base.to_path_buf(),
            };
            // Eager *configuration* validation, deferred connection. Same
            // split as `NatsTlsConfig::validate` in `startup/fanout.rs`, and
            // for the same reason.
            config.validate().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "APEX_CONTROL_VALKEY_* configuration was refused: {}",
                        error.code.as_str()
                    ),
                )
            })?;
            let store: Box<dyn EphemeralStore> = Box::new(FallbackEphemeralStore::new(
                crate::startup::valkey::LazyValkeyStore::new(config),
                InMemoryEphemeralStore::new(),
            ));
            println!(
                "apex-control-plane-api admission ceiling: shared (valkey), local ceiling retained as the floor"
            );
            return Ok(Some(std::sync::Mutex::new(store).into()));
        }
    }
    #[cfg(not(feature = "valkey"))]
    {
        let _ = trusted_base;
        if configured.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_VALKEY_HOST is set but this binary was not built with --features valkey",
            )
            .into());
        }
    }
    println!("apex-control-plane-api admission ceiling: process-local only");
    Ok(None)
}

/// Selects the durable outbox backend, mirroring `event-ingest`'s
/// `open_durability_stores`: a URL selects Postgres, its absence selects the
/// file backend, and a URL set on a binary built without `--features postgres`
/// is a hard startup error rather than a silent downgrade to a single-writer
/// file.
///
/// That last case is the one this function used to get wrong in the other
/// direction. It unconditionally built a `FileOutbox`, so `--features postgres`
/// changed nothing about the running binary -- it only forwarded the feature to
/// `apex-durability`. A deployment that believed it had a multi-writer
/// backend had a single-writer one, which is exactly the assumption
/// cross-replica work would have been built on top of.
pub(super) fn open_outbox() -> Result<ControlOutboxBackend, Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    {
        if let Some(url) = control_postgres_url()? {
            // Reused verbatim from `event-ingest`, including its multi-replica
            // fixes (advisory-locked schema DDL, `ON CONFLICT DO NOTHING` on
            // the insert race, and `FOR UPDATE SKIP LOCKED` claim leases in
            // `pending_batch()`). See `env::control_postgres_url_value` for why this
            // must be a different database or schema from the ingest
            // gateway's, given both share the `apex_event_outbox` table name.
            let pool_size = postgres_pool_size()?;
            let mut outboxes = Vec::with_capacity(pool_size);
            for _ in 0..pool_size {
                let outbox =
                    RecoveringPostgresOutbox::connect(&url, OUTBOX_CAPACITY).map_err(|error| {
                        format!("failed to open control outbox: {}", error.code.as_str())
                    })?;
                outboxes.push(Box::new(outbox) as Box<dyn apex_durability::EventOutbox + Send>);
            }
            println!("apex-control-plane-api outbox backend: postgres");
            println!("apex-control-plane-api postgres outbox pool: {pool_size} connection(s)");
            return ControlOutboxBackend::new_pool(outboxes)
                .map_err(|_| io::Error::other("failed to create control outbox pool").into());
        }
    }
    #[cfg(not(feature = "postgres"))]
    {
        if control_postgres_url()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_CONTROL_POSTGRES_URL is set but this binary was not built with --features postgres",
            )
            .into());
        }
    }
    let outbox_base = outbox_base();
    std::fs::create_dir_all(&outbox_base)?;
    let outbox_file = outbox_base.join(
        std::env::var("APEX_CONTROL_OUTBOX_FILE").unwrap_or_else(|_| "commands.jsonl".to_owned()),
    );
    let file_outbox =
        apex_durability::FileOutbox::open(&outbox_file, &outbox_base, OUTBOX_CAPACITY)
            .map_err(|error| format!("failed to open control outbox: {}", error.code.as_str()))?;
    println!("apex-control-plane-api outbox backend: file");
    Ok(ControlOutboxBackend::new(Box::new(file_outbox)))
}
