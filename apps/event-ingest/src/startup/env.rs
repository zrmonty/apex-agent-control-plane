use std::collections::HashSet;
use std::env;
use std::io;
use std::path::PathBuf;

pub(crate) fn required(name: &str) -> Result<String, io::Error> {
    env::var(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{name} is required")))
}

pub(crate) fn path(name: &str) -> Result<PathBuf, io::Error> {
    Ok(PathBuf::from(required(name)?))
}

pub(crate) fn optional_path(name: &str) -> Result<Option<PathBuf>, io::Error> {
    Ok(optional_path_value(env::var(name).ok().as_deref()))
}

pub(crate) fn optional_path_value(value: Option<&str>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

pub(crate) fn attempts() -> Result<usize, io::Error> {
    attempts_value(env::var("APEX_RETRY_ATTEMPTS").ok().as_deref())
}

pub(crate) fn attempts_value(value: Option<&str>) -> Result<usize, io::Error> {
    value
        .unwrap_or("3")
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_RETRY_ATTEMPTS must be an integer from 1 through 8",
            )
        })
        .and_then(|value| {
            if (1..=8).contains(&value) {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "APEX_RETRY_ATTEMPTS must be an integer from 1 through 8",
                ))
            }
        })
}

/// How long a `complete` outbox row survives before the retention sweep
/// (`startup::service::run`'s analogue of the idempotency reaper) prunes it
/// and compacts the durable journal. Bounds mirror control-plane-api's
/// `APEX_CONTROL_COMMAND_RETENTION_SECS` (1 hour through 365 days, 30-day
/// default): both settings retain settled delivery history for the same
/// operational reconciliation window before it becomes safe to discard.
pub(crate) fn outbox_retention_secs() -> Result<u64, io::Error> {
    outbox_retention_secs_value(env::var("APEX_OUTBOX_RETENTION_SECS").ok().as_deref())
}

pub(crate) fn outbox_retention_secs_value(value: Option<&str>) -> Result<u64, io::Error> {
    value
        .unwrap_or("2592000")
        .parse::<u64>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_OUTBOX_RETENTION_SECS must be an integer from 3600 through 31536000",
            )
        })
        .and_then(|value| {
            if (3_600..=31_536_000).contains(&value) {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "APEX_OUTBOX_RETENTION_SECS must be an integer from 3600 through 31536000",
                ))
            }
        })
}

/// How often the outbox retention sweep runs. Kept separate from
/// `APEX_OUTBOX_RETENTION_SECS` so an operator can tune sweep frequency
/// without changing how long completed rows are kept, matching
/// `APEX_IDEMPOTENCY_REAP_INTERVAL_SECS`'s relationship to
/// `APEX_IDEMPOTENCY_REAP_MAX_AGE_SECS`. Default of one minute matches
/// control-plane-api's `RETENTION_SWEEP_INTERVAL`, which sweeps the same kind
/// of durable outbox on the same rhythm.
pub(crate) fn outbox_retention_interval_secs() -> Result<u64, io::Error> {
    outbox_retention_interval_secs_value(
        env::var("APEX_OUTBOX_RETENTION_INTERVAL_SECS")
            .ok()
            .as_deref(),
    )
}

pub(crate) fn outbox_retention_interval_secs_value(value: Option<&str>) -> Result<u64, io::Error> {
    value
        .unwrap_or("60")
        .parse::<u64>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_OUTBOX_RETENTION_INTERVAL_SECS must be an integer from 1 through 86400",
            )
        })
        .and_then(|value| {
            if (1..=86_400).contains(&value) {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "APEX_OUTBOX_RETENTION_INTERVAL_SECS must be an integer from 1 through 86400",
                ))
            }
        })
}

/// How many concurrent fanout workers `startup::service::run` spawns
/// (Phase 0.6 item 4). `pending_batch`'s `SELECT ... FOR UPDATE SKIP LOCKED`
/// claim (`outbox/postgres_replay.rs`) is what makes more than one safe: each
/// worker gets its own outbox handle and its own JetStream/ClickHouse/archive
/// stack (`open_durability_stores`/`build_fanout_publisher`), so raising this
/// only adds independent claimers, never a second claimer of the same row.
///
/// Bounded like every other startup setting here. The upper bound (32) is a
/// sanity ceiling, not a target: the archive sink is one Object-Lock PUT +
/// read-back verify per event against an S3-compatible endpoint (MinIO by
/// default), so throughput scales with worker count only as far as that
/// endpoint (and the Postgres connection pool backing each worker's outbox
/// handle) can actually take. The default of 4 is deliberately conservative
/// for a MinIO-by-default deployment; operators fronted by managed S3 (higher
/// realistic concurrency) can raise it.
pub(crate) fn fanout_workers() -> Result<usize, io::Error> {
    fanout_workers_value(env::var("APEX_FANOUT_WORKERS").ok().as_deref())
}

pub(crate) fn fanout_workers_value(value: Option<&str>) -> Result<usize, io::Error> {
    value
        .unwrap_or("4")
        .parse::<usize>()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "APEX_FANOUT_WORKERS must be an integer from 1 through 32",
            )
        })
        .and_then(|value| {
            if (1..=32).contains(&value) {
                Ok(value)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "APEX_FANOUT_WORKERS must be an integer from 1 through 32",
                ))
            }
        })
}

pub(crate) fn allowed_scopes() -> Result<HashSet<String>, io::Error> {
    let scopes_value = required("APEX_ALLOWED_SCOPES")?;
    if scopes_value.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES is too large",
        ));
    }
    let scopes = scopes_value
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    if scopes.is_empty() || scopes.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES must contain between 1 and 256 scopes",
        ));
    }
    if scopes.iter().any(|scope| !valid_scope(scope)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_ALLOWED_SCOPES contains an invalid scope",
        ));
    }
    Ok(scopes)
}

pub(crate) fn valid_scope(value: &str) -> bool {
    let Some((workspace, namespace)) = value.split_once('/') else {
        return false;
    };
    [workspace, namespace].iter().all(|part| {
        !part.is_empty()
            && part.len() <= 256
            && !part.contains("..")
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
    })
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod fanout_workers_tests {
    use super::fanout_workers_value;

    #[test]
    fn defaults_to_four_when_unset() {
        assert_eq!(fanout_workers_value(None).unwrap(), 4);
    }

    #[test]
    fn accepts_the_full_bounded_range() {
        assert_eq!(fanout_workers_value(Some("1")).unwrap(), 1);
        assert_eq!(fanout_workers_value(Some("32")).unwrap(), 32);
        assert_eq!(fanout_workers_value(Some("16")).unwrap(), 16);
    }

    #[test]
    fn rejects_zero_and_values_past_the_ceiling() {
        assert!(fanout_workers_value(Some("0")).is_err());
        assert!(fanout_workers_value(Some("33")).is_err());
        assert!(fanout_workers_value(Some("1000")).is_err());
    }

    #[test]
    fn fails_closed_on_non_numeric_or_negative_input() {
        assert!(fanout_workers_value(Some("not-a-number")).is_err());
        assert!(fanout_workers_value(Some("-1")).is_err());
        assert!(fanout_workers_value(Some("")).is_err());
        assert!(fanout_workers_value(Some("4.5")).is_err());
    }
}
