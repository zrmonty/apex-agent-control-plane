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
