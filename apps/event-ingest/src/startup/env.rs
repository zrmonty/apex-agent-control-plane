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
