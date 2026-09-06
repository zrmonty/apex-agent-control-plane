//! Explicit workload mode; no token-only or privileged host-role fallback.
use apex_control_plane_api::{GovernanceConfig, ManagedAuthorityOwner};
use std::{io, path::Path};

pub(super) fn prepare(
    base: &Path,
    policy: GovernanceConfig,
) -> Result<Option<ManagedAuthorityOwner>, io::Error> {
    let raw = match std::env::var("APEX_CONTROL_MANAGED_AUTHORITY_FILE") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => return Err(unavailable()),
    };
    let database = crate::startup::env::control_postgres_url()?;
    let path = resolve(raw.as_deref(), database.is_some())?;
    let Some(path) = path else {
        return Ok(None);
    };
    let path = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    ManagedAuthorityOwner::new(
        path,
        base.to_owned(),
        database.as_deref().ok_or_else(unavailable)?,
        policy,
    )
    .map(Some)
    .map_err(|_| unavailable())
}
fn resolve(raw: Option<&str>, database: bool) -> Result<Option<std::path::PathBuf>, io::Error> {
    match raw {
        None => Ok(None),
        Some(raw) if !raw.trim().is_empty() && database => Ok(Some(raw.into())),
        _ => Err(unavailable()),
    }
}
fn unavailable() -> io::Error {
    io::Error::other("managed authority configuration unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_configuration_is_explicit_and_requires_postgres() {
        assert!(resolve(None, false).unwrap().is_none());
        assert!(resolve(Some(""), true).is_err());
        assert!(resolve(Some("  "), true).is_err());
        assert!(resolve(Some("profile.json"), false).is_err());
        assert_eq!(
            resolve(Some("profile.json"), true).unwrap(),
            Some("profile.json".into())
        );
    }
}
