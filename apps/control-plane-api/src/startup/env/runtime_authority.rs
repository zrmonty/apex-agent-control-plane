//! Explicit paired opt-in on the existing mTLS control listener.
use std::{io, path::PathBuf};

#[cfg_attr(all(not(feature = "postgres"), not(test)), allow(dead_code))]
pub(crate) struct RuntimeAuthorityEnv {
    pub peer_policy_file: PathBuf,
    pub enrollment_file: PathBuf,
}

const PEER: &str = "APEX_CONTROL_RUNTIME_PEER_POLICY_FILE";
const ENROLLMENT: &str = "APEX_CONTROL_RUNTIME_ENROLLMENT_FILE";

pub(crate) fn runtime_authority_env() -> Result<Option<RuntimeAuthorityEnv>, io::Error> {
    let peer = read(PEER)?;
    let enrollment = read(ENROLLMENT)?;
    if peer.is_none() && enrollment.is_none() {
        return Ok(None);
    }
    resolve(
        peer.as_deref(),
        enrollment.as_deref(),
        cfg!(feature = "postgres"),
        super::control_postgres_url()?.is_some(),
    )
}

fn read(name: &str) -> Result<Option<String>, io::Error> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(invalid()),
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "runtime authority requires paired policy/enrollment files and compiled PostgreSQL with an explicit control database",
    )
}

fn resolve(
    peer: Option<&str>,
    enrollment: Option<&str>,
    postgres_compiled: bool,
    has_postgres: bool,
) -> Result<Option<RuntimeAuthorityEnv>, io::Error> {
    if peer.is_none() && enrollment.is_none() {
        return Ok(None);
    }
    let peer = peer
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(invalid)?;
    let enrollment = enrollment
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(invalid)?;
    if !postgres_compiled || !has_postgres {
        return Err(invalid());
    }
    Ok(Some(RuntimeAuthorityEnv {
        peer_policy_file: PathBuf::from(peer),
        enrollment_file: PathBuf::from(enrollment),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_callback_configuration_stays_disabled_without_dependencies() {
        for compiled in [false, true] {
            assert!(resolve(None, None, compiled, false).unwrap().is_none());
        }
    }

    #[test]
    fn paired_paths_preserve_exact_settings_with_postgres() {
        let config = resolve(
            Some("peer.json"),
            Some("nested/enrollment.json"),
            true,
            true,
        )
        .unwrap()
        .expect("explicit callback settings");
        assert_eq!(config.peer_policy_file, PathBuf::from("peer.json"));
        assert_eq!(
            config.enrollment_file,
            PathBuf::from("nested/enrollment.json")
        );
    }

    #[test]
    fn partial_empty_and_nonpostgres_callback_configuration_refuses() {
        for (peer, enrollment, compiled, database) in [
            (Some("peer.json"), None, true, true),
            (None, Some("enrollment.json"), true, true),
            (Some(""), Some("enrollment.json"), true, true),
            (Some("peer.json"), Some("  "), true, true),
            (Some("peer.json"), Some("enrollment.json"), false, true),
            (Some("peer.json"), Some("enrollment.json"), true, false),
        ] {
            let error = match resolve(peer, enrollment, compiled, database) {
                Err(error) => error,
                Ok(_) => {
                    panic!("invalid configuration must not enable or silently disable callback")
                }
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains("peer.json"));
        }
    }
}
