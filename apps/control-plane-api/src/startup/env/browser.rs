//! Explicit opt-in for the confined browser hop; never a public plaintext API.
use super::OperatorTokenSource;
use std::{io, net::SocketAddr, path::PathBuf};

// Parsed settings are only consumed by the PostgreSQL-enabled browser service;
// non-PostgreSQL builds still compile the parser to reject explicit enablement.
#[cfg_attr(all(not(feature = "postgres"), not(test)), allow(dead_code))]
pub(crate) struct BrowserEnv {
    pub bind_addr: SocketAddr,
    pub config_file: PathBuf,
}

pub(crate) fn browser_env() -> Result<Option<BrowserEnv>, io::Error> {
    let bind = read_optional("APEX_CONTROL_BROWSER_BIND_ADDR")?;
    let config = read_optional("APEX_CONTROL_BROWSER_CONFIG_FILE")?;
    if bind.is_none() && config.is_none() {
        return Ok(None);
    }
    browser_env_value(
        bind.as_deref(),
        config.as_deref(),
        cfg!(feature = "postgres"),
        super::control_postgres_url()?.is_some(),
        &super::operator_token_source()?,
    )
}

fn read_optional(name: &str) -> Result<Option<String>, io::Error> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid {name} encoding"),
        )),
    }
}

fn browser_env_value(
    bind: Option<&str>,
    config: Option<&str>,
    postgres_compiled: bool,
    has_postgres: bool,
    operator: &OperatorTokenSource,
) -> Result<Option<BrowserEnv>, io::Error> {
    if bind.is_none() && config.is_none() {
        return Ok(None);
    }
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "browser edge requires paired bind/config, compiled PostgreSQL with its own database, and Keycloak operator authentication",
        )
    };
    let bind = bind.filter(|value| !value.is_empty()).ok_or_else(invalid)?;
    let config = config
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(invalid)?;
    if !postgres_compiled || !has_postgres || !matches!(operator, OperatorTokenSource::Keycloak(_))
    {
        return Err(invalid());
    }
    let bind_addr: SocketAddr = bind.parse().map_err(|_| invalid())?;
    if !bind_addr.ip().is_loopback() || bind_addr.port() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_BROWSER_BIND_ADDR must be numeric loopback with a nonzero port; expose only the configured HTTPS edge",
        ));
    }
    Ok(Some(BrowserEnv {
        bind_addr,
        config_file: PathBuf::from(config),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keycloak() -> OperatorTokenSource {
        OperatorTokenSource::Keycloak("https://identity.example/realms/apex".into())
    }
    #[test]
    fn unconfigured_browser_remains_disabled_without_extra_dependencies() {
        assert!(
            browser_env_value(None, None, false, false, &OperatorTokenSource::Unset)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn enabled_browser_requires_both_settings_postgres_and_keycloak() {
        for (bind, config, compiled, database, source) in [
            (Some("127.0.0.1:8088"), None, true, true, keycloak()),
            (None, Some("browser.json"), true, true, keycloak()),
            (Some(""), Some("browser.json"), true, true, keycloak()),
            (Some("127.0.0.1:8088"), Some(""), true, true, keycloak()),
            (
                Some("127.0.0.1:8088"),
                Some("browser.json"),
                false,
                true,
                keycloak(),
            ),
            (
                Some("127.0.0.1:8088"),
                Some("browser.json"),
                true,
                false,
                keycloak(),
            ),
            (
                Some("127.0.0.1:8088"),
                Some("browser.json"),
                true,
                true,
                OperatorTokenSource::Unset,
            ),
            (
                Some("127.0.0.1:8088"),
                Some("browser.json"),
                true,
                true,
                OperatorTokenSource::Inline("canary".into()),
            ),
            (
                Some("127.0.0.1:8088"),
                Some("browser.json"),
                true,
                true,
                OperatorTokenSource::File("table".into()),
            ),
        ] {
            assert!(browser_env_value(bind, config, compiled, database, &source).is_err());
        }
    }
    #[test]
    fn listener_is_numeric_loopback_with_an_explicit_nonzero_port() {
        for bind in ["127.0.0.1:8088", "[::1]:8088"] {
            let env = browser_env_value(Some(bind), Some("browser.json"), true, true, &keycloak())
                .unwrap()
                .unwrap();
            assert_eq!(env.bind_addr.to_string(), bind);
            assert_eq!(env.config_file, PathBuf::from("browser.json"));
        }
        for bind in [
            "0.0.0.0:8088",
            "[::]:8088",
            "192.0.2.2:8088",
            "localhost:8088",
            "127.0.0.1:0",
            " 127.0.0.1:8088",
            "127.0.0.1:8088\n",
        ] {
            assert!(
                browser_env_value(Some(bind), Some("browser.json"), true, true, &keycloak())
                    .is_err(),
                "{bind}"
            );
        }
    }
}
