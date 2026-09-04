use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProxyStorageProfile {
    Production,
    Development,
}

pub(crate) fn proxy_storage_profile_value(
    raw: Option<&str>,
    postgres_configured: bool,
) -> Result<ProxyStorageProfile, io::Error> {
    match raw {
        Some("development") => Ok(ProxyStorageProfile::Development),
        None | Some("production") if postgres_configured => Ok(ProxyStorageProfile::Production),
        None | Some("production") => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "production MCP proxy storage requires APEX_CONTROL_POSTGRES_URL",
        )),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APEX_CONTROL_PROXY_PROFILE must be exactly production or development",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_and_default_require_postgres() {
        for profile in [None, Some("production")] {
            assert!(proxy_storage_profile_value(profile, false).is_err());
            assert_eq!(
                proxy_storage_profile_value(profile, true).unwrap(),
                ProxyStorageProfile::Production
            );
        }
    }

    #[test]
    fn memory_requires_explicit_development_profile() {
        assert_eq!(
            proxy_storage_profile_value(Some("development"), false).unwrap(),
            ProxyStorageProfile::Development
        );
        for profile in ["", "dev", "PRODUCTION", " development ", "unknown"] {
            assert!(proxy_storage_profile_value(Some(profile), false).is_err());
            assert!(proxy_storage_profile_value(Some(profile), true).is_err());
        }
    }
}
