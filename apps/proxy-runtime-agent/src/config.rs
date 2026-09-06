//! Fixed deployment configuration. No RPC-selected paths or secret values.
use serde::Deserialize;
use std::net::SocketAddr;
mod execution;
pub(crate) use execution::ExecutionConfig;

#[cfg(target_os = "linux")]
mod protected;
#[cfg(target_os = "linux")]
pub(crate) use protected::Directory;
#[cfg(target_os = "linux")]
pub(crate) mod deployment;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentConfig {
    pub schema_version: u32,
    pub listen: SocketAddr,
    pub installation_id: String,
    pub agent_identity_id: String,
    pub enrollment_version: String,
    pub host_policy_version: String,
    pub authority_endpoint: String,
    pub authority_tls_server_name: String,
    #[serde(default, deserialize_with = "execution::present")]
    pub execution: Option<ExecutionConfig>,
}

impl AgentConfig {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        const ERROR: &str = "RUNTIME_CONFIG_INVALID";
        if !(1..=65_536).contains(&bytes.len())
            || bytes.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{')
        {
            return Err(ERROR);
        }
        let config: Self = serde_json::from_slice(bytes).map_err(|_| ERROR)?;
        if config.schema_version != 1
            || config.listen.port() == 0
            || !apex_domain::is_lowercase_uuidv7(&config.installation_id)
            || ![
                &config.agent_identity_id,
                &config.enrollment_version,
                &config.host_policy_version,
            ]
            .into_iter()
            .all(|s| s.len() <= 128 && apex_domain::is_scope_identifier(s))
            || config.authority_endpoint.len() > 2048
            || !config.authority_endpoint.starts_with("https://")
            || config.authority_tls_server_name.is_empty()
            || config.authority_tls_server_name.len() > 253
        {
            return Err(ERROR);
        }
        if let Some(execution) = &config.execution {
            execution.validate()?;
        }
        // The existing authority transport validator additionally checks the exact
        // origin and TLS hostname grammar before connecting or starting a listener.
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Vec<u8> {
        br#"{"schema_version":1,"listen":"127.0.0.1:9443","installation_id":"018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01","agent_identity_id":"agent","enrollment_version":"e1","host_policy_version":"h1","authority_endpoint":"https://authority:9443","authority_tls_server_name":"authority"}"#.to_vec()
    }
    #[test]
    fn optional_execution_accepts_exact_paths_and_refuses_invalid_presence() {
        let mut value: serde_json::Value = serde_json::from_slice(&valid()).unwrap();
        value["execution"] = serde_json::json!({
            "journal_root":"/protected/journal", "staging_root":"/protected/staging",
            "material_root":"/protected/material", "docker_executable":"/tools/docker",
            "docker_socket":"/run/docker.sock", "docker_config_root":"/protected/docker",
            "cosign_executable":"/tools/cosign", "cosign_cache_root":"/protected/cosign"
        });
        assert!(
            AgentConfig::parse(&serde_json::to_vec(&value).unwrap()).is_ok(),
            "valid execution refused"
        );
        for bad in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!({"jobs":99}),
            serde_json::json!([
                "/protected/journal",
                "/protected/staging",
                "/protected/material",
                "/tools/docker",
                "/run/docker.sock",
                "/protected/docker",
                "/tools/cosign",
                "/protected/cosign"
            ]),
        ] {
            let mut invalid = value.clone();
            invalid["execution"] = bad;
            assert!(AgentConfig::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        value["execution"]["staging_root"] = "/protected/journal/staging".into();
        assert!(AgentConfig::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn deployment_configuration_requires_named_strict_bounded_fields() {
        assert!(
            AgentConfig::parse(&valid()).is_ok(),
            "valid fixed deployment config refused"
        );
        let mut value: serde_json::Value = serde_json::from_slice(&valid()).unwrap();
        for bad in [0, 2] {
            value["schema_version"] = bad.into();
            assert!(AgentConfig::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        for (field, bad) in [
            ("listen", "127.0.0.1:0"),
            ("installation_id", "no"),
            ("agent_identity_id", ".."),
            ("authority_endpoint", "http://authority"),
            ("authority_tls_server_name", ""),
        ] {
            let mut value: serde_json::Value = serde_json::from_slice(&valid()).unwrap();
            value[field] = bad.into();
            assert!(
                AgentConfig::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{field}"
            );
        }
        let text = String::from_utf8(valid()).unwrap();
        for bytes in [
            text.replacen('{', "{\"schema_version\":1,", 1).into_bytes(),
            text.replacen('{', "{\"secret\":\"canary\",", 1)
                .into_bytes(),
            b"[]".to_vec(),
            vec![b' '; 65_537],
        ] {
            assert!(AgentConfig::parse(&bytes).is_err());
        }
    }
}
