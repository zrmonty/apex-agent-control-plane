use apex_control_plane_api::{
    ExactScope, OperatorCaller,
    browser::{edge::BrowserConfig, security::ConfiguredOrigin},
};
use serde::Deserialize;
use std::{io, path::PathBuf, time::Duration};

pub(super) const MAX_CONFIG_BYTES: usize = 32768;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Settings {
    pub version: u8,
    pub public_origin: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    pub session_keys: Vec<KeyFile>,
    pub management: ManagementIdentity,
    pub session_max_age_secs: u32,
    pub idle_timeout_secs: u32,
    pub max_in_flight: usize,
    pub request_timeout_secs: u64,
    pub global_scope_catalog: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagementIdentity {
    pub server_name: String,
    pub ca_file: PathBuf,
    pub certificate_file: PathBuf,
    pub key_file: PathBuf,
}
#[derive(Deserialize)]
#[serde(tag = "usage", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum KeyFile {
    Active {
        id: String,
        file: PathBuf,
    },
    Retired {
        id: String,
        file: PathBuf,
        decrypt_until_unix_seconds: i64,
    },
}
impl Settings {
    pub fn parse(
        bytes: &[u8],
        api_audience: &str,
        expected_typ: Option<&str>,
    ) -> Result<Self, io::Error> {
        if bytes.is_empty() || bytes.len() > MAX_CONFIG_BYTES || expected_typ != Some("Bearer") {
            return Err(invalid());
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if value.version != 1
            || api_audience.is_empty()
            || value.client_id == api_audience
            || value.client_id.is_empty()
            || value.client_id.len() > 256
            || value.client_id == "account"
            || !value.client_id.bytes().all(|byte| byte.is_ascii_graphic())
            || !(300..=86400).contains(&value.session_max_age_secs)
            || !(60..=3600).contains(&value.idle_timeout_secs)
            || value.idle_timeout_secs > value.session_max_age_secs
            || !(1..=256).contains(&value.max_in_flight)
            || !(15..=60).contains(&value.request_timeout_secs)
            || value.global_scope_catalog.len() > 256
            || !(1..=4).contains(&value.session_keys.len())
            || value
                .session_keys
                .iter()
                .filter(|key| matches!(key, KeyFile::Active { .. }))
                .count()
                != 1
        {
            return Err(invalid());
        }
        ConfiguredOrigin::parse(&value.public_origin).map_err(|_| invalid())?;
        value.scope_catalog()?;
        let mut ids = std::collections::BTreeSet::new();
        for key in &value.session_keys {
            let (id, file) = match key {
                KeyFile::Active { id, file } => (id, file),
                KeyFile::Retired {
                    id,
                    file,
                    decrypt_until_unix_seconds,
                } => {
                    if *decrypt_until_unix_seconds <= 0 {
                        return Err(invalid());
                    }
                    (id, file)
                }
            };
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                || file.as_os_str().is_empty()
                || !ids.insert(id)
            {
                return Err(invalid());
            }
        }
        Ok(value)
    }
    pub fn edge_config(&self) -> BrowserConfig {
        BrowserConfig {
            session_max_age_secs: self.session_max_age_secs,
            idle_timeout_secs: self.idle_timeout_secs,
            max_in_flight: self.max_in_flight,
            request_timeout: Duration::from_secs(self.request_timeout_secs),
        }
    }
    pub fn scope_catalog(&self) -> Result<Vec<ExactScope>, io::Error> {
        OperatorCaller::scoped(
            "configuration-validation",
            self.global_scope_catalog.clone(),
        )
        .and_then(|caller| caller.scope_choices(&[]))
        .map_err(|_| invalid())
    }
}
pub(super) fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid browser configuration or authentication profile",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> serde_json::Value {
        serde_json::json!({
            "version":1, "public_origin":"https://console.example", "client_id":"apex-browser",
            "client_secret_file":"browser-client-secret", "session_keys":[{"usage":"active","id":"k1","file":"session-key"}],
            "management":{"server_name":"control.example","ca_file":"ca.pem","certificate_file":"browser.pem","key_file":"browser.key"},
            "session_max_age_secs":28800,"idle_timeout_secs":900,"max_in_flight":32,"request_timeout_secs":30,
            "global_scope_catalog":["acme/prod"]
        })
    }
    fn parse(value: serde_json::Value) -> Result<Settings, io::Error> {
        Settings::parse(
            &serde_json::to_vec(&value).unwrap(),
            "apex-control-gateway",
            Some("Bearer"),
        )
    }
    #[test]
    fn explicit_browser_profile_preserves_limits_and_exact_catalog() {
        let settings = parse(valid()).unwrap();
        assert_eq!(
            settings.edge_config().request_timeout,
            Duration::from_secs(30)
        );
        assert_eq!(
            settings.scope_catalog().unwrap(),
            vec![ExactScope {
                workspace_id: "acme".into(),
                namespace_id: "prod".into()
            }]
        );
    }
    #[test]
    fn api_audience_and_bearer_typ_cannot_be_waived_or_confused_with_login() {
        let bytes = serde_json::to_vec(&valid()).unwrap();
        for (audience, typ) in [
            ("apex-browser", Some("Bearer")),
            ("", Some("Bearer")),
            ("api", None),
            ("api", Some("ID")),
            ("api", Some("Refresh")),
        ] {
            assert!(Settings::parse(&bytes, audience, typ).is_err());
        }
    }
    #[test]
    fn config_is_strict_bounded_and_never_carries_inline_secrets_or_arbitrary_targets() {
        for (key, value) in [
            ("version", serde_json::json!(2)),
            ("public_origin", serde_json::json!("http://console.example")),
            ("client_id", serde_json::json!("account")),
            ("client_secret", serde_json::json!("secret-canary")),
            (
                "token_endpoint",
                serde_json::json!("https://attacker.invalid/token"),
            ),
            ("session_max_age_secs", serde_json::json!(86401)),
            ("idle_timeout_secs", serde_json::json!(3601)),
            ("max_in_flight", serde_json::json!(0)),
            ("request_timeout_secs", serde_json::json!(61)),
            ("global_scope_catalog", serde_json::json!(["*"])),
            ("session_keys", serde_json::json!([])),
        ] {
            let mut config = valid();
            config[key] = value;
            assert!(parse(config).is_err(), "{key}");
        }
        let text = serde_json::to_string(&valid()).unwrap();
        let duplicate = format!("{{\"version\":1,{}", &text[1..]);
        assert!(Settings::parse(duplicate.as_bytes(), "api", Some("Bearer")).is_err());
        assert!(Settings::parse(&vec![b' '; MAX_CONFIG_BYTES + 1], "api", Some("Bearer")).is_err());
        let mut config = valid();
        config["management"]["target"] = serde_json::json!("https://attacker.invalid");
        assert!(parse(config).is_err());
    }
}
