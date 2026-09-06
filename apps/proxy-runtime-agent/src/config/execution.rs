use serde::{Deserialize, Deserializer};
use std::path::PathBuf;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionConfig {
    pub journal_root: PathBuf,
    pub staging_root: PathBuf,
    pub material_root: PathBuf,
    pub docker_executable: PathBuf,
    pub docker_socket: PathBuf,
    pub docker_config_root: PathBuf,
    pub cosign_executable: PathBuf,
    pub cosign_cache_root: PathBuf,
    #[serde(default, deserialize_with = "network_profile")]
    pub network_profile: Option<NetworkProfile>,
}
#[derive(Clone, Copy)]
pub(crate) enum NetworkProfile {
    IsolatedBridgeV1,
}
fn network_profile<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NetworkProfile>, D::Error> {
    match String::deserialize(d)?.as_str() {
        "isolated-bridge-v1" => Ok(Some(NetworkProfile::IsolatedBridgeV1)),
        _ => Err(serde::de::Error::custom("RUNTIME_EXECUTION_CONFIG_INVALID")),
    }
}
pub(super) fn present<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<ExecutionConfig>, D::Error> {
    struct Object;
    impl<'de> serde::de::Visitor<'de> for Object {
        type Value = ExecutionConfig;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an execution object")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            ExecutionConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    d.deserialize_map(Object).map(Some)
}
impl ExecutionConfig {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        let roots = [
            &self.journal_root,
            &self.staging_root,
            &self.material_root,
            &self.docker_config_root,
            &self.cosign_cache_root,
        ];
        for path in roots.into_iter().chain([
            &self.docker_executable,
            &self.docker_socket,
            &self.cosign_executable,
        ]) {
            let s = path.to_str().ok_or("RUNTIME_EXECUTION_CONFIG_INVALID")?;
            if !s.starts_with('/')
                || s.len() > 2048
                || s.len() < 2
                || s[1..]
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                || s.bytes()
                    .any(|b| !b.is_ascii_graphic() || matches!(b, b',' | b'\\'))
            {
                return Err("RUNTIME_EXECUTION_CONFIG_INVALID");
            }
        }
        for (i, root) in roots.iter().enumerate() {
            if roots[..i]
                .iter()
                .any(|p| root.starts_with(p) || p.starts_with(root))
            {
                return Err("RUNTIME_EXECUTION_CONFIG_INVALID");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::json!({"journal_root":"/j","staging_root":"/s","material_root":"/m",
            "docker_executable":"/bin/docker","docker_socket":"/run/docker.sock","docker_config_root":"/d",
            "cosign_executable":"/bin/cosign","cosign_cache_root":"/c"})
    }
    #[test]
    fn protected_network_opt_in_accepts_only_exact_string_or_absence() {
        let mut v = fixture();
        assert!(
            serde_json::from_value::<ExecutionConfig>(v.clone())
                .unwrap()
                .network_profile
                .is_none()
        );
        v["network_profile"] = "isolated-bridge-v1".into();
        assert!(
            serde_json::from_value::<ExecutionConfig>(v.clone())
                .unwrap()
                .network_profile
                .is_some()
        );
        for bad in [
            serde_json::Value::Null,
            serde_json::json!({"isolated-bridge-v1":null}),
            serde_json::json!("host"),
            serde_json::json!(""),
            serde_json::json!(1),
        ] {
            v["network_profile"] = bad;
            assert!(serde_json::from_value::<ExecutionConfig>(v.clone()).is_err());
        }
    }
}
