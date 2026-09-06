use super::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// Selection/current publication and filesystem sealing precede this boundary.
// This is deterministic metadata derivation, never a grant or a fresh file read.
pub(super) fn environment(
    installation: &str,
    installed: &Installed,
) -> Result<Vec<String>, &'static str> {
    let mut env: Vec<String> = ENV.iter().map(|value| (*value).to_owned()).collect();
    let authority = inspect::Json::bounded(installed.authority_json.as_bytes(), 16_384)?;
    let profile = authority.0["profile"].as_object().ok_or(ERROR)?;
    match (authority.0["schema_version"].as_u64(), profile.get("mode")) {
        (Some(1), None) => return Ok(env),
        (Some(2), Some(mode)) if mode.as_str() == Some("managed_preparation") => return Ok(env),
        (Some(3), Some(mode)) if mode.as_str() == Some("managed_ingress") => {}
        _ => return Err(ERROR),
    }
    if !shapes::uuid_v7(installation)
        || profile.get("installation_id").and_then(|v| v.as_str()) != Some(installation)
        || installed.instance_proof_version != Some(1)
        || installed.configuration_json.len() > 262_144
        || installed.files.len() > 50
        || installed.files.values().any(|hash| !shapes::hex_hash(hash))
    {
        return Err(ERROR);
    }
    let configuration: proto::RuntimeConfiguration =
        serde_json::from_str(&installed.configuration_json).map_err(|_| ERROR)?;
    if configuration.secret_refs.len() > 32 {
        return Err(ERROR);
    }
    let refs: BTreeSet<_> = configuration.secret_refs.iter().collect();
    if refs.len() != configuration.secret_refs.len() || refs.iter().any(|r| !reference(r)) {
        return Err(ERROR);
    }
    let mut names: BTreeSet<String> = ["instance-proof".into()].into_iter().collect();
    for (name, value, cap) in [
        (
            "runtime-revision.json",
            &installed.configuration_json,
            262_144,
        ),
        ("launch-context.json", &installed.launch_json, 16_384),
        ("authority-profile.json", &installed.authority_json, 16_384),
        ("tool-bindings.json", &installed.tools_json, 65_536),
    ] {
        if value.is_empty()
            || value.len() > cap
            || installed.files.get(name) != Some(&digest(value.as_bytes()))
        {
            return Err(ERROR);
        }
        names.insert(name.into());
    }
    for number in 1..=13 {
        let role = proto::RuntimeMaterialRole::try_from(number).map_err(|_| ERROR)?;
        let name = role
            .as_str_name()
            .strip_prefix("RUNTIME_MATERIAL_ROLE_")
            .ok_or(ERROR)?
            .to_ascii_lowercase()
            .replace('_', "-");
        if !names.insert(name) {
            return Err(ERROR);
        }
    }
    for reference in &refs {
        names.insert(format!("tool-{}", digest(reference.as_bytes())));
    }
    if names != installed.files.keys().cloned().collect() {
        return Err(ERROR);
    }
    env.extend([
        "APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v1".into(),
        format!("APEX_INSTALLATION_ID={installation}"),
        format!(
            "APEX_STAGE_MANIFEST_SHA256={}",
            digest(&serde_json::to_vec(&installed.files).map_err(|_| ERROR)?)
        ),
        format!(
            "APEX_TOOL_SECRET_REFERENCES={}",
            serde_json::to_string(&refs).map_err(|_| ERROR)?
        ),
    ]);
    Ok(env)
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn reference(value: &str) -> bool {
    value.len() <= 256
        && value.strip_prefix("secret://").is_some_and(|tail| {
            tail.as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
                && tail
                    .split('/')
                    .all(|part| part != "." && shapes::scope(part))
        })
}
#[cfg(test)]
mod tests;
