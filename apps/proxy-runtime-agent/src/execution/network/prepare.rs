use super::{ERROR, Installed};
use crate::{
    execution::{engine::inspect::json::Json, record::Phase},
    network_catalog::NetworkCatalog,
    proto,
};
pub(in crate::execution) fn prepare(
    catalog: &NetworkCatalog,
    installation: &str,
    i: &Installed,
    now: u64,
) -> Result<(), &'static str> {
    if i.phase != Phase::Intent
        || !i.files.is_empty()
        || !i.image_id.is_empty()
        || !i.container_id.is_empty()
        || i.instance_proof_version != Some(1)
    {
        return Err(ERROR);
    }
    if let Some(binding) = &i.network {
        binding.validate(installation, i)?;
    }
    let authority = Json::bounded(i.authority_json.as_bytes(), 16_384).map_err(|_| ERROR)?;
    let p = &authority.0["profile"];
    let launch: proto::RuntimeLaunchContext =
        serde_json::from_str(&i.launch_json).map_err(|_| ERROR)?;
    let target = i.original.target.as_ref().ok_or(ERROR)?;
    if authority.0["schema_version"].as_u64() != Some(3)
        || p["mode"].as_str() != Some("managed_ingress")
        || p["installation_id"].as_str() != Some(installation)
        || p["workspace_id"].as_str() != Some(&target.workspace_id)
        || p["namespace_id"].as_str() != Some(&target.namespace_id)
        || p["proxy_id"].as_str() != Some(&target.proxy_id)
        || p["reference"].as_str() != Some(&launch.authority_profile_ref)
        || p["version"].as_str() != Some(&launch.authority_profile_version)
        || launch.process_instance_id != i.instance
        || launch.target.as_ref() != Some(target)
        || launch.config_hash != i.original.config_hash
    {
        return Err(ERROR);
    }
    let policy = &p["managed"]["network_policy"];
    let profile = catalog.select(
        installation,
        p["host_policy_version"].as_str().ok_or(ERROR)?,
        policy["reference"].as_str().ok_or(ERROR)?,
        policy["version"].as_str().ok_or(ERROR)?,
        now,
    )?;
    for purpose in ["governance", "evidence"] {
        let endpoint = p[purpose]["endpoint"].as_str().ok_or(ERROR)?;
        let url = url::Url::parse(endpoint).map_err(|_| ERROR)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !profile.grants().any(|g| {
                g.purpose() == purpose
                    && Some(g.host()) == url.host_str()
                    && Some(g.port()) == url.port_or_known_default()
            })
        {
            return Err(ERROR);
        }
    }
    Ok(())
}
