//! Private data producer. Output never establishes a stage or effect permission.
use super::{
    engine::inspect::json::Json,
    metadata::strict::Object,
    network_owner::topology::{Phase, Topology},
};
use super::{metadata::Selected, network_owner::topology::Document, record::Installed};
use crate::proto;
use crate::{image_catalog::ImageCatalog, launch::PreparedLaunch, network_catalog::NetworkCatalog};
use std::collections::BTreeMap;
mod frozen;
mod routes;
mod serialize;
pub(super) use frozen::reproduce;

const ERROR: &str = "RUNTIME_GUARD_STAGE_REFUSED";
pub(super) struct Inputs<'a> {
    pub installation: &'a str,
    pub installed: &'a Installed,
    pub launch: &'a PreparedLaunch,
    pub selected: &'a Selected,
    pub catalog: &'a NetworkCatalog,
    pub images: &'a ImageCatalog,
    pub source_digest: String,
    pub observed: &'a Document,
    pub now: u64,
}
#[derive(Debug, serde::Serialize)]
pub(super) struct Data {
    pub bytes: Vec<u8>,
    pub files: BTreeMap<String, String>,
    pub manifest: String,
    pub environment: BTreeMap<String, String>,
    pub image_catalog_id: String,
    pub image_ref: String,
}
pub(super) fn produce(input: Inputs<'_>) -> Result<Data, &'static str> {
    let Inputs {
        installation,
        installed: i,
        launch,
        selected,
        catalog,
        images,
        source_digest,
        observed,
        now,
    } = input;
    // Charge original bytes before decoding, comparing, hashing, or traversing them.
    for (bytes, limit) in [
        (i.launch_json.as_bytes(), 16384),
        (i.configuration_json.as_bytes(), 262144),
        (i.authority_json.as_bytes(), 16384),
        (i.tools_json.as_bytes(), 262144),
        (observed.topology.0.selected_catalog_json.as_bytes(), 262144),
        (observed.topology.0.launch_json.as_bytes(), 16384),
    ] {
        if bytes.is_empty() || bytes.len() > limit {
            return Err(ERROR);
        }
    }
    if i.launch_json.as_bytes() != launch.launch_json()
        || i.configuration_json.as_bytes() != launch.configuration_json()
        || i.authority_json.as_bytes() != selected.authority_json
        || i.tools_json.as_bytes() != selected.tools_json
        || observed.phase != Phase::Observed
        || observed.topology.0.installation != installation
        || i.network.as_ref() != Some(&observed.topology.0.binding.0)
    {
        return Err(ERROR);
    }
    observed.validate()?;
    observed.topology.0.validate(i)?;
    let fresh = Topology::new(catalog, installation, i, source_digest, now)?;
    if !observed.topology.0.matches_current(&fresh)? {
        return Err(ERROR);
    }
    // Decode ORIGINAL generated configuration, never a normalized Value substitute.
    let Object(configuration): Object<proto::RuntimeConfiguration> =
        serde_json::from_slice(i.configuration_json.as_bytes()).map_err(|_| ERROR)?;
    if serde_json::to_vec(&configuration).map_err(|_| ERROR)? != launch.configuration_json()
        || crate::check_target_configuration_binding(
            i.original.target.as_ref().ok_or(ERROR)?,
            &configuration,
        )
        .is_err()
        || configuration.config_hash != i.original.config_hash
        || crate::runtime_manifest_hash(&configuration).map_err(|_| ERROR)?
            != configuration.runtime_manifest_hash
    {
        return Err(ERROR);
    }
    let authority = Json::bounded(&selected.authority_json, 16384).map_err(|_| ERROR)?;
    let p = &authority.0["profile"];
    let policy = &p["managed"]["network_policy"];
    let profile = catalog.select(
        installation,
        p["host_policy_version"].as_str().ok_or(ERROR)?,
        policy["reference"].as_str().ok_or(ERROR)?,
        policy["version"].as_str().ok_or(ERROR)?,
        now,
    )?;
    let image = images
        .select(profile.guard_image_catalog_id(), profile.guard_image_ref())
        .map_err(|_| ERROR)?;
    let routes = routes::derive(&configuration.network_grants, p, profile, catalog)?;
    // selected_snapshot uses exact u64 serde numbers. Extract CURRENT interval,
    // then stringify integers directly; historical topology clocks stay immutable.
    let current: serde_json::Value =
        serde_json::from_str(&fresh.selected_catalog_json).map_err(|_| ERROR)?;
    let from = current["valid_from_unix_us"].as_u64().ok_or(ERROR)?;
    let until = current["expires_at_unix_us"].as_u64().ok_or(ERROR)?;
    serialize::data(
        installation,
        i,
        observed,
        catalog,
        (from, until),
        routes,
        image,
    )
}
#[cfg(test)]
mod tests;
