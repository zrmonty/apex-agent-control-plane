//! Recompute historical bytes for journal shape/join validation, never authority.
use super::*;
use crate::image_catalog::SelectedImage;

pub(in crate::execution) fn reproduce(
    i: &Installed,
    observed: &Document,
    image: SelectedImage<'_>,
    original: &str,
) -> Result<Data, &'static str> {
    let frozen = Json::bounded(original.as_bytes(), 262_144).map_err(|_| ERROR)?;
    let clock = |name: &str| -> Result<u64, &'static str> {
        frozen.0[name]
            .as_str()
            .ok_or(ERROR)?
            .parse()
            .map_err(|_| ERROR)
    };
    let (from, until) = (clock("not_before_unix_us")?, clock("not_after_unix_us")?);
    if from == 0 || from >= until || until > i64::MAX as u64 {
        return Err(ERROR);
    }
    Json::bounded(i.configuration_json.as_bytes(), 262_144).map_err(|_| ERROR)?;
    let Object(configuration): Object<proto::RuntimeConfiguration> =
        serde_json::from_str(&i.configuration_json).map_err(|_| ERROR)?;
    if serde_json::to_string(&configuration).map_err(|_| ERROR)? != i.configuration_json
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
    let authority = Json::bounded(i.authority_json.as_bytes(), 16_384).map_err(|_| ERROR)?;
    let p = &authority.0["profile"];
    let catalog = observed.topology.0.catalog()?;
    let snapshot: serde_json::Value =
        serde_json::from_str(&observed.topology.0.selected_catalog_json).map_err(|_| ERROR)?;
    let profile = catalog.select(
        &observed.topology.0.installation,
        p["host_policy_version"].as_str().ok_or(ERROR)?,
        p["managed"]["network_policy"]["reference"]
            .as_str()
            .ok_or(ERROR)?,
        p["managed"]["network_policy"]["version"]
            .as_str()
            .ok_or(ERROR)?,
        snapshot["valid_from_unix_us"].as_u64().ok_or(ERROR)?,
    )?;
    if profile.guard_image_catalog_id() != image.catalog_id
        || profile.guard_image_ref() != image.image_ref
    {
        return Err(ERROR);
    }
    let routes = routes::derive(&configuration.network_grants, p, profile, &catalog)?;
    serialize::data(
        &observed.topology.0.installation,
        i,
        observed,
        &catalog,
        (from, until),
        routes,
        image,
    )
}
