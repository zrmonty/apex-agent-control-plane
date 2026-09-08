//! Reconstruct current protected data from the immutable installed binding.
//! The local snapshot below is pure catalog input, never online operation authority.
use super::super::{guard_stage, metadata::strict::Object, network_owner::topology::Topology};
use super::*;
use sha2::{Digest, Sha256};

pub(in crate::execution) fn check(
    staging: &crate::secrets::StagingOwner,
    installation: &str,
    i: &Installed,
    m: &owner::Metadata,
    checkpoint: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    checkpoint()?;
    m.current()?;
    let now = m.policy.check_current().map_err(|_| ERROR)?;
    let Object(configuration): Object<proto::RuntimeConfiguration> =
        serde_json::from_str(&i.configuration_json).map_err(|_| ERROR)?;
    let tools =
        super::super::engine::inspect::json::Json::bounded(i.tools_json.as_bytes(), 262_144)?;
    let host = tools.0["host_policy_version"].as_str().ok_or(ERROR)?;
    let bindings = tools.0["deployment_bindings_version"]
        .as_str()
        .ok_or(ERROR)?;
    let data = proto::RuntimeAuthoritySnapshot {
        installation_id: installation.into(),
        target: i.original.target.clone(),
        config_hash: i.original.config_hash.clone(),
        host_policy_version: host.into(),
        checked_at_unix_us: now,
        ..Default::default()
    };
    let launch = m
        .catalog
        .prepare_data(&data, &configuration, bindings, &i.instance)
        .map_err(|_| ERROR)?;
    let catalogs = m.execution.as_ref().ok_or(ERROR)?;
    let selected = catalogs.select(&data, bindings, &configuration, &launch)?;
    if !selected.registration_required
        || launch.launch_json() != i.launch_json.as_bytes()
        || launch.configuration_json() != i.configuration_json.as_bytes()
        || selected.authority_json != i.authority_json.as_bytes()
        || selected.tools_json != i.tools_json.as_bytes()
    {
        return Err(ERROR);
    }
    let signing = catalogs
        .images
        .select(launch.image_catalog_id(), &launch.context().image_ref)
        .map_err(|_| ERROR)?;
    let publication = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(&(
                launch.materials(),
                &selected.tools,
                launch.catalog_version(),
                signing.catalog_id,
                signing.certificate_identity,
                signing.certificate_oidc_issuer,
            ))
            .map_err(|_| ERROR)?
        )
    );
    if publication != i.publication_hash {
        return Err(ERROR);
    }
    let guard = i.guard_stage.as_ref().ok_or(ERROR)?;
    let network = m.network.as_ref().ok_or(ERROR)?;
    let fresh = Topology::new(network, installation, i, m.digest(), now)?;
    if !guard.topology.0.topology.0.matches_current(&fresh)? {
        return Err(ERROR);
    }
    let produced = guard_stage::produce(guard_stage::Inputs {
        installation,
        installed: i,
        launch: &launch,
        selected: &selected,
        catalog: network,
        images: &catalogs.images,
        source_digest: m.digest(),
        observed: &guard.topology.0,
        now,
    })?;
    if produced.bytes != guard.config_json.as_bytes() {
        return Err(ERROR);
    }
    stages(staging, i, &launch, &selected, checkpoint)?;
    m.current()?;
    checkpoint()
}
