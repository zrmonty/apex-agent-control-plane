//! Read-only installed confinement, with no lifecycle or operation authority.
use super::record::Installed;
use super::{
    engine::{Engine, paired::Role},
    journal::Journal,
    pool::Context,
};
use crate::proto;
use crate::{
    owner,
    service::network_readiness::{self as wire, BUDGET},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
pub(super) mod current;
pub(super) const ERROR: &str = "RUNTIME_NETWORK_INSPECTION_REFUSED";

pub(super) fn inspect(
    ctx: &Context,
    request: &tonic::Request<proto::RuntimeNetworkInspectionRequest>,
    started: Instant,
    cancel: &AtomicBool,
    metadata: &Arc<owner::Metadata>,
) -> Result<proto::RuntimeNetworkInspectionResponse, &'static str> {
    let mut check = || {
        deadline(started, cancel)?;
        if *ctx.shutdown.borrow() || !Arc::ptr_eq(metadata, &owner::snapshot(&ctx.shared)?) {
            return Err(ERROR);
        }
        wire::authorize(request, &ctx.installation, metadata).map_err(|_| ERROR)?;
        Ok(())
    };
    // The original incoming TLS request is checked before journal, staging or engine IO.
    check()?;
    let b = request.get_ref().binding.as_ref().ok_or(ERROR)?;
    let t = b.target.as_ref().ok_or(ERROR)?;
    let r = ctx
        .resources
        .journal
        .load(&ctx.installation, t)?
        .ok_or(ERROR)?;
    let i = r.installed.as_ref().ok_or(ERROR)?;
    if r.installation != ctx.installation
        || r.original != i.original
        || r.instance != i.instance
        || i.mount_profile != ctx.resources.engine.mount_profile()
    {
        return Err(ERROR);
    }
    binding(&ctx.installation, i, b)?;
    current::check(
        &ctx.resources.staging,
        &ctx.installation,
        i,
        metadata,
        &mut check,
    )?;
    let (gateway, guard) = observe(
        &ctx.resources.journal,
        &ctx.resources.engine,
        &ctx.installation,
        i,
        started,
        cancel,
        &mut check,
    )?;
    current::check(
        &ctx.resources.staging,
        &ctx.installation,
        i,
        metadata,
        &mut check,
    )?;
    // Journal replacement is also refused, even if it preserves just the caller hashes.
    let after = ctx
        .resources
        .journal
        .load(&ctx.installation, t)?
        .ok_or(ERROR)?;
    if serde_json::to_vec(&r).map_err(|_| ERROR)?
        != serde_json::to_vec(&after).map_err(|_| ERROR)?
    {
        return Err(ERROR);
    }
    check()?;
    Ok(proto::RuntimeNetworkInspectionResponse {
        schema_version: 1,
        binding: Some(b.clone()),
        nonce: request.get_ref().nonce.clone(),
        network_binding_sha256: i.network.as_ref().ok_or(ERROR)?.binding_hash.clone(),
        gateway_process_sha256: gateway,
        guard_process_sha256: guard,
        // A duration from the receiver's ORIGINAL start, never a new expiry timestamp.
        valid_for_us: 10_000_000,
        confined: true,
    })
}

fn deadline(started: Instant, cancel: &AtomicBool) -> Result<Instant, &'static str> {
    let until = started + BUDGET;
    if cancel.load(Ordering::Acquire) || Instant::now() >= until {
        return Err(ERROR);
    }
    Ok(until)
}

pub(in crate::execution) fn observe(
    journal: &Journal,
    engine: &Engine,
    installation: &str,
    i: &Installed,
    started: Instant,
    cancel: &AtomicBool,
    check: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(String, String), &'static str> {
    check()?;
    let p = i.paired_containers.as_ref().ok_or(ERROR)?;
    p.validate(installation, i)?;
    let saved = p
        .start
        .as_ref()
        .filter(|s| s.phase == super::paired::start::Step::Running)
        .ok_or(ERROR)?;
    let g = i.guard_stage.as_ref().ok_or(ERROR)?;
    let t = &g.topology.0.topology.0;
    let history = journal.topology_history(installation)?;
    let own = history.get(&i.instance).ok_or(ERROR)?;
    if serde_json::to_vec(own).map_err(|_| ERROR)?
        != serde_json::to_vec(&g.topology.0).map_err(|_| ERROR)?
    {
        return Err(ERROR);
    }
    let outer =
        engine.pair_memberships(journal, t, &history, deadline(started, cancel)?, cancel)?;
    check()?;
    let guard = engine.pair_running(
        installation,
        i,
        Role::Guard,
        &outer,
        deadline(started, cancel)?,
        cancel,
    )?;
    check()?;
    let gateway = engine.pair_running(
        installation,
        i,
        Role::Gateway,
        &outer,
        deadline(started, cancel)?,
        cancel,
    )?;
    if saved.guard.as_ref() != Some(&guard) || saved.gateway.as_ref() != Some(&gateway) {
        return Err(ERROR);
    }
    check()?;
    if engine.pair_memberships(journal, t, &history, deadline(started, cancel)?, cancel)? != outer {
        return Err(ERROR);
    }
    deadline(started, cancel)?;
    check()?;
    Ok((gateway.process_hash, guard.process_hash))
}

pub(in crate::execution) fn binding(
    installation: &str,
    i: &Installed,
    expected: &proto::ManagedDeploymentBinding,
) -> Result<(), &'static str> {
    let p = i.paired_containers.as_ref().ok_or(ERROR)?;
    p.validate(installation, i)?;
    if p.phase != super::paired::Phase::Verified
        || p.start
            .as_ref()
            .is_none_or(|s| s.phase != super::paired::start::Step::Running)
    {
        return Err(ERROR);
    }
    let a = i.attestation(installation)?.ok_or(ERROR)?;
    let l = a.launch.as_ref().ok_or(ERROR)?;
    if expected.installation_id != installation
        || expected.target != i.original.target
        || expected.process_instance_id != i.instance
        || expected.config_hash != i.original.config_hash
        || expected.launch_context_hash != l.launch_context_hash
    {
        return Err(ERROR);
    }
    Ok(())
}

pub(in crate::execution) fn stages(
    staging: &crate::secrets::StagingOwner,
    i: &Installed,
    launch: &crate::launch::PreparedLaunch,
    selected: &super::metadata::Selected,
    check: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    check()?;
    let guard = i.guard_stage.as_ref().ok_or(ERROR)?;
    let gateway = i.gateway_stage.as_ref().ok_or(ERROR)?;
    // Explicit recovery and identities are mandatory; absent stages cannot be created.
    let guard_identity = &guard.sealed_identity.as_ref().ok_or(ERROR)?.0;
    let gateway_identity = &gateway.identity.as_ref().ok_or(ERROR)?.0;
    staging
        .guard(
            &i.instance,
            guard.config_json.as_bytes(),
            true,
            Some(guard_identity),
            &guard.root_identity.as_ref().ok_or(ERROR)?.0,
            check,
        )
        .map_err(|_| ERROR)?;
    let material = staging
        .gateway_material(launch, selected, check)
        .map_err(|_| ERROR)?;
    if gateway.source_identity.as_ref() != Some(&material.source_identity().map_err(|_| ERROR)?) {
        return Err(ERROR);
    }
    staging
        .gateway(
            &material,
            crate::secrets::GatewayExpected {
                instance: &i.instance,
                root: &gateway.root.0,
                files: &gateway.files,
                identity: Some(gateway_identity),
            },
            check,
            &mut |_| Err(ERROR),
        )
        .map_err(|_| ERROR)?;
    staging
        .gateway_recheck(&i.instance, &gateway.root.0, gateway_identity, &material)
        .map_err(|_| ERROR)?;
    check()
}
