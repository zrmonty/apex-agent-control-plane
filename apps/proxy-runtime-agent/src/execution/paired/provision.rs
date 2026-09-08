use super::{ERROR, Pair};
use crate::{
    execution::{
        guard_stage,
        metadata::Selected,
        pool::{Context, Job},
        provision,
        record::{Installed, Record},
    },
    launch::PreparedLaunch,
    owner,
};
use std::{
    sync::{Arc, TryLockError},
    time::Duration,
};

pub(in crate::execution) fn run(
    ctx: &Context,
    job: &Job,
    metadata: &Arc<owner::Metadata>,
    r: &mut Record,
    launch: &PreparedLaunch,
    selected: &Selected,
) -> Result<(), &'static str> {
    let i = r.installed.as_ref().ok_or(ERROR)?;
    let gateway = i.gateway_stage.as_ref().ok_or(ERROR)?;
    let guard = i.guard_stage.as_ref().ok_or(ERROR)?;
    let images = &metadata.execution.as_ref().ok_or(ERROR)?.images;
    let mut verified = Vec::with_capacity(2);
    for (catalog, reference) in [
        (&gateway.image_catalog_id, &gateway.image_ref),
        (&guard.image_catalog_id, &guard.image_ref),
    ] {
        provision::checkpoint(ctx, job, Some(metadata))?;
        verified.push(
            ctx.resources
                .signature
                .verify(
                    images,
                    catalog,
                    reference,
                    provision::budget(job)?,
                    &job.cancelled,
                )
                .map_err(|_| "RUNTIME_SIGNATURE_REFUSED")?,
        );
    }
    let mut inspected = Vec::with_capacity(2);
    for image in &verified {
        recheck(ctx, job, metadata, i, launch, selected)?;
        if i.paired_containers.is_none() {
            let mut check = || recheck(ctx, job, metadata, i, launch, selected);
            let deadline = || provision::deadline(job);
            let mut gate = super::transition::Gate {
                check: &mut check,
                deadline: &deadline,
                attempted: false,
            };
            ctx.resources
                .engine
                .pair_pull(image, &mut gate, &job.cancelled)?;
        }
        provision::checkpoint(ctx, job, Some(metadata))?;
        inspected.push(ctx.resources.engine.image(
            image.image_ref(),
            provision::deadline(job)?,
            &job.cancelled,
        )?);
    }
    let guard = inspected.pop().ok_or(ERROR)?;
    let gateway = inspected.pop().ok_or(ERROR)?;
    let fresh = Pair::new(i, gateway, guard)?;
    fresh.validate(&ctx.installation, i)?;
    if let Some(old) = &i.paired_containers {
        old.validate(&ctx.installation, i)?;
        if old.binding_hash != fresh.binding_hash {
            return Err(ERROR);
        }
    }
    // Serialize all paired mutations with the existing installation network owner.
    let _effect = loop {
        provision::checkpoint(ctx, job, Some(metadata))?;
        match ctx.resources.network_effect.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(_)) => return Err(ERROR),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(2)),
        }
    };
    recheck(ctx, job, metadata, i, launch, selected)?;
    if i.paired_containers.is_none() {
        r.installed.as_mut().ok_or(ERROR)?.paired_containers = Some(fresh);
        ctx.resources.journal.save(r)?;
    }
    let sealed = r.installed.as_ref().ok_or(ERROR)?.clone();
    super::transition::finish(
        &ctx.resources.journal,
        &ctx.resources.engine,
        r,
        &mut || recheck(ctx, job, metadata, &sealed, launch, selected),
        &|| provision::deadline(job),
        &job.cancelled,
    )?;
    // The sealed pair has its own proof and gateway image identity. Register
    // through the existing pinned Agent callback BEFORE either process starts;
    // the gateway's first outbound renewal requires this durable identity.
    let installed = r.installed.as_ref().ok_or(ERROR)?;
    super::registration::before_start(
        &ctx.installation,
        installed,
        selected.registration_required,
        &mut || recheck(ctx, job, metadata, installed, launch, selected),
        &mut |attestation| {
            ctx.runtime
                .block_on(ctx.authority.register(
                    &job.request,
                    &metadata.policy,
                    provision::operation(job)?,
                    attestation,
                    provision::budget(job)?,
                ))
                .map(|_| ())
                .map_err(|_| "RUNTIME_REGISTRATION_REFUSED")
        },
    )?;
    super::start::run(
        &ctx.resources.journal,
        &ctx.resources.engine,
        r,
        &mut || {
            // A prior image ID or journal observation never substitutes for the
            // actual verifier under the current protected signature policy.
            let i = &sealed;
            for stage in [
                i.gateway_stage
                    .as_ref()
                    .map(|g| (&g.image_catalog_id, &g.image_ref)),
                i.guard_stage
                    .as_ref()
                    .map(|g| (&g.image_catalog_id, &g.image_ref)),
            ] {
                let (catalog, reference) = stage.ok_or(ERROR)?;
                provision::checkpoint(ctx, job, Some(metadata))?;
                ctx.resources
                    .signature
                    .verify(
                        images,
                        catalog,
                        reference,
                        provision::budget(job)?,
                        &job.cancelled,
                    )
                    .map_err(|_| "RUNTIME_SIGNATURE_REFUSED")?;
            }
            recheck(ctx, job, metadata, &sealed, launch, selected)
        },
        &|| provision::deadline(job),
        &job.cancelled,
    )
}

fn recheck(
    ctx: &Context,
    job: &Job,
    metadata: &Arc<owner::Metadata>,
    i: &Installed,
    launch: &PreparedLaunch,
    selected: &Selected,
) -> Result<(), &'static str> {
    let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
    let catalogs = metadata.execution.as_ref().ok_or(ERROR)?;
    catalogs.current(now.checked_at_unix_us)?;
    metadata.current()?;
    let g = i.guard_stage.as_ref().ok_or(ERROR)?;
    let gateway = i.gateway_stage.as_ref().ok_or(ERROR)?;
    let data = guard_stage::produce(guard_stage::Inputs {
        installation: &ctx.installation,
        installed: i,
        launch,
        selected,
        catalog: metadata.network.as_ref().ok_or(ERROR)?,
        images: &catalogs.images,
        source_digest: metadata.digest(),
        observed: &g.topology.0,
        now: now.checked_at_unix_us,
    })?;
    if data.bytes != g.config_json.as_bytes() {
        return Err(ERROR);
    }
    let mut current = || provision::checkpoint(ctx, job, Some(metadata)).map(|_| ());
    ctx.resources
        .staging
        .guard(
            &i.instance,
            g.config_json.as_bytes(),
            true,
            g.sealed_identity.as_ref().map(|v| &v.0),
            &g.root_identity.as_ref().ok_or(ERROR)?.0,
            &mut current,
        )
        .map_err(|_| ERROR)?;
    let material = ctx
        .resources
        .staging
        .gateway_material(launch, selected, &mut current)
        .map_err(|_| ERROR)?;
    if gateway.source_identity.as_ref() != Some(&material.source_identity().map_err(|_| ERROR)?) {
        return Err(ERROR);
    }
    ctx.resources
        .staging
        .gateway(
            &material,
            crate::secrets::GatewayExpected {
                instance: &i.instance,
                root: &gateway.root.0,
                files: &gateway.files,
                identity: Some(&gateway.identity.as_ref().ok_or(ERROR)?.0),
            },
            &mut current,
            &mut |_| Err(ERROR),
        )
        .map_err(|_| ERROR)?;
    ctx.resources
        .staging
        .gateway_recheck(
            &i.instance,
            &gateway.root.0,
            &gateway.identity.as_ref().ok_or(ERROR)?.0,
            &material,
        )
        .map_err(|_| ERROR)?;
    current()?;
    provision::deadline(job)?;
    Ok(())
}
