use super::{ERROR, GuardStage};
use crate::{
    execution::{
        guard_stage,
        metadata::Selected,
        network, network_owner,
        pool::{Context, Job},
        provision::{self, DORMANT},
        record::{Installed, Record},
    },
    launch::PreparedLaunch,
    owner,
};
use std::sync::Arc;

pub(in crate::execution) fn run(
    ctx: &Context,
    job: &Job,
    metadata: &Arc<owner::Metadata>,
    record: &mut Record,
    launch: &PreparedLaunch,
    selected: &Selected,
) -> Result<(), &'static str> {
    let catalog = metadata.network.as_ref().ok_or(DORMANT)?;
    let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
    let i = record.installed.as_mut().ok_or(ERROR)?;
    network::prepare(catalog, &ctx.installation, i, now.checked_at_unix_us)?;
    let binding = ctx
        .resources
        .journal
        .reserve_network(catalog, &ctx.installation, i)?;
    provision::checkpoint(ctx, job, Some(metadata))?;
    if i.network.as_ref().is_some_and(|old| old != &binding) {
        return Err(ERROR);
    }
    i.network = Some(binding);
    ctx.resources.journal.save(record)?;
    provision::checkpoint(ctx, job, Some(metadata))?;
    let i = record.installed.as_ref().ok_or(ERROR)?;
    network_owner::prepare_empty(ctx, job, metadata, i)?;
    let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
    let frozen = fresh(ctx, metadata, i, launch, selected, now.checked_at_unix_us)?;
    if let Some(old) = &i.guard_stage {
        old.matches(&frozen)?;
    }
    // Required even for recovery. Historical image metadata is not a current permit.
    let images = &metadata.execution.as_ref().ok_or(ERROR)?.images;
    provision::checkpoint(ctx, job, Some(metadata))?;
    let verified = ctx
        .resources
        .signature
        .verify(
            images,
            &frozen.image_catalog_id,
            &frozen.image_ref,
            provision::budget(job)?,
            &job.cancelled,
        )
        .map_err(|_| "RUNTIME_SIGNATURE_REFUSED")?;
    if verified.image_ref() != frozen.image_ref {
        return Err("RUNTIME_SIGNATURE_REFUSED");
    }
    let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
    frozen.matches(&fresh(
        ctx,
        metadata,
        i,
        launch,
        selected,
        now.checked_at_unix_us,
    )?)?;
    // Reinspect the actual empty native network after potentially slow signature IO.
    network_owner::prepare_empty(ctx, job, metadata, i)?;
    let original = i.clone();
    let expected = frozen.clone();
    let mut check = || {
        let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
        expected.matches(&fresh(
            ctx,
            metadata,
            &original,
            launch,
            selected,
            now.checked_at_unix_us,
        )?)?;
        if *ctx.shutdown.borrow() || !Arc::ptr_eq(metadata, &owner::snapshot(&ctx.shared)?) {
            return Err(owner::UNAVAILABLE);
        }
        provision::deadline(job)?;
        Ok(())
    };
    super::stage(
        &ctx.resources.journal,
        &ctx.resources.staging,
        record,
        frozen,
        &mut check,
    )
}

fn fresh(
    ctx: &Context,
    metadata: &Arc<owner::Metadata>,
    i: &Installed,
    launch: &PreparedLaunch,
    selected: &Selected,
    now: u64,
) -> Result<GuardStage, &'static str> {
    let catalog = metadata.network.as_ref().ok_or(DORMANT)?;
    let images = &metadata.execution.as_ref().ok_or(ERROR)?.images;
    let history = ctx.resources.journal.topology_history(&ctx.installation)?;
    let observed = history.get(&i.instance).ok_or(DORMANT)?;
    let data = guard_stage::produce(guard_stage::Inputs {
        installation: &ctx.installation,
        installed: i,
        launch,
        selected,
        catalog,
        images,
        source_digest: metadata.digest(),
        observed,
        now,
    })
    .map_err(|_| DORMANT)?;
    let image = images
        .select(&data.image_catalog_id, &data.image_ref)
        .map_err(|_| ERROR)?;
    GuardStage::freeze(data, image, observed)
}
