use super::{ERROR, GatewayStage};
use crate::{
    execution::{
        metadata::Selected,
        network,
        pool::{Context, Job},
        provision,
    },
    launch::PreparedLaunch,
    owner,
};
use std::sync::Arc;
pub(in crate::execution) fn run(
    ctx: &Context,
    job: &Job,
    metadata: &Arc<owner::Metadata>,
    record: &mut crate::execution::record::Record,
    launch: &PreparedLaunch,
    selected: &Selected,
) -> Result<(), &'static str> {
    let i = record.installed.as_ref().ok_or(ERROR)?;
    let catalogs = metadata.execution.as_ref().ok_or(ERROR)?;
    let signing = catalogs
        .images
        .select(launch.image_catalog_id(), &launch.context().image_ref)
        .map_err(|_| ERROR)?;
    let fresh = GatewayStage::new(
        &ctx.installation,
        i,
        signing,
        network::hash(&(launch.materials(), &selected.tools))?,
        ctx.resources.staging.guard_root().map_err(|_| ERROR)?,
    )?;
    if let Some(old) = &i.gateway_stage {
        old.matches(&fresh)?;
    }
    provision::checkpoint(ctx, job, Some(metadata))?;
    let verified = ctx
        .resources
        .signature
        .verify(
            &catalogs.images,
            &fresh.image_catalog_id,
            &fresh.image_ref,
            provision::budget(job)?,
            &job.cancelled,
        )
        .map_err(|_| "RUNTIME_SIGNATURE_REFUSED")?;
    if verified.image_ref() != fresh.image_ref {
        return Err("RUNTIME_SIGNATURE_REFUSED");
    }
    provision::checkpoint(ctx, job, Some(metadata))?;
    // Repeat the real guard signature/topology/sealed-file checks after the slow
    // gateway verification. A historical guard seal alone grants no authority.
    crate::execution::guard_staging::run(ctx, job, metadata, record, launch, selected)?;
    let original = record.installed.as_ref().ok_or(ERROR)?.clone();
    let guard = original.guard_stage.as_ref().ok_or(ERROR)?;
    let mut check = || {
        let (_, now) = provision::checkpoint(ctx, job, Some(metadata))?;
        catalogs.current(now.checked_at_unix_us)?;
        metadata.current()?;
        let data = crate::execution::guard_stage::produce(crate::execution::guard_stage::Inputs {
            installation: &ctx.installation,
            installed: &original,
            launch,
            selected,
            catalog: metadata.network.as_ref().ok_or(ERROR)?,
            images: &catalogs.images,
            source_digest: metadata.digest(),
            observed: &guard.topology.0,
            now: now.checked_at_unix_us,
        })?;
        if data.bytes != guard.config_json.as_bytes() {
            return Err(ERROR);
        }
        ctx.resources
            .staging
            .guard(
                &original.instance,
                guard.config_json.as_bytes(),
                true,
                guard.sealed_identity.as_ref().map(|v| &v.0),
                &guard.root_identity.as_ref().ok_or(ERROR)?.0,
                &mut || Ok(()),
            )
            .map_err(|_| ERROR)?;
        if *ctx.shutdown.borrow() {
            return Err("RUNTIME_SHUTTING_DOWN");
        }
        // Guard filesystem IO can outlast a metadata refresh as well.
        if !Arc::ptr_eq(metadata, &owner::snapshot(&ctx.shared)?) {
            return Err(owner::UNAVAILABLE);
        }
        provision::deadline(job)?;
        Ok(())
    };
    super::stage(
        &ctx.resources.journal,
        &ctx.resources.staging,
        record,
        fresh,
        launch,
        selected,
        &mut check,
    )
}
