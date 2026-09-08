use super::{
    pool::{Context, JOB_BUDGET, Job},
    record::{Installed, Phase, Record},
};
use crate::{
    authority::{AuthorityOperation, ResolvedDeployment},
    owner, proto,
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
pub(super) const DORMANT: &str = "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE";
const ERROR: &str = "RUNTIME_PROVISIONING_QUARANTINED";
pub(super) fn budget(job: &Job) -> Result<Duration, &'static str> {
    deadline(job)?
        .checked_duration_since(Instant::now())
        .ok_or("RUNTIME_LEASE_EXPIRED")
}
pub(super) fn deadline(job: &Job) -> Result<Instant, &'static str> {
    if job.cancelled.load(Ordering::Acquire) {
        return Err("RUNTIME_CANCELLED");
    }
    let whole = job.started + JOB_BUDGET;
    let deadline = job
        .lease_deadline
        .lock()
        .map_err(|_| ERROR)?
        .map_or(whole, |lease| whole.min(lease));
    if Instant::now() >= deadline {
        return Err("RUNTIME_LEASE_EXPIRED");
    }
    Ok(deadline)
}
pub(super) fn operation(job: &Job) -> Result<AuthorityOperation<'_>, &'static str> {
    let b = job.request.get_ref();
    Ok(AuthorityOperation {
        target: b.target.as_ref().ok_or(ERROR)?,
        operation_id: &b.operation_id,
        command_id: &b.command_id,
        config_hash: &b.config_hash,
    })
}
pub(super) fn checkpoint(
    ctx: &Context,
    job: &Job,
    expected: Option<&Arc<owner::Metadata>>,
) -> Result<(Arc<owner::Metadata>, proto::RuntimeAuthoritySnapshot), &'static str> {
    if *ctx.shutdown.borrow() {
        return Err("RUNTIME_SHUTTING_DOWN");
    }
    // A fresh callback may refresh authority, but never the whole-job clock.
    if job.cancelled.load(Ordering::Acquire) {
        return Err("RUNTIME_CANCELLED");
    }
    let b = JOB_BUDGET
        .checked_sub(job.started.elapsed())
        .ok_or("RUNTIME_DEADLINE")?;
    let metadata = owner::snapshot(&ctx.shared)?;
    if expected.is_some_and(|e| !Arc::ptr_eq(e, &metadata)) {
        return Err(owner::UNAVAILABLE);
    }
    let started = Instant::now();
    let a = ctx
        .runtime
        .block_on(
            ctx.authority
                .check(&job.request, &metadata.policy, operation(job)?, b),
        )
        .map_err(|_| "RUNTIME_AUTHORITY_REFUSED")?;
    crate::service::validation::states(&a).map_err(|_| "RUNTIME_OPERATION_NOT_CURRENT")?;
    let previous = job
        .desired
        .compare_exchange(0, a.desired_state, Ordering::AcqRel, Ordering::Acquire)
        .unwrap_or_else(|n| n);
    if previous != 0 && previous != a.desired_state {
        return Err("RUNTIME_OPERATION_NOT_CURRENT");
    }
    *job.lease_deadline.lock().map_err(|_| ERROR)? = Some(
        started
            .checked_add(Duration::from_micros(
                a.lease_expires_at_unix_us
                    .checked_sub(a.checked_at_unix_us)
                    .ok_or(ERROR)?,
            ))
            .ok_or(ERROR)?,
    );
    if !Arc::ptr_eq(&metadata, &owner::snapshot(&ctx.shared)?)
        || started.elapsed()
            >= Duration::from_micros(
                a.lease_expires_at_unix_us
                    .checked_sub(a.checked_at_unix_us)
                    .ok_or(ERROR)?,
            )
    {
        return Err(owner::UNAVAILABLE);
    }
    budget(job)?;
    // Shutdown may arrive during the blocking authority RPC while its request
    // waiter is still alive, so cancellation alone cannot close this boundary.
    if *ctx.shutdown.borrow() {
        return Err("RUNTIME_SHUTTING_DOWN");
    }
    Ok((metadata, a))
}
fn resolve(
    ctx: &Context,
    job: &Job,
    m: &Arc<owner::Metadata>,
) -> Result<ResolvedDeployment, &'static str> {
    let d = ctx
        .runtime
        .block_on(
            ctx.authority
                .resolve(&job.request, &m.policy, operation(job)?, budget(job)?),
        )
        .map_err(|_| "RUNTIME_AUTHORITY_REFUSED")?;
    if !Arc::ptr_eq(m, &owner::snapshot(&ctx.shared)?) {
        return Err(owner::UNAVAILABLE);
    }
    Ok(d)
}
pub(super) fn run(
    ctx: &Context,
    job: &Job,
) -> Result<proto::RuntimeReconcileResponse, &'static str> {
    #[cfg(test)]
    let _scope = super::testing::enter(&ctx.resources.hooks);
    let (metadata, authority) = checkpoint(ctx, job, None)?;
    let serving = authority.desired_state == i32::from(proto::ProxyDesiredState::Serving);
    let claims = job.request.get_ref();
    let t = claims.target.as_ref().ok_or(ERROR)?;
    let old = ctx.resources.journal.load(&ctx.installation, t)?;
    // Restart cannot bypass unresolved physical health ownership. Only exact
    // daemon completion recovered by the observation owner closes this history.
    if let Some(installed) = old.as_ref().and_then(|r| r.installed.as_ref()) {
        super::health::mutation_allowed(&ctx.resources.journal, &ctx.installation, installed)?;
    }
    // Empty cleanup history cannot manufacture terminal removal proof.
    if !serving && old.is_none() {
        return Err("RUNTIME_CLEANUP_HISTORY_UNAVAILABLE");
    }
    let mut record = match old {
        Some(old) if old.claims.operation_id != claims.operation_id => {
            old.advance(claims, serving)?
        }
        old => Record::select(&ctx.installation, claims, old)?,
    };
    ctx.resources.journal.save(&record)?;
    if !serving {
        return cleanup(ctx, job, &metadata, &authority, record);
    }
    let resolved = resolve(ctx, job, &metadata)?;
    if resolved.authority().desired_state != authority.desired_state {
        return Err("RUNTIME_OPERATION_NOT_CURRENT");
    }
    let launch = metadata
        .catalog
        .recover(
            &resolved,
            record.original.target.as_ref().ok_or(ERROR)?,
            &record.instance,
        )
        .map_err(|_| "RUNTIME_LAUNCH_REFUSED")?;
    let catalogs = metadata.execution.as_ref().ok_or(ERROR)?;
    let selected = catalogs.select(
        resolved.authority(),
        resolved.bindings_version(),
        resolved.configuration(),
        &launch,
    )?;
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
                signing.certificate_oidc_issuer
            ))
            .map_err(|_| ERROR)?
        )
    );
    if let Some(i) = &record.installed {
        if i.original != record.original
            || i.instance != record.instance
            || i.launch_json.as_bytes() != launch.launch_json()
            || i.configuration_json.as_bytes() != launch.configuration_json()
            || i.authority_json.as_bytes() != selected.authority_json
            || i.tools_json.as_bytes() != selected.tools_json
            || i.publication_hash != publication
            || i.phase == Phase::Removed
            || i.mount_profile != ctx.resources.engine.mount_profile()
        {
            return Err(ERROR);
        }
    } else {
        record.installed = Some(Installed {
            original: record.original.clone(),
            instance: record.instance.clone(),
            launch_json: String::from_utf8(launch.launch_json().to_vec()).map_err(|_| ERROR)?,
            configuration_json: String::from_utf8(launch.configuration_json().to_vec())
                .map_err(|_| ERROR)?,
            authority_json: String::from_utf8(selected.authority_json.clone())
                .map_err(|_| ERROR)?,
            tools_json: String::from_utf8(selected.tools_json.clone()).map_err(|_| ERROR)?,
            publication_hash: publication,
            image_id: String::new(),
            mount_profile: ctx.resources.engine.mount_profile().into(),
            unset_env: vec![],
            container_id: String::new(),
            phase: Phase::Intent,
            files: Default::default(),
            instance_proof_version: Some(1),
            network: None,
            guard_stage: None,
            gateway_stage: None,
            paired_containers: None,
        });
        ctx.resources.journal.save(&record)?;
    }
    // Consult durable global history even with no selected network catalog.
    // A committed reservation may not yet have its per-proxy attachment.
    let reserved = ctx
        .resources
        .journal
        .network_reserved(&ctx.installation, record.installed.as_ref().ok_or(ERROR)?)?;
    if metadata.network.is_some() || reserved {
        super::guard_staging::run(ctx, job, &metadata, &mut record, &launch, &selected)?;
        super::gateway_staging::run(ctx, job, &metadata, &mut record, &launch, &selected)?;
        super::paired::run(ctx, job, &metadata, &mut record, &launch, &selected)?;
        return Err(DORMANT);
    }
    checkpoint(ctx, job, Some(&metadata))?;
    let image = ctx
        .resources
        .signature
        .verify(
            &catalogs.images,
            launch.image_catalog_id(),
            &launch.context().image_ref,
            budget(job)?,
            &job.cancelled,
        )
        .map_err(|_| "RUNTIME_SIGNATURE_REFUSED")?;
    let mut i = record.installed.take().ok_or(ERROR)?;
    if i.image_id.is_empty() {
        checkpoint(ctx, job, Some(&metadata))?;
        ctx.resources
            .engine
            .pull(&image, deadline(job)?, &job.cancelled)?;
    }
    checkpoint(ctx, job, Some(&metadata))?;
    let (image_id, keys) =
        ctx.resources
            .engine
            .image(image.image_ref(), deadline(job)?, &job.cancelled)?;
    if !i.image_id.is_empty() && (i.image_id != image_id || i.unset_env != keys) {
        return Err(ERROR);
    }
    i.image_id = image_id;
    i.unset_env = keys.clone();
    if i.phase == Phase::ProofIntent {
        // A previous owner may have generated bytes but not sealed them. A new
        // random credential under this same immutable identity is forbidden.
        return Err("RUNTIME_INSTANCE_PROOF_QUARANTINED");
    }
    if i.phase == Phase::Intent {
        checkpoint(ctx, job, Some(&metadata))?;
        let proof = if i.instance_proof_version == Some(1) {
            i.phase = Phase::ProofIntent;
            persist(ctx, &mut record, &i)?;
            #[cfg(test)]
            super::testing::at(super::testing::Point::ProofIntent, None)?;
            Some(
                crate::secrets::InstanceProof::generate()
                    .map_err(|_| "RUNTIME_INSTANCE_PROOF_REFUSED")?,
            )
        } else {
            None
        };
        i.files = ctx
            .resources
            .staging
            .managed(&launch, &selected, false, None, proof.as_ref())
            .map_err(|_| "RUNTIME_STAGE_REFUSED")?;
        i.phase = Phase::StageIntent;
        persist(ctx, &mut record, &i)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::StageIntent, None)?;
        checkpoint(ctx, job, Some(&metadata))?;
        ctx.resources
            .staging
            .managed(&launch, &selected, false, Some(&i.files), proof.as_ref())
            .map_err(|_| "RUNTIME_STAGE_REFUSED")?;
        i.phase = Phase::Staged;
        persist(ctx, &mut record, &i)?;
    } else {
        checkpoint(ctx, job, Some(&metadata))?;
        ctx.resources
            .staging
            .managed(&launch, &selected, true, Some(&i.files), None)
            .map_err(|_| "RUNTIME_STAGE_QUARANTINED")?;
        if i.phase == Phase::StageIntent {
            i.phase = Phase::Staged;
            persist(ctx, &mut record, &i)?;
        }
    }
    if i.phase == Phase::Staged {
        checkpoint(ctx, job, Some(&metadata))?;
        ctx.resources
            .staging
            .managed(&launch, &selected, true, Some(&i.files), None)
            .map_err(|_| "RUNTIME_STAGE_QUARANTINED")?;
        i.phase = Phase::CreateIntent;
        persist(ctx, &mut record, &i)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::CreateIntent, None)?;
        let create_deadline =
            match checkpoint(ctx, job, Some(&metadata)).and_then(|_| deadline(job)) {
                Ok(deadline) => deadline,
                Err(refusal) => {
                    // This physical owner still holds the proxy guard and has not
                    // called create. Record only that known no-dispatch fact, even
                    // when authority was withdrawn; this authorizes no new effect.
                    // A crash before this save still leaves ambiguous CreateIntent.
                    i.phase = Phase::Staged;
                    persist(ctx, &mut record, &i)?;
                    return Err(refusal);
                }
            };
        // Once create is called, any failure stays CreateIntent: completion can
        // be unknown. Absence alone must never authorize a replacement create.
        ctx.resources.engine.create(
            &ctx.installation,
            &i,
            &keys,
            create_deadline,
            &job.cancelled,
        )?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::Created, None)?;
    }
    checkpoint(ctx, job, Some(&metadata))?;
    i.container_id =
        ctx.resources
            .engine
            .inspect(&ctx.installation, &i, deadline(job)?, &job.cancelled)?;
    i.phase = Phase::Installed;
    persist(ctx, &mut record, &i)?;
    if selected.registration_required {
        // Explicit schema2 preparation only. Receipt is not engine admission.
        // Re-read the complete sealed stage immediately before its attestation
        // leaves the actual agent; caller response fields never self-register.
        checkpoint(ctx, job, Some(&metadata))?;
        ctx.resources
            .staging
            .managed(&launch, &selected, true, Some(&i.files), None)
            .map_err(|_| "RUNTIME_STAGE_QUARANTINED")?;
        let attestation = i
            .attestation(&ctx.installation)?
            .ok_or("RUNTIME_INSTANCE_ATTESTATION_REFUSED")?;
        ctx.runtime
            .block_on(ctx.authority.register(
                &job.request,
                &metadata.policy,
                operation(job)?,
                &attestation,
                budget(job)?,
            ))
            .map_err(|_| "RUNTIME_REGISTRATION_REFUSED")?;
        // Current shared policy, cancellation, original whole-job budget and
        // current operation must still match after the registration callback.
        checkpoint(ctx, job, Some(&metadata))?;
    }
    let (_, a) = checkpoint(ctx, job, Some(&metadata))?;
    response(
        &ctx.installation,
        claims,
        Some(&i),
        proto::ProxyObservedState::NotServing,
        a.checked_at_unix_us,
        DORMANT,
    )
}
fn persist(ctx: &Context, r: &mut Record, i: &Installed) -> Result<(), &'static str> {
    r.installed = Some(i.clone());
    ctx.resources.journal.save(r)
}
fn response(
    installation: &str,
    claims: &proto::RuntimeReconcileRequest,
    i: Option<&Installed>,
    state: proto::ProxyObservedState,
    now: u64,
    error: &str,
) -> Result<proto::RuntimeReconcileResponse, &'static str> {
    let runtime = i
        .map(|i| -> Result<proto::RuntimeObservation, &'static str> {
            Ok(proto::RuntimeObservation {
                target: i.original.target.clone(),
                runtime_id: i.container_id.clone(),
                state: "not-serving".into(),
                observed_at_unix_us: now,
                error_code: error.into(),
                launch_attestation: i.attestation(installation)?,
                ..Default::default()
            })
        })
        .transpose()?;
    Ok(proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(claims.clone()),
        observed_state: state.into(),
        error_code: error.into(),
        runtime,
    })
}
fn cleanup(
    ctx: &Context,
    job: &Job,
    m: &Arc<owner::Metadata>,
    a: &proto::RuntimeAuthoritySnapshot,
    mut r: Record,
) -> Result<proto::RuntimeReconcileResponse, &'static str> {
    // Task3A can prove only dormant, never-started resources. Anything running
    // remains quarantined for the Task4 admission/drain owner.
    let retired = a.desired_state == i32::from(proto::ProxyDesiredState::Retired);
    for i in [&r.installed, &r.predecessor].into_iter().flatten() {
        if i.paired_containers.is_some() {
            return Err("RUNTIME_NETWORK_CLEANUP_PENDING");
        }
        if ctx
            .resources
            .journal
            .network_reserved(&ctx.installation, i)?
        {
            return Err("RUNTIME_NETWORK_CLEANUP_PENDING");
        }
    }
    for predecessor in [false, true] {
        let entry = if predecessor {
            r.predecessor.clone()
        } else {
            r.installed.clone()
        };
        let Some(mut i) = entry else {
            continue;
        };
        checkpoint(ctx, job, Some(m))?;
        if i.phase == Phase::Staged {
            // No create was issued for this durable stage. A successful exact
            // absence query is still required; a surprising container quarantines.
            if !i.container_id.is_empty()
                || !ctx
                    .resources
                    .engine
                    .absent(&i, deadline(job)?, &job.cancelled)?
            {
                return Err(ERROR);
            }
            if !retired {
                // Pause retains the sealed stage; it never creates to prove stop.
                continue;
            }
        } else if matches!(
            i.phase,
            Phase::RemoveIntent | Phase::StageRemoveIntent | Phase::Removed
        ) && ctx
            .resources
            .engine
            .absent(&i, deadline(job)?, &job.cancelled)?
        {
            // Durable removal intent plus a successful exact absence query.
        } else {
            i.container_id = ctx.resources.engine.inspect(
                &ctx.installation,
                &i,
                deadline(job)?,
                &job.cancelled,
            )?;
            if !retired {
                continue;
            }
            i.phase = Phase::RemoveIntent;
            if predecessor {
                r.predecessor = Some(i.clone());
            } else {
                r.installed = Some(i.clone());
            }
            ctx.resources.journal.save(&r)?;
            #[cfg(test)]
            super::testing::at(super::testing::Point::RemoveIntent, None)?;
            checkpoint(ctx, job, Some(m))?;
            ctx.resources
                .engine
                .remove(&i, deadline(job)?, &job.cancelled)?;
            #[cfg(test)]
            super::testing::at(super::testing::Point::Removed, None)?;
            checkpoint(ctx, job, Some(m))?;
            if !ctx
                .resources
                .engine
                .absent(&i, deadline(job)?, &job.cancelled)?
            {
                return Err(ERROR);
            }
        }
        i.phase = Phase::StageRemoveIntent;
        if predecessor {
            r.predecessor = Some(i.clone());
        } else {
            r.installed = Some(i.clone());
        }
        ctx.resources.journal.save(&r)?;
        checkpoint(ctx, job, Some(m))?;
        ctx.resources
            .staging
            .remove_managed(&i.instance, &i.files)
            .map_err(|_| "RUNTIME_MATERIAL_CLEANUP_PENDING")?;
        i.phase = Phase::Removed;
        if predecessor {
            r.predecessor = Some(i);
        } else {
            r.installed = Some(i);
        }
        ctx.resources.journal.save(&r)?;
    }
    let (_, now) = checkpoint(ctx, job, Some(m))?;
    if retired && r.installed.is_none() && r.predecessor.is_none() {
        return Err("RUNTIME_CLEANUP_HISTORY_UNAVAILABLE");
    }
    response(
        &ctx.installation,
        job.request.get_ref(),
        if retired {
            None
        } else {
            r.installed.as_ref().filter(|i| !i.container_id.is_empty())
        },
        if retired {
            proto::ProxyObservedState::Retired
        } else {
            proto::ProxyObservedState::Paused
        },
        now.checked_at_unix_us,
        "",
    )
}
