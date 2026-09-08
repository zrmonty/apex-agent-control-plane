//! Fresh fixed-process collection against the original installed revision.
use super::{
    health_record::{Phase, Record},
    network_readiness as network,
    pool::Context,
};
use crate::{
    owner, proto,
    service::{health_observation as wire, network_readiness::authorize_binding},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
mod physical;

pub(super) fn mutation_allowed(
    journal: &super::journal::Journal,
    installation: &str,
    installed: &super::record::Installed,
) -> Result<(), &'static str> {
    // Pre-pair stages cannot yet have dispatched health. Never require a ready
    // attestation to clean up never-started provisioning failures.
    if installed
        .paired_containers
        .as_ref()
        .is_none_or(|p| p.start.is_none())
    {
        return Ok(());
    }
    let attestation = installed.attestation(installation)?.ok_or(wire::ERROR)?;
    let launch = attestation.launch.ok_or(wire::ERROR)?;
    let b = proto::ManagedDeploymentBinding {
        installation_id: installation.into(),
        target: launch.target,
        process_instance_id: installed.instance.clone(),
        config_hash: launch.config_hash,
        launch_context_hash: launch.launch_context_hash,
    };
    if journal
        .health_record(&b)?
        .is_some_and(|r| r.phase != Phase::Finished)
    {
        return Err(wire::ERROR);
    }
    Ok(())
}

/// Data retains its original monotonic deadline through the final TLS handoff.
pub(crate) struct Observation {
    response: proto::RuntimeHealthObservationResponse,
    expires: Instant,
}
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Observation { [data only; redacted] }")
    }
}
impl Observation {
    pub(crate) fn handoff(
        mut self,
    ) -> Result<proto::RuntimeHealthObservationResponse, &'static str> {
        let left = self
            .expires
            .checked_duration_since(Instant::now())
            .ok_or(wire::ERROR)?;
        let ns = u64::try_from(left.as_nanos()).map_err(|_| wire::ERROR)?;
        if ns == 0 {
            return Err(wire::ERROR);
        }
        self.response
            .sample
            .as_mut()
            .ok_or(wire::ERROR)?
            .valid_for_ns = ns;
        Ok(self.response)
    }
}

pub(super) fn collect(
    ctx: &Context,
    request: &tonic::Request<proto::RuntimeHealthObservationRequest>,
    started: Instant,
    cancel: &AtomicBool,
    metadata: &Arc<owner::Metadata>,
) -> Result<Observation, &'static str> {
    let b = request.get_ref().binding.as_ref().ok_or(wire::ERROR)?;
    let t = b.target.as_ref().ok_or(wire::ERROR)?;
    let mut check = || {
        if cancel.load(Ordering::Acquire)
            || started.elapsed() >= wire::BUDGET
            || *ctx.shutdown.borrow()
            || !Arc::ptr_eq(metadata, &owner::snapshot(&ctx.shared)?)
        {
            return Err(wire::ERROR);
        }
        authorize_binding(request, Some(b), &ctx.installation, metadata)
            .map_err(|_| wire::ERROR)?;
        Ok(())
    };
    check()?;
    let journal = &ctx.resources.journal;
    let r = journal.load(&ctx.installation, t)?.ok_or(wire::ERROR)?;
    let i = r.installed.as_ref().ok_or(wire::ERROR)?;
    if r.installation != ctx.installation
        || r.original != i.original
        || r.instance != i.instance
        || i.mount_profile != ctx.resources.engine.mount_profile()
    {
        return Err(wire::ERROR);
    }
    network::binding(&ctx.installation, i, b)?;
    let verify = |check: &mut dyn FnMut() -> Result<(), &'static str>| {
        network::current::check(
            &ctx.resources.staging,
            &ctx.installation,
            i,
            metadata,
            &mut || check(),
        )?;
        // No network-effect lock is retained while the health process waits on
        // gateway readiness: its concurrent NETWORK callback needs this owner.
        let _network = ctx
            .resources
            .network_effect
            .try_lock()
            .map_err(|_| wire::ERROR)?;
        network::observe(
            journal,
            &ctx.resources.engine,
            &ctx.installation,
            i,
            Instant::now(),
            cancel,
            &mut || check(),
        )?;
        Ok::<_, &'static str>(())
    };
    verify(&mut check)?;
    let container = &i.paired_containers.as_ref().ok_or(wire::ERROR)?.gateway_id;
    let previous = journal.health_record(b)?;
    if previous
        .as_ref()
        .is_some_and(|p| &p.container_id != container)
    {
        return Err(wire::ERROR);
    }
    if let Some(previous) = previous.as_ref().filter(|p| p.phase != Phase::Finished) {
        physical::recover(ctx, previous)?;
        // Recovery proves cleanup only. Never reuse a prior sample or execute
        // again within the recovering request.
        return Err(wire::ERROR);
    }
    check()?;
    let intent = Record {
        schema_version: 1,
        attempt_id: uuid::Uuid::now_v7().to_string(),
        binding: b.clone(),
        container_id: container.clone(),
        exec_id: String::new(),
        phase: Phase::CreateIntent,
    };
    journal.health_transition(previous.as_ref(), &intent)?;
    check()?;
    let dispatch = Instant::now();
    let until = started + wire::BUDGET;
    let exec_id = ctx
        .resources
        .engine
        .health_create(container, until, cancel)?;
    let created = Record {
        exec_id,
        phase: Phase::Created,
        ..intent.clone()
    };
    journal.health_transition(Some(&intent), &created)?;
    check()?;
    let start = Record {
        phase: Phase::StartIntent,
        ..created.clone()
    };
    journal.health_transition(Some(&created), &start)?;
    // Persist the intent before the last permission check. If that check fails,
    // the exact exec has not been started and can safely be marked finished.
    if let Err(e) = check() {
        let finished = Record {
            phase: Phase::Finished,
            ..start.clone()
        };
        journal.health_transition(Some(&start), &finished)?;
        return Err(e);
    }
    let bytes = ctx
        .resources
        .engine
        .health_start(&start.exec_id, until, cancel);
    // Independently inspect daemon termination even on timeout, cancellation,
    // malformed output or transport error. Physical work may outlive the RPC.
    let exit = physical::finish(ctx, &start)?;
    check()?;
    if exit != 0 {
        return Err(wire::ERROR);
    }
    let bytes = bytes?;
    let attestation = i.attestation(&ctx.installation)?.ok_or(wire::ERROR)?;
    let launch = attestation.launch.as_ref().ok_or(wire::ERROR)?;
    let sample = crate::readiness_report::decode_health_sample_stdout(&bytes, launch)
        .map_err(|_| wire::ERROR)?;
    let expires = dispatch
        .checked_add(Duration::from_nanos(sample.valid_for_ns()))
        .ok_or(wire::ERROR)?;
    verify(&mut check)?;
    let after = journal.load(&ctx.installation, t)?.ok_or(wire::ERROR)?;
    if serde_json::to_vec(&r).map_err(|_| wire::ERROR)?
        != serde_json::to_vec(&after).map_err(|_| wire::ERROR)?
    {
        return Err(wire::ERROR);
    }
    check()?;
    if Instant::now() >= expires {
        return Err(wire::ERROR);
    }
    Ok(Observation {
        expires,
        response: proto::RuntimeHealthObservationResponse {
            schema_version: 1,
            binding: Some(b.clone()),
            nonce: request.get_ref().nonce.clone(),
            sample: Some(proto::RuntimeHealthSample {
                schema_version: 1,
                report: Some(sample.report().clone()),
                valid_for_ns: 0,
            }),
        },
    })
}
