//! Empty isolated-network owner. No container effects, activation or release API.
use super::{
    pool::{Context, Job},
    provision,
    record::Installed,
};
use crate::owner;
use std::{
    sync::{Arc, TryLockError, atomic::AtomicBool},
    time::{Duration, Instant},
};
pub(super) mod topology;
use topology::{Document, Phase, Topology};
pub(in crate::execution) const ERROR: &str = "RUNTIME_NETWORK_EFFECT_QUARANTINED";

// This composition can be constructed only after this owner's durable intent.
// Native command code may check it, but cannot mint an authority permit.
pub(crate) struct DispatchGate<'a> {
    ctx: &'a Context,
    job: &'a Job,
    metadata: &'a Arc<owner::Metadata>,
    installed: &'a Installed,
    topology: &'a Topology,
    attempted: bool,
}
impl<'a> DispatchGate<'a> {
    pub(crate) fn cancelled(&self) -> &'a AtomicBool {
        &self.job.cancelled
    }
    pub(crate) fn deadline(&self) -> Result<Instant, &'static str> {
        provision::deadline(self.job)
    }
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        let (_, now) = provision::checkpoint(self.ctx, self.job, Some(self.metadata))?;
        let fresh = Topology::new(
            self.metadata.network.as_ref().ok_or(ERROR)?,
            &self.ctx.installation,
            self.installed,
            self.metadata.digest(),
            now.checked_at_unix_us,
        )?;
        if !self.topology.matches_current(&fresh)? {
            return Err(ERROR);
        }
        if *self.ctx.shutdown.borrow()
            || !Arc::ptr_eq(self.metadata, &owner::snapshot(&self.ctx.shared)?)
        {
            return Err(ERROR);
        }
        self.deadline()?;
        Ok(())
    }
    pub(crate) fn spawn_attempt(&mut self) {
        self.attempted = true;
    }
}
impl crate::command::Dispatch for DispatchGate<'_> {
    fn deadline(&self) -> Result<Instant, &'static str> {
        self.deadline()
    }
    fn check(&mut self) -> Result<(), &'static str> {
        DispatchGate::check(self)
    }
    fn spawn_attempt(&mut self) {
        DispatchGate::spawn_attempt(self);
    }
}
pub(super) fn prepare_empty(
    ctx: &Context,
    job: &Job,
    m: &Arc<owner::Metadata>,
    i: &Installed,
) -> Result<(), &'static str> {
    let _effect = loop {
        provision::deadline(job)?;
        if *ctx.shutdown.borrow() {
            return Err(ERROR);
        }
        match ctx.resources.network_effect.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(_)) => return Err(ERROR),
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(2)),
        }
    };
    let (_, now) = provision::checkpoint(ctx, job, Some(m))?;
    let fresh = Topology::new(
        m.network.as_ref().ok_or(ERROR)?,
        &ctx.installation,
        i,
        m.digest(),
        now.checked_at_unix_us,
    )?;
    let journal = &ctx.resources.journal;
    let engine = &ctx.resources.engine;
    let mut history = journal.topology_history(&ctx.installation)?;
    let mut d = match history.get(&i.instance) {
        Some(old) => {
            if !old.topology.0.matches_current(&fresh)? {
                return Err(ERROR);
            }
            old.clone()
        }
        None => Document::prepared(fresh)?,
    };
    let (before, _) = engine.pair_inventory(
        journal,
        &d.topology.0,
        &history,
        provision::deadline(job)?,
        &job.cancelled,
    )?;
    let own = before.validate(&d.topology.0, &history)?;
    if d.phase == Phase::Observed {
        return if own == d.observation {
            Ok(())
        } else {
            Err(ERROR)
        };
    }
    if d.phase == Phase::CreateIntent {
        let id = own.ok_or(ERROR)?;
        let (after, _) = engine.pair_inventory(
            journal,
            &d.topology.0,
            &history,
            provision::deadline(job)?,
            &job.cancelled,
        )?;
        if !before.unchanged(&after, None)
            || after.validate(&d.topology.0, &history)? != Some(id.clone())
        {
            return Err(ERROR);
        }
        let old = d.clone();
        d.phase = Phase::Observed;
        d.observation = Some(id);
        journal.transition_topology(&old, &d)?;
        provision::checkpoint(ctx, job, Some(m))?;
        return Ok(());
    }
    if !history.contains_key(&i.instance) {
        journal.prepare_topology(&d)?;
    }
    history.insert(i.instance.clone(), d.clone());
    let (before_intent, _) = engine.pair_inventory(
        journal,
        &d.topology.0,
        &history,
        provision::deadline(job)?,
        &job.cancelled,
    )?;
    if !before.unchanged(&before_intent, None)
        || before_intent.validate(&d.topology.0, &history)?.is_some()
    {
        return Err(ERROR);
    }
    provision::checkpoint(ctx, job, Some(m))?;
    let prepared = d.clone();
    d.phase = Phase::CreateIntent;
    journal.transition_topology(&prepared, &d)?;
    #[cfg(test)]
    super::testing::at(super::testing::Point::NetworkIntent, None)?;
    let mut gate = DispatchGate {
        ctx,
        job,
        metadata: m,
        installed: i,
        topology: &d.topology.0,
        attempted: false,
    };
    let id = match engine.create_internal(&d.topology.0, &mut gate) {
        Ok(id) => id,
        Err(error) => {
            if !gate.attempted {
                journal.transition_topology(&d, &prepared)?;
            }
            return Err(error);
        }
    };
    #[cfg(test)]
    super::testing::at(super::testing::Point::NetworkCreated, None)?;
    history.insert(i.instance.clone(), d.clone());
    let (after, _) = engine.pair_inventory(
        journal,
        &d.topology.0,
        &history,
        provision::deadline(job)?,
        &job.cancelled,
    )?;
    if !before_intent.unchanged(&after, Some(&id))
        || after.validate(&d.topology.0, &history)? != Some(id.clone())
    {
        return Err(ERROR);
    }
    let old = d.clone();
    d.phase = Phase::Observed;
    d.observation = Some(id);
    journal.transition_topology(&old, &d)?;
    provision::checkpoint(ctx, job, Some(m))?;
    Ok(())
}
