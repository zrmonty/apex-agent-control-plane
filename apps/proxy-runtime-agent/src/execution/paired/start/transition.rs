//! Start intents precede effects; only the physical owner can prove no dispatch.
use super::{ERROR, Observation, Step};
use crate::execution::{
    engine::{Engine, paired::Role},
    journal::Journal,
    paired::transition::Gate,
    record::Record,
};
use std::{sync::atomic::AtomicBool, time::Instant};

pub(in crate::execution) fn run(
    journal: &Journal,
    engine: &Engine,
    r: &mut Record,
    check: &mut dyn FnMut() -> Result<(), &'static str>,
    deadline: &dyn Fn() -> Result<Instant, &'static str>,
    cancelled: &AtomicBool,
) -> Result<(), &'static str> {
    loop {
        check()?;
        let i = r.installed.as_ref().ok_or(ERROR)?;
        let p = i.paired_containers.as_ref().ok_or(ERROR)?;
        p.validate(&r.installation, i)?;
        if p.phase != super::super::Phase::Verified {
            return Err(ERROR);
        }
        let t = i
            .guard_stage
            .as_ref()
            .ok_or(ERROR)?
            .topology
            .0
            .topology
            .0
            .clone();
        let history = journal.topology_history(&r.installation)?;
        let outer = engine.pair_memberships(journal, &t, &history, deadline()?, cancelled)?;
        check()?;
        let phase = p.start.as_ref().map(|s| s.phase);
        match phase {
            None | Some(Step::GuardObserved) => {
                let role = if phase.is_none() {
                    Role::Guard
                } else {
                    Role::Gateway
                };
                let previous = p.start.clone();
                let mut next = previous.clone().unwrap_or_else(|| Observation {
                    schema_version: 1,
                    phase: Step::GuardIntent,
                    gateway_id: p.gateway_id.clone(),
                    guard_id: p.guard_id.clone(),
                    guard: None,
                    gateway: None,
                });
                if role == Role::Gateway {
                    next.phase = Step::GatewayIntent;
                }
                r.installed
                    .as_mut()
                    .ok_or(ERROR)?
                    .paired_containers
                    .as_mut()
                    .ok_or(ERROR)?
                    .start = Some(next);
                journal.save(r)?;
                #[cfg(test)]
                crate::execution::testing::at(crate::execution::testing::Point::StartIntent, None)?;
                let i = r.installed.as_ref().ok_or(ERROR)?;
                let mut dispatch_check = || {
                    check()?;
                    let history = journal.topology_history(&r.installation)?;
                    let outer =
                        engine.pair_memberships(journal, &t, &history, deadline()?, cancelled)?;
                    engine.pair_start_preflight(
                        &r.installation,
                        i,
                        role,
                        &outer,
                        deadline()?,
                        cancelled,
                    )?;
                    check()
                };
                let mut gate = Gate {
                    check: &mut dispatch_check,
                    deadline,
                    attempted: false,
                };
                let result = engine.pair_start(&r.installation, i, role, &mut gate, cancelled);
                if let Err(error) = result {
                    if !gate.attempted {
                        r.installed
                            .as_mut()
                            .ok_or(ERROR)?
                            .paired_containers
                            .as_mut()
                            .ok_or(ERROR)?
                            .start = previous;
                        journal.save(r)?;
                    }
                    return Err(error);
                }
                #[cfg(test)]
                crate::execution::testing::at(
                    crate::execution::testing::Point::StartEffectReturned,
                    None,
                )?;
            }
            Some(Step::GuardIntent | Step::GatewayIntent) => {
                let role = if phase == Some(Step::GuardIntent) {
                    Role::Guard
                } else {
                    Role::Gateway
                };
                // Intent recovery can only adopt running. A still-created, absent,
                // exited or ambiguous process is never dispatched again.
                let receipt = engine.pair_running(
                    &r.installation,
                    i,
                    role,
                    &outer,
                    deadline()?,
                    cancelled,
                )?;
                check()?;
                let s = r
                    .installed
                    .as_mut()
                    .ok_or(ERROR)?
                    .paired_containers
                    .as_mut()
                    .ok_or(ERROR)?
                    .start
                    .as_mut()
                    .ok_or(ERROR)?;
                if role == Role::Guard {
                    s.guard = Some(receipt);
                    s.phase = Step::GuardObserved;
                } else {
                    s.gateway = Some(receipt);
                    s.phase = Step::Running;
                }
                journal.save(r)?;
            }
            Some(Step::Running) => {
                for role in [Role::Guard, Role::Gateway] {
                    engine.pair_running(
                        &r.installation,
                        i,
                        role,
                        &outer,
                        deadline()?,
                        cancelled,
                    )?;
                }
                check()?;
                deadline()?;
                return Ok(());
            }
        }
    }
}
