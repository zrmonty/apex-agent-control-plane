//! Durable intent and exact completed adoption; unknown absence never recreates.
use super::{ERROR, Phase};
use crate::{
    command,
    execution::{
        engine::{Engine, paired::Role},
        journal::Journal,
        record::Record,
    },
};
use std::{sync::atomic::AtomicBool, time::Instant};

pub(in crate::execution) struct Gate<'a> {
    pub check: &'a mut dyn FnMut() -> Result<(), &'static str>,
    pub deadline: &'a dyn Fn() -> Result<Instant, &'static str>,
    pub attempted: bool,
}
impl command::Dispatch for Gate<'_> {
    fn check(&mut self) -> Result<(), &'static str> {
        (self.check)()
    }
    fn deadline(&self) -> Result<Instant, &'static str> {
        (self.deadline)()
    }
    fn spawn_attempt(&mut self) {
        self.attempted = true;
    }
}

pub(in crate::execution) fn finish(
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
        let topology = &i.guard_stage.as_ref().ok_or(ERROR)?.topology.0.topology.0;
        let history = journal.topology_history(&r.installation)?;
        let outer = engine.pair_memberships(journal, topology, &history, deadline()?, cancelled)?;
        check()?;
        match p.phase {
            Phase::Prepared | Phase::GatewayObserved | Phase::GuardObserved => {
                let previous = p.phase;
                let intent = match previous {
                    Phase::Prepared => Phase::GatewayIntent,
                    Phase::GatewayObserved => Phase::GuardIntent,
                    Phase::GuardObserved => Phase::ConnectIntent,
                    _ => return Err(ERROR),
                };
                set_phase(r, intent)?;
                journal.save(r)?;
                #[cfg(test)]
                crate::execution::testing::at(crate::execution::testing::Point::PairIntent, None)?;
                let i = r.installed.as_ref().ok_or(ERROR)?;
                // Both the final physical dispatch and the ordinary preflight
                // recheck sealed files/currentness and the independent inventory.
                let mut dispatch_check = || {
                    check()?;
                    let history = journal.topology_history(&r.installation)?;
                    engine.pair_memberships(
                        journal,
                        &i.guard_stage.as_ref().ok_or(ERROR)?.topology.0.topology.0,
                        &history,
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
                let result = match intent {
                    Phase::GatewayIntent => {
                        engine.pair_create(&r.installation, i, Role::Gateway, &mut gate, cancelled)
                    }
                    Phase::GuardIntent => {
                        engine.pair_create(&r.installation, i, Role::Guard, &mut gate, cancelled)
                    }
                    Phase::ConnectIntent => engine.pair_connect(i, &mut gate, cancelled),
                    _ => return Err(ERROR),
                };
                if let Err(error) = result {
                    if !gate.attempted {
                        set_phase(r, previous)?;
                        journal.save(r)?;
                    }
                    return Err(error);
                }
                #[cfg(test)]
                crate::execution::testing::at(
                    crate::execution::testing::Point::PairEffectReturned,
                    None,
                )?;
            }
            Phase::GatewayIntent | Phase::GuardIntent => {
                let role = if p.phase == Phase::GatewayIntent {
                    Role::Gateway
                } else {
                    Role::Guard
                };
                let id = engine.pair_inspect(
                    &r.installation,
                    i,
                    role,
                    (&outer, false),
                    deadline()?,
                    cancelled,
                )?;
                check()?;
                let p = r
                    .installed
                    .as_mut()
                    .ok_or(ERROR)?
                    .paired_containers
                    .as_mut()
                    .ok_or(ERROR)?;
                if role == Role::Gateway {
                    p.gateway_id = id;
                    p.phase = Phase::GatewayObserved;
                } else {
                    p.guard_id = id;
                    p.phase = Phase::GuardObserved;
                }
                journal.save(r)?;
            }
            Phase::ConnectIntent | Phase::Verified => {
                engine.pair_inspect(
                    &r.installation,
                    i,
                    Role::Gateway,
                    (&outer, false),
                    deadline()?,
                    cancelled,
                )?;
                engine.pair_inspect(
                    &r.installation,
                    i,
                    Role::Guard,
                    (&outer, true),
                    deadline()?,
                    cancelled,
                )?;
                check()?;
                if p.phase != Phase::Verified {
                    set_phase(r, Phase::Verified)?;
                    journal.save(r)?;
                }
                check()?;
                return Ok(());
            }
        }
    }
}
fn set_phase(r: &mut Record, phase: Phase) -> Result<(), &'static str> {
    r.installed
        .as_mut()
        .ok_or(ERROR)?
        .paired_containers
        .as_mut()
        .ok_or(ERROR)?
        .phase = phase;
    Ok(())
}
