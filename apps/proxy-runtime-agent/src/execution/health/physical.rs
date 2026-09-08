//! Cleanup observations retain physical ownership beyond logical cancellation.
use super::*;
use crate::execution::{engine::Engine, journal::Journal};
use tokio::sync::watch;

#[cfg(test)]
mod tests;

pub(super) fn recover(ctx: &Context, record: &Record) -> Result<(), &'static str> {
    recover_exec(
        &ctx.resources.engine,
        &ctx.resources.journal,
        &ctx.shutdown,
        record,
    )
}

fn recover_exec(
    engine: &Engine,
    journal: &Journal,
    shutdown: &watch::Receiver<bool>,
    record: &Record,
) -> Result<(), &'static str> {
    match record.phase {
        Phase::StartIntent => {
            finish_exec(engine, journal, shutdown, record)?;
        }
        Phase::Created => {
            if *shutdown.borrow() {
                return Err(wire::ERROR);
            }
            let state = engine.health_inspect(
                &record.exec_id,
                &record.container_id,
                Instant::now() + Duration::from_secs(2),
                &AtomicBool::new(false),
            )?;
            // No start dispatch was authorized. An unexpected actual process is
            // quarantined, not adopted or silently killed.
            if state.running || state.pid != 0 {
                return Err(wire::ERROR);
            }
            complete(journal, shutdown, record)?;
        }
        Phase::CreateIntent => return Err(wire::ERROR),
        Phase::Finished => {}
    }
    Ok(())
}

pub(super) fn finish(ctx: &Context, record: &Record) -> Result<i32, &'static str> {
    finish_exec(
        &ctx.resources.engine,
        &ctx.resources.journal,
        &ctx.shutdown,
        record,
    )
}

fn finish_exec(
    engine: &Engine,
    journal: &Journal,
    shutdown: &watch::Receiver<bool>,
    record: &Record,
) -> Result<i32, &'static str> {
    let never_cancel = AtomicBool::new(false);
    loop {
        // Shutdown closes admission globally. Keep unresolved intent on disk so
        // the next process must recover the exact exec before mutation/retry.
        if *shutdown.borrow() {
            return Err(wire::ERROR);
        }
        if let Ok(state) = engine.health_inspect(
            &record.exec_id,
            &record.container_id,
            Instant::now() + Duration::from_secs(2),
            &never_cancel,
        ) && !state.running
            && state.pid > 0
            && let Some(exit_code) = state.exit_code
        {
            complete(journal, shutdown, record)?;
            return Ok(exit_code);
        }
        // This is cleanup polling only, never a readiness lease extension or
        // retry of create/start. Its physical worker and proxy guard remain held.
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn complete(
    journal: &Journal,
    shutdown: &watch::Receiver<bool>,
    record: &Record,
) -> Result<(), &'static str> {
    // Serialize the durable completion decision with shutdown publication. A
    // shutdown observed while inspection was pending must leave intent unresolved.
    let stopped = shutdown.borrow();
    if *stopped {
        return Err(wire::ERROR);
    }
    journal.health_transition(
        Some(record),
        &Record {
            phase: Phase::Finished,
            ..record.clone()
        },
    )
}
