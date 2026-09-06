//! Guard-only durable storage. Neither a sealed record nor this IO permits serving.
use super::{journal::Journal, record::Record};
use crate::secrets::StagingOwner;
mod provision;
mod record;
pub(super) use provision::run;
pub(super) use record::{GuardStage, Phase, present};
const ERROR: &str = "RUNTIME_GUARD_STAGE_QUARANTINED";

// The production caller verifies signatures and supplies its real currentness gate.
// This private storage composition is also exercised directly by protected IO tests;
// those tests establish no production authorization outcome.
pub(super) fn stage(
    journal: &Journal,
    staging: &StagingOwner,
    record: &mut Record,
    mut fresh: GuardStage,
    check: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let installed = record.installed.as_ref().ok_or(ERROR)?;
    fresh.validate(&record.installation, installed)?;
    let recover = installed.guard_stage.is_some();
    let root = staging.guard_root().map_err(|_| ERROR)?;
    if let Some(old) = &installed.guard_stage {
        old.validate(&record.installation, installed)?;
        old.matches(&fresh)?;
        if old.root_identity.as_ref().is_none_or(|old| old.0 != root) {
            return Err(ERROR);
        }
    }
    check()?;
    if !recover {
        fresh.root_identity = Some(super::metadata::strict::Object(root));
        record.installed.as_mut().ok_or(ERROR)?.guard_stage = Some(fresh);
        journal.save(record)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::GuardIntent, None)?;
    }
    check()?;
    let installed = record.installed.as_ref().ok_or(ERROR)?;
    let guard = installed.guard_stage.as_ref().ok_or(ERROR)?;
    let identity = staging
        .guard(
            &installed.instance,
            guard.config_json.as_bytes(),
            recover,
            guard.sealed_identity.as_ref().map(|identity| &identity.0),
            &guard.root_identity.as_ref().ok_or(ERROR)?.0,
            check,
        )
        .map_err(|_| ERROR)?;
    check()?;
    if guard.phase == Phase::Intent {
        let guard = record
            .installed
            .as_mut()
            .ok_or(ERROR)?
            .guard_stage
            .as_mut()
            .ok_or(ERROR)?;
        guard.phase = Phase::Sealed;
        guard.sealed_identity = Some(super::metadata::strict::Object(identity));
        journal.save(record)?;
    }
    check()
}
