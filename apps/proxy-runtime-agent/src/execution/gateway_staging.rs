//! Paired gateway storage only. Never container execution, admission or readiness.
use super::{journal::Journal, metadata::Selected, record::Record};
use crate::{
    launch::PreparedLaunch,
    secrets::{InstanceProof, StagingOwner},
};
mod provision;
mod record;
pub(super) use provision::run;
pub(super) use record::{GatewayStage, Phase, present};
const ERROR: &str = "RUNTIME_GATEWAY_STAGE_QUARANTINED";

pub(super) fn stage(
    journal: &Journal,
    staging: &StagingOwner,
    record: &mut Record,
    fresh: GatewayStage,
    launch: &PreparedLaunch,
    selected: &Selected,
    check: &mut impl FnMut() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let i = record.installed.as_ref().ok_or(ERROR)?;
    fresh.validate(&record.installation, i)?;
    if fresh.root.0 != staging.guard_root().map_err(|_| ERROR)? {
        return Err(ERROR);
    }
    let recover = i.gateway_stage.is_some();
    if let Some(old) = &i.gateway_stage {
        old.validate(&record.installation, i)?;
        old.matches(&fresh)?;
        if matches!(old.phase, Phase::ProofIntent | Phase::StageIntent) {
            return Err(ERROR);
        }
    }
    check()?;
    if !recover {
        record.installed.as_mut().ok_or(ERROR)?.gateway_stage = Some(fresh);
        journal.save(record)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::GatewayProofIntent, None)?;
    }
    check()?;
    let proof = if !recover {
        let proof = InstanceProof::generate().map_err(|_| ERROR)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::GatewayProofGenerated, None)?;
        check()?;
        Some(proof)
    } else {
        None
    };
    let mut material = staging
        .gateway_material(launch, selected, check)
        .map_err(|_| ERROR)?;
    check()?;
    if let Some(proof) = &proof {
        material.add_proof(proof);
    }
    if !recover {
        let g = record
            .installed
            .as_mut()
            .ok_or(ERROR)?
            .gateway_stage
            .as_mut()
            .ok_or(ERROR)?;
        g.files = material.hashes();
        g.source_identity = Some(material.source_identity().map_err(|_| ERROR)?);
        g.phase = Phase::StageIntent;
        journal.save(record)?;
        #[cfg(test)]
        super::testing::at(super::testing::Point::GatewayStageIntent, None)?;
    }
    check()?;
    let i = record.installed.as_ref().ok_or(ERROR)?;
    let instance = i.instance.clone();
    let g = i.gateway_stage.as_ref().ok_or(ERROR)?.clone();
    if g.source_identity.as_ref() != Some(&material.source_identity().map_err(|_| ERROR)?) {
        return Err(ERROR);
    }
    let identity = staging
        .gateway(
            &material,
            crate::secrets::GatewayExpected {
                instance: &instance,
                root: &g.root.0,
                files: &g.files,
                identity: g.identity.as_ref().map(|v| &v.0),
            },
            check,
            &mut |identity| {
                let g = record
                    .installed
                    .as_mut()
                    .ok_or(ERROR)?
                    .gateway_stage
                    .as_mut()
                    .ok_or(ERROR)?;
                g.phase = Phase::SealIntent;
                g.identity = Some(super::metadata::strict::Object(identity));
                journal.save(record)?;
                #[cfg(test)]
                super::testing::at(super::testing::Point::GatewaySealIntent, None)?;
                Ok(())
            },
        )
        .map_err(|_| ERROR)?;
    check()?;
    staging
        .gateway_recheck(&instance, &g.root.0, &identity, &material)
        .map_err(|_| ERROR)?;
    if g.phase != Phase::Sealed {
        let g = record
            .installed
            .as_mut()
            .ok_or(ERROR)?
            .gateway_stage
            .as_mut()
            .ok_or(ERROR)?;
        g.phase = Phase::Sealed;
        g.identity = Some(super::metadata::strict::Object(identity.clone()));
        journal.save(record)?;
    }
    check()?;
    staging
        .gateway_recheck(&instance, &g.root.0, &identity, &material)
        .map_err(|_| ERROR)?;
    Err(super::provision::DORMANT)
}
