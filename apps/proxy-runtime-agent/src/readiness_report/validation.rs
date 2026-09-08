//! Lexical expectations and report relations, without IO or wall-time arithmetic.

use super::ReadinessReportError;
use crate::{check_runtime_target, proto, shapes};
use std::collections::BTreeSet;

pub(super) fn expected_binding(
    launch: &proto::RuntimeLaunchContext,
) -> Result<(), ReadinessReportError> {
    let invalid = ReadinessReportError;
    check_runtime_target(launch.target.as_ref().ok_or(invalid)?).map_err(|_| invalid)?;
    if launch.schema_version != 1
        || !shapes::hex_hash(&launch.config_hash)
        || !shapes::hex_hash(&launch.runtime_manifest_hash)
        || !shapes::hex_hash(&launch.launch_context_hash)
        || !shapes::uuid_v7(&launch.process_instance_id)
        || !shapes::image_ref(&launch.image_ref)
        || !shapes::version(&launch.authority_profile_ref)
        || !shapes::version(&launch.authority_profile_version)
        || !(1..=13).contains(&launch.materials.len())
    {
        return Err(invalid);
    }
    let health = launch.health.as_ref().ok_or(invalid)?;
    if health.port != 8081 || !shapes::secret_reference(&health.credential_ref) {
        return Err(invalid);
    }
    let mut roles = BTreeSet::new();
    for material in &launch.materials {
        let role = proto::RuntimeMaterialRole::try_from(material.role).map_err(|_| invalid)?;
        if role == proto::RuntimeMaterialRole::Unspecified
            || !roles.insert(material.role)
            || !shapes::secret_reference(&material.reference)
            || !shapes::version(&material.version)
            || ((role == proto::RuntimeMaterialRole::HealthToken)
                != (material.reference == health.credential_ref))
        {
            return Err(invalid);
        }
    }
    if !roles.contains(&i32::from(proto::RuntimeMaterialRole::HealthToken)) {
        return Err(invalid);
    }
    Ok(())
}

pub(super) fn report(
    report: proto::ReadinessReport,
    expected: &proto::RuntimeLaunchContext,
) -> Result<proto::ReadinessReport, ReadinessReportError> {
    if !report.live
        || !report.ready
        || report.observed_at_unix_us == 0
        || report.target != expected.target
        || report.config_hash != expected.config_hash
        || report.runtime_manifest_hash != expected.runtime_manifest_hash
        || report.launch_context_hash != expected.launch_context_hash
        || report.process_instance_id != expected.process_instance_id
    {
        return Err(ReadinessReportError);
    }
    let mut checks = BTreeSet::new();
    for check in &report.checks {
        if !checks.insert(check.id) {
            return Err(ReadinessReportError);
        }
    }
    let mut names = BTreeSet::new();
    for stage in &report.stages {
        if !matches!(
            stage.name.as_str(),
            "readiness.config"
                | "readiness.launch"
                | "readiness.material"
                | "readiness.inbound_auth"
                | "readiness.upstream_catalog"
                | "readiness.governance"
                | "readiness.evidence_admission"
                | "readiness.network"
                | "readiness.admission"
        ) || !names.insert(&stage.name)
            || stage.process_instance_id != expected.process_instance_id
            || stage.started_at_unix_us == 0
            || stage.clock_resolution_ns == 0
            || stage.duration_ns.map(|ns| ns / 1000) != Some(stage.duration_us)
            || !(1..=128).contains(&stage.clock_source.len())
            || !stage
                .clock_source
                .bytes()
                .all(|byte| (b' '..=b'~').contains(&byte))
            || stage.clock_source.trim() != stage.clock_source
        {
            return Err(ReadinessReportError);
        }
    }
    Ok(report)
}
