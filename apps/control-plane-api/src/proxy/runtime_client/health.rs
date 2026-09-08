//! Fresh authenticated health observations; data only, never serving authority.
use super::{
    RuntimeExecutionClient, invalid, unavailable, validate_installation, validate_response,
};
use crate::{ProxyError, proto};
use prost::Message;
use std::time::{Duration, Instant};

const LIMIT: Duration = Duration::from_secs(10);

/// Original peer report plus a local monotonic bound. Not an admission permit.
pub(crate) struct HealthObservation {
    report: proto::ReadinessReport,
    expires: Instant,
}
impl std::fmt::Debug for HealthObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HealthObservation { [redacted; data only] }")
    }
}
impl HealthObservation {
    /// Consumes the data at handoff; elapsed local time can only reduce validity.
    pub(crate) fn into_remaining(self) -> Result<(proto::ReadinessReport, Duration), ProxyError> {
        Ok((self.report, remaining(self.expires)?))
    }
}

impl RuntimeExecutionClient {
    /// Uses this execution client's existing Controller channel/config. The
    /// caller owns polling of cancellation, shutdown and operation replacement.
    /// Reconnection and RPC IO stay in this future; no detached task or retry.
    pub(crate) async fn observe_health(
        &mut self,
        request: &proto::RuntimeReconcileRequest,
        observed: &proto::RuntimeReconcileResponse,
        deadline: Instant,
        check: &dyn Fn() -> Result<(), ProxyError>,
    ) -> Result<HealthObservation, ProxyError> {
        let started = Instant::now();
        let deadline = deadline.min(started + LIMIT);
        let current = || {
            remaining(deadline)?;
            check()?;
            remaining(deadline).map(|_| ())
        };
        current()?;
        validate_request(request, &self.config)?;
        validate_response(request, observed, proto::ProxyDesiredState::Serving)?;
        validate_installation(observed, &self.config.installation_id)?;
        let runtime = observed.runtime.as_ref().ok_or_else(invalid)?;
        let attestation = runtime.launch_attestation.as_ref().ok_or_else(invalid)?;
        let launch = attestation.launch.as_ref().ok_or_else(invalid)?;
        validate_target(launch.target.as_ref().ok_or_else(invalid)?)?;
        let mut nonce = vec![0; 32];
        getrandom::fill(&mut nonce).map_err(|_| unavailable())?;
        let input = proto::RuntimeHealthObservationRequest {
            schema_version: 1,
            binding: Some(proto::ManagedDeploymentBinding {
                installation_id: attestation.installation_id.clone(),
                target: launch.target.clone(),
                process_instance_id: launch.process_instance_id.clone(),
                config_hash: launch.config_hash.clone(),
                launch_context_hash: launch.launch_context_hash.clone(),
            }),
            nonce,
        };
        if input.encoded_len() > 4096 {
            return Err(invalid());
        }
        self.config.recheck()?;
        current()?;
        let mut wire = tonic::Request::new(input.clone());
        wire.set_timeout(remaining(deadline)?);
        let response = {
            let call = self.health.observe(wire);
            tokio::pin!(call);
            loop {
                current()?;
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => return Err(unavailable()),
                    result = &mut call => break result,
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                }
            }
        };
        current()?;
        self.config.recheck()?;
        current()?;
        let response = response.map_err(|_| unavailable())?.into_inner();
        if response.encoded_len() > 32768
            || response.schema_version != 1
            || response.binding != input.binding
            || response.nonce != input.nonce
        {
            return Err(invalid());
        }
        let sample = response.sample.ok_or_else(invalid)?;
        if sample.schema_version != 1 || !(1..=10_000_000_000).contains(&sample.valid_for_ns) {
            return Err(invalid());
        }
        let report = sample.report.ok_or_else(invalid)?;
        validate_report(&report, launch)?;
        let expires = (started + Duration::from_nanos(sample.valid_for_ns)).min(deadline);
        current()?;
        remaining(expires)?;
        Ok(HealthObservation { report, expires })
    }
}

fn validate_request(
    request: &proto::RuntimeReconcileRequest,
    config: &super::RuntimeExecutionConfig,
) -> Result<(), ProxyError> {
    let target = request.target.as_ref().ok_or_else(invalid)?;
    validate_target(target)?;
    if request.schema_version != 1
        || request.encoded_len() > 4096
        || !apex_domain::is_lowercase_uuidv7(&request.operation_id)
        || !apex_domain::is_lowercase_uuidv7(&request.command_id)
        || request.config_hash.len() != 64
        || !request
            .config_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !config
            .scopes
            .iter()
            .any(|s| s.workspace_id == target.workspace_id && s.namespace_id == target.namespace_id)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_target(target: &proto::RuntimeTarget) -> Result<(), ProxyError> {
    if !crate::proxy::is_scope_identifier(&target.workspace_id)
        || !crate::proxy::is_scope_identifier(&target.namespace_id)
        || !apex_domain::is_lowercase_uuidv7(&target.proxy_id)
        || !apex_domain::is_lowercase_uuidv7(&target.revision_id)
        || !(1..=i64::MAX as u64).contains(&target.generation)
        || !(1..=i64::MAX as u64).contains(&target.fencing_token)
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_report(
    report: &proto::ReadinessReport,
    launch: &proto::RuntimeLaunchContext,
) -> Result<(), ProxyError> {
    if !report.live
        || !report.ready
        || report.observed_at_unix_us == 0
        || report.target != launch.target
        || report.config_hash != launch.config_hash
        || report.runtime_manifest_hash != launch.runtime_manifest_hash
        || report.launch_context_hash != launch.launch_context_hash
        || report.process_instance_id != launch.process_instance_id
        || report.checks.len() != 9
        || report.stages.len() != 9
    {
        return Err(invalid());
    }
    let mut checks = std::collections::BTreeSet::new();
    for check in &report.checks {
        if !(1..=9).contains(&check.id)
            || !checks.insert(check.id)
            || check.status != i32::from(proto::ReadinessCheckStatus::Pass)
            || check.reason != i32::from(proto::ReadinessReason::Ok)
        {
            return Err(invalid());
        }
    }
    let mut stages = std::collections::BTreeSet::new();
    for stage in &report.stages {
        if !matches!(stage.name.as_str(), "readiness.config" | "readiness.launch" | "readiness.material"
            | "readiness.inbound_auth" | "readiness.upstream_catalog" | "readiness.governance"
            | "readiness.evidence_admission" | "readiness.network" | "readiness.admission")
            || !stages.insert(&stage.name)
            || stage.process_instance_id != launch.process_instance_id
            || stage.started_at_unix_us == 0 || stage.clock_resolution_ns == 0
            || stage.duration_ns.map(|ns| ns / 1000) != Some(stage.duration_us)
            || !(1..=128).contains(&stage.clock_source.len())
            || !stage.clock_source.bytes().all(|b| (b' '..=b'~').contains(&b))
            || stage.clock_source.trim() != stage.clock_source
            // No owner supplies tracing fields in this health profile. Prost
            // cannot distinguish absent/default scalar fields, unlike ProtoJSON.
            || !stage.otel_trace_id.is_empty() || !stage.span_id.is_empty() || !stage.parent_span_id.is_empty()
        {
            return Err(invalid());
        }
        // Optional uncertainty is already an exact u64; Some(0) and None are
        // distinct and preserved. No remote wall time is freshness authority.
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration, ProxyError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(unavailable)
}

#[cfg(test)]
mod tests;
