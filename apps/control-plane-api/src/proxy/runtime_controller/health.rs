//! One bounded health attempt on the reconcile client; no route publication.
use super::*;
use crate::LeasedProxyOperation;

pub(super) struct Attempt<'a> {
    pub lease: &'a LeasedProxyOperation,
    pub request: &'a proto::RuntimeReconcileRequest,
    pub response: &'a proto::RuntimeReconcileResponse,
    pub deadline: Instant,
}

pub(super) fn consume(
    config: &RuntimeExecutionConfig,
    store: &PostgresProxyStore,
    runtime: &tokio::runtime::Runtime,
    client: &mut RuntimeExecutionClient,
    attempt: &Attempt<'_>,
    check: &impl Fn() -> Result<(), ProxyError>,
) -> Result<(), ProxyError> {
    let Some(binding) = candidate(attempt) else {
        return Ok(());
    };
    let current = || {
        check()?;
        config.recheck()?;
        if Instant::now() >= attempt.deadline {
            return Err(unavailable());
        }
        check()
    };
    // SQL stays outside the Tokio runtime, on this physical owner's thread.
    if store
        .read_health_candidate_checked(attempt.lease, &binding, &current)?
        .is_none()
    {
        return Ok(());
    }
    let observation = runtime.block_on(client.observe_health(
        attempt.request,
        attempt.response,
        attempt.deadline,
        &current,
    ));
    let observation = match observation {
        Ok(observation) => observation,
        Err(error) if error.code() == "RUNTIME_EXECUTION_UNAVAILABLE" => {
            eprintln!("runtime_execution_health_unavailable");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    store.select_healthy_candidate_checked(attempt.lease, &binding, observation, &current)
}

fn candidate(attempt: &Attempt<'_>) -> Option<proto::ManagedDeploymentBinding> {
    if attempt.lease.operation.desired_state != proto::ProxyDesiredState::Serving as i32
        || attempt.response.observed_state != proto::ProxyObservedState::NotServing as i32
        // The agent's successful original installation currently caches this
        // dormant code. Fresh health may supersede its readiness meaning, never
        // its immutable evidence. All other failure/quarantine codes refuse.
        || !matches!(attempt.response.error_code.as_str(), "" | "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    {
        return None;
    }
    let installed = attempt.response.runtime.as_ref()?;
    let attestation = installed.launch_attestation.as_ref()?;
    let launch = attestation.launch.as_ref()?;
    let target = launch.target.as_ref()?;
    // Reconcile may legitimately recover an older generation. That original
    // launch remains evidence, but can never become the current candidate.
    if target.generation != attempt.lease.operation.generation
        || target.revision_id != attempt.lease.operation.revision_id
    {
        return None;
    }
    Some(proto::ManagedDeploymentBinding {
        installation_id: attestation.installation_id.clone(),
        target: launch.target.clone(),
        process_instance_id: launch.process_instance_id.clone(),
        config_hash: launch.config_hash.clone(),
        launch_context_hash: launch.launch_context_hash.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_current_serving_candidate_with_original_installation_can_be_probed() {
        let target = proto::RuntimeTarget {
            generation: 2,
            revision_id: "revision".into(),
            ..Default::default()
        };
        let lease = LeasedProxyOperation {
            operation: proto::ProxyOperation {
                generation: 2,
                revision_id: "revision".into(),
                desired_state: proto::ProxyDesiredState::Serving as i32,
                ..Default::default()
            },
            worker_id: "worker".into(),
            fencing_token: 3,
            lease_expires_at_micros: 1,
        };
        let request = proto::RuntimeReconcileRequest::default();
        let response = proto::RuntimeReconcileResponse {
            observed_state: proto::ProxyObservedState::NotServing as i32,
            runtime: Some(proto::RuntimeObservation {
                launch_attestation: Some(proto::RuntimeLaunchAttestation {
                    installation_id: "installation".into(),
                    launch: Some(proto::RuntimeLaunchContext {
                        target: Some(target),
                        process_instance_id: "original".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let deadline = Instant::now();
        let attempt = Attempt {
            lease: &lease,
            request: &request,
            response: &response,
            deadline,
        };
        assert_eq!(candidate(&attempt).unwrap().process_instance_id, "original");
        let mut dormant = response.clone();
        dormant.error_code = "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE".into();
        assert!(
            candidate(&Attempt {
                response: &dormant,
                ..attempt
            })
            .is_some()
        );
        for change in [
            "paused",
            "retired",
            "older-generation",
            "wrong-revision",
            "missing-attestation",
            "quarantined",
            "failed",
        ] {
            let mut lease = lease.clone();
            let mut response = response.clone();
            match change {
                "paused" => lease.operation.desired_state = proto::ProxyDesiredState::Paused as i32,
                "retired" => {
                    lease.operation.desired_state = proto::ProxyDesiredState::Retired as i32
                }
                "older-generation" => lease.operation.generation += 1,
                "wrong-revision" => lease.operation.revision_id = "other".into(),
                "missing-attestation" => {
                    response.runtime.as_mut().unwrap().launch_attestation = None
                }
                "quarantined" => {
                    response.error_code = "RUNTIME_PAIRED_CONTAINERS_QUARANTINED".into()
                }
                "failed" => response.observed_state = proto::ProxyObservedState::Failed as i32,
                _ => unreachable!(),
            }
            assert!(
                candidate(&Attempt {
                    lease: &lease,
                    request: &request,
                    response: &response,
                    deadline
                })
                .is_none(),
                "{change}"
            );
        }
    }
}
