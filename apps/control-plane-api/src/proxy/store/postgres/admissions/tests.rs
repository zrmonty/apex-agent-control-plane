use super::super::serving::{CandidateReadiness, DeploymentRegistration};
use super::*;
use crate::LeasedProxyOperation;
#[path = "../serving/tests/fixture.rs"]
#[allow(clippy::duplicate_mod)] // Reuse the trusted fixture without widening its sibling-test API.
mod fixture;
use fixture::Fixture;
mod cleanup;
mod integrity;
mod limits;
mod races;

fn counters(f: &Fixture) -> (i64, i64, i64, i64) {
    let row=f.client().query_one("SELECT minute_used,day_used,active_calls,total_admissions FROM mcp_proxy_admission_counters", &[]).unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

fn complete(f: &Fixture, input: &ManagedCallReservation, admission: &ManagedCallAdmission) {
    f.store
        .complete_managed_call_checked(
            &input.binding,
            admission.admission_id,
            input.call_id,
            &|| Ok(()),
        )
        .unwrap();
}

fn request(f: &Fixture) -> ManagedCallReservation {
    ManagedCallReservation {
        binding: f.registration.binding.clone(),
        call_id: Uuid::now_v7(),
        semantic_sha256: [9; 32],
        policy_id: "ria-read-v1".into(),
        policy_revision: 9_007_199_254_740_993,
    }
}

fn renew(
    f: &Fixture,
    sequence: u64,
    grant: Option<&proto::ManagedDeploymentGrant>,
    admitting: bool,
) -> proto::ManagedDeploymentGrant {
    f.store
        .renew_deployment_checked(
            &proto::ManagedDeploymentRenewal {
                binding: Some(f.registration.binding.clone()),
                nonce: vec![u8::try_from(sequence).unwrap(); 32],
                renewal_sequence: sequence,
                applied: grant.map(|g| proto::ManagedGrantAcknowledgement {
                    decision_id: g.decision_id.clone(),
                    epoch: g.epoch,
                    admitting,
                    active_calls: 0,
                }),
            },
            &|| Ok(()),
        )
        .unwrap()
}

fn selected(f: &Fixture) -> proto::ManagedDeploymentGrant {
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let d1 = renew(f, 1, None, false);
    renew(f, 2, Some(&d1), false);
    let id = f
        .store
        .record_candidate_readiness_checked(
            &f.lease,
            &f.registration.binding,
            &CandidateReadiness {
                admitting: false,
                active_calls: 0,
                report: proto::ReadinessReport {
                    live: true,
                    ready: true,
                    target: f.registration.binding.target.clone(),
                    observed_at_unix_us: 1_788_500_000_000_000,
                    config_hash: f.registration.binding.config_hash.clone(),
                    runtime_manifest_hash: f
                        .registration
                        .configuration
                        .runtime_manifest_hash
                        .clone(),
                    process_instance_id: f.registration.binding.process_instance_id.clone(),
                    checks: (1..=9)
                        .map(|id| proto::ReadinessCheck {
                            id,
                            status: 2,
                            reason: 1,
                        })
                        .collect(),
                    stages: vec![],
                    launch_context_hash: f.registration.binding.launch_context_hash.clone(),
                },
            },
            &|| Ok(()),
        )
        .unwrap();
    f.store
        .select_candidate_checked(&f.lease, &f.registration.binding, id, &|| Ok(()))
        .unwrap();
    renew(f, 3, None, false)
}

fn serving(f: &Fixture) {
    let g = selected(f);
    renew(f, 4, Some(&g), true);
}

#[test]
fn applied_serving_reserves_once_and_exact_retry_recovers_original() {
    let f = Fixture::new();
    serving(&f);
    let input = request(&f);
    let first = f
        .store
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    let replica = PostgresProxyStore::connect(&f.url).unwrap();
    let retry = replica
        .reserve_managed_call_checked(&input, &|| Ok(()))
        .unwrap();
    assert_eq!(first.admission_id, retry.admission_id);
    assert_eq!(first.expires_at_unix_us, retry.expires_at_unix_us);
    assert_eq!(first.policy_revision, input.policy_revision);
    assert!(
        retry.valid_for_us > 0
            && retry.valid_for_us <= first.valid_for_us
            && first.valid_for_us <= 10_000_000
    );
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_call_admissions", &[])
            .unwrap()
            .get::<_, i64>(0),
        1
    );
}

#[test]
fn selected_mode_without_current_applied_serve_is_not_call_permission() {
    let f = Fixture::new();
    selected(&f);
    assert!(
        f.store
            .reserve_managed_call_checked(&request(&f), &|| Ok(()))
            .is_err()
    );
}
