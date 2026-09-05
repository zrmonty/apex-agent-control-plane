use crate::{
    material::{INSTALLATION, Materials},
    operation::Fixture,
    pki::{self, Pki},
    transport,
};
use apex_control_plane_api::proto::{CheckRuntimeAuthorityRequest, RuntimeAuthorityAction};
use prost::Message;

pub(super) fn request(fixture: &Fixture, pki: &Pki) -> CheckRuntimeAuthorityRequest {
    CheckRuntimeAuthorityRequest {
        schema_version: 1,
        target: Some(fixture.target.clone()),
        operation_id: fixture.operation.operation_id.clone(),
        command_id: uuid::Uuid::now_v7().to_string(),
        action: RuntimeAuthorityAction::CheckCurrentOperation as i32,
        installation_id: INSTALLATION.into(),
        observed_controller_certificate_sha256: pki.pin(pki::CONTROLLER).to_vec(),
    }
}

#[test]
fn actual_pg_refuses_noncurrent_claims_and_explicit_healthy_followup_succeeds() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let mut owner = materials.owner(&fixture.database.url);
    let service = owner.start().unwrap();
    let valid = request(&fixture, &pki);
    transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let mut client = transport::client(&pki, &endpoint, pki::AGENT).await;
        transport::within(client.check_runtime_authority(valid.clone()))
            .await
            .expect("healthy control");
        for case in 0..4 {
            let mut wrong = valid.clone();
            match case {
                0 => wrong.target.as_mut().unwrap().fencing_token += 1,
                1 => wrong.operation_id = uuid::Uuid::now_v7().to_string(),
                2 => wrong.target.as_mut().unwrap().revision_id = uuid::Uuid::now_v7().to_string(),
                _ => wrong.target.as_mut().unwrap().generation += 1,
            }
            let error = transport::within(client.check_runtime_authority(wrong))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert_eq!(error.message(), "PROXY_RUNTIME_OPERATION_NOT_CURRENT");
            assert!(error.details().is_empty());
        }
        transport::within(client.check_runtime_authority(valid))
            .await
            .expect("healthy after refused lookups");
    });
    assert!(owner.shutdown().cleanup_complete);
    assert_eq!(fixture.bytes(), before);
}

#[test]
fn actual_agent_tls_and_current_published_pg_return_only_the_safe_snapshot() {
    let fixture = Fixture::new(true);
    let database = fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let materials = Materials::new(&fixture, &pki);
    let mut owner = materials.owner(&fixture.database.url);
    let service = owner
        .start()
        .expect("actual policy reader and PG owner required");
    let query = request(&fixture, &pki);
    let expected = query.clone();
    let outcome = transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let mut client = transport::client(&pki, &endpoint, pki::AGENT).await;
        transport::within(client.check_runtime_authority(query)).await
    });
    assert!(owner.shutdown().cleanup_complete);
    let snapshot = outcome
        .expect("otherwise valid real TLS/PG callback must succeed")
        .into_inner();
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.target, expected.target);
    assert_eq!(snapshot.operation_id, expected.operation_id);
    assert_eq!(snapshot.command_id, expected.command_id);
    assert_eq!(snapshot.action, expected.action);
    assert_eq!(snapshot.installation_id, INSTALLATION);
    assert_eq!(snapshot.agent_identity_id, "live-agent");
    assert_eq!(snapshot.observed_controller_identity_id, "live-controller");
    assert_eq!(snapshot.peer_policy_version, "live-policy-1");
    assert_eq!(snapshot.enrollment_version, "live-enrollment-1");
    assert_eq!(snapshot.host_policy_version, "live-host-policy-1");
    assert_eq!(snapshot.desired_state, database.operation.desired_state);
    assert_eq!(snapshot.observed_state, database.operation.observed_state);
    assert_eq!(snapshot.config_hash, database.revision.config_hash);
    assert!(snapshot.checked_at_unix_us >= database.checked_at_unix_us);
    assert_eq!(
        snapshot.lease_expires_at_unix_us,
        database.lease_expires_at_unix_us
    );
    assert!(snapshot.checked_at_unix_us < snapshot.lease_expires_at_unix_us);
    assert!(snapshot.encoded_len() <= 4096);
    let json = serde_json::to_value(&snapshot).unwrap();
    assert!(json["checkedAtUnixUs"].is_string());
    assert!(json["leaseExpiresAtUnixUs"].is_string());
    for forbidden in [
        "SNAPSHOT_CANARY",
        "controller-a",
        "certificateSha256",
        "workerId",
        "spec",
    ] {
        assert!(!json.to_string().contains(forbidden));
    }
    assert_eq!(
        fixture.bytes(),
        before,
        "all seven application tables unchanged"
    );
}

#[test]
fn actual_wrong_role_or_scope_refuses_before_an_otherwise_valid_pg_snapshot() {
    let fixture = Fixture::new(true);
    fixture.positive();
    let before = fixture.bytes();
    let pki = Pki::require();
    let mut materials = Materials::new(&fixture, &pki);
    let mut owner = materials.owner(&fixture.database.url);
    let service = owner.start().unwrap();
    #[cfg(feature = "test-support")]
    let witness = owner.observations();
    let valid = request(&fixture, &pki);
    let results = transport::exercise(service, &pki, move |endpoint| async move {
        let pki = Pki::require();
        let mut agent = transport::client(&pki, &endpoint, pki::AGENT).await;
        transport::within(agent.check_runtime_authority(valid.clone()))
            .await
            .expect("positive TLS/PG control");
        #[cfg(feature = "test-support")]
        assert_eq!(crate::observer::counts(&witness, 3, 1).await, [1; 4]);
        let mut controller = transport::client(&pki, &endpoint, pki::CONTROLLER).await;
        let wrong_role = transport::within(controller.check_runtime_authority(valid.clone())).await;
        #[cfg(feature = "test-support")]
        assert_eq!(
            witness.counts(),
            [1; 4],
            "wrong TLS role never enters the PG queue"
        );
        // Keep the valid published target unchanged; remove that scope from the
        // deployment grant so a speculative PG read would otherwise succeed.
        materials.peer["version"] = "live-policy-2".into();
        materials.peer["peers"][0]["grants"][0]["namespaceId"] = "other-namespace".into();
        materials.enrollment["peerPolicyVersion"] = "live-policy-2".into();
        materials.enrollment["version"] = "live-enrollment-2".into();
        materials.write();
        crate::refresh::wait_for_refusal(
            &mut agent,
            &valid,
            tonic::Code::PermissionDenied,
            "RUNTIME_PEER_DENIED",
        )
        .await;
        // Refresh polling may have dispatched while the prior grant was still
        // current. Establish a settled baseline after the new grant is observed.
        #[cfg(feature = "test-support")]
        let baseline = crate::observer::counts(&witness, 3, witness.counts()[0]).await;
        let wrong_scope = transport::within(agent.check_runtime_authority(valid.clone())).await;
        #[cfg(feature = "test-support")]
        assert_eq!(
            witness.counts(),
            baseline,
            "wrong scope never enters the PG queue"
        );
        materials.peer["version"] = "live-policy-3".into();
        materials.peer["peers"][0]["grants"][0]["namespaceId"] =
            valid.target.as_ref().unwrap().namespace_id.clone().into();
        materials.enrollment["peerPolicyVersion"] = "live-policy-3".into();
        materials.enrollment["version"] = "live-enrollment-3".into();
        materials.write();
        crate::refresh::wait_for_version(&mut agent, &valid, "live-enrollment-3").await;
        let recovered = transport::within(agent.check_runtime_authority(valid)).await;
        (wrong_role, wrong_scope, recovered)
    });
    assert!(owner.shutdown().cleanup_complete);
    for result in [results.0, results.1] {
        let error = result.expect_err("role/scope refusal");
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert_eq!(error.message(), "RUNTIME_PEER_DENIED");
        assert!(error.details().is_empty());
    }
    results
        .2
        .expect("same healthy channel after refused claims");
    assert_eq!(fixture.bytes(), before);
}
