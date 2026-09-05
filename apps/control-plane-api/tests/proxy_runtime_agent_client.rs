#![cfg(feature = "postgres")]
//! Real production control root + PostgreSQL + separately compiled agent client.
//! The probe supplies test-only controller ingress, never a provisioning service.
#[allow(dead_code)]
#[path = "proxy_runtime_authority/material.rs"]
mod material;
#[allow(dead_code)]
#[path = "proxy_runtime_operation/support.rs"]
mod operation;
#[allow(dead_code)]
#[path = "../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
#[path = "proxy_runtime_agent_client/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "proxy_operation_recovery/support.rs"]
mod recovery;
#[path = "proxy_runtime_agent_client/root.rs"]
mod root;
#[allow(dead_code)]
#[path = "proxy_runtime_authority/transport.rs"]
mod transport;

use apex_control_plane_api::proto::{CheckRuntimeAuthorityRequest, RuntimeAuthoritySnapshot};
use operation::Fixture;

#[test]
fn actual_agent_client_checks_production_root_and_current_postgres_lease() {
    let fixture = Fixture::new(true);
    settle_evidence(&fixture);
    let before = fixture.bytes();
    let pki = pki::Pki::require();
    let materials = material::Materials::new(&fixture, &pki);
    let root = root::Root::start(&fixture, &pki, &materials);
    let mut request = CheckRuntimeAuthorityRequest {
        schema_version: 1,
        target: Some(fixture.target.clone()),
        operation_id: fixture.operation.operation_id.clone(),
        command_id: uuid::Uuid::now_v7().to_string(),
        action: 1,
        installation_id: material::INSTALLATION.into(),
        // Deliberately forged body pin: actual Controller TLS must replace it.
        observed_controller_certificate_sha256: vec![0xA5; 32],
    };
    let checked_before = operation::database_now(&mut fixture.client());
    let mut direct = request.clone();
    direct.observed_controller_certificate_sha256 = pki.pin(pki::CONTROLLER).to_vec();
    assert_eq!(
        root.direct(&pki, direct).config_hash,
        fixture.revision.config_hash,
        "real root/PG positive control before the client under test"
    );
    let result = root.probe(
        &materials,
        &request,
        &fixture.revision.config_hash,
        "controller",
    );
    let checked_after = operation::database_now(&mut fixture.client());
    let snapshot: RuntimeAuthoritySnapshot = serde_json::from_value(
        result
            .get("snapshot")
            .expect("real callback must return a snapshot")
            .clone(),
    )
    .unwrap();
    assert_eq!(snapshot.target, request.target);
    assert_eq!(snapshot.operation_id, fixture.operation.operation_id);
    assert_eq!(snapshot.command_id, request.command_id);
    assert_eq!(snapshot.schema_version, 1);
    assert_eq!(snapshot.action, 1);
    assert_eq!(snapshot.installation_id, material::INSTALLATION);
    assert_eq!(snapshot.agent_identity_id, "live-agent");
    assert_eq!(snapshot.observed_controller_identity_id, "live-controller");
    assert_eq!(snapshot.peer_policy_version, "live-policy-1");
    assert_eq!(snapshot.enrollment_version, "live-enrollment-1");
    assert_eq!(snapshot.host_policy_version, "live-host-policy-1");
    assert_eq!(snapshot.config_hash, fixture.revision.config_hash);
    assert_eq!(snapshot.desired_state, fixture.operation.desired_state);
    assert_eq!(snapshot.observed_state, fixture.operation.observed_state);
    assert!((checked_before..=checked_after).contains(&snapshot.checked_at_unix_us));
    assert_eq!(
        snapshot.lease_expires_at_unix_us,
        fixture.lease.as_ref().unwrap().lease_expires_at_micros
    );
    assert_unchanged(fixture.bytes(), &before);

    request.target.as_mut().unwrap().fencing_token += 1;
    root::assert_refusal(
        root.probe(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "controller",
        ),
        "RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL",
    );
    request.target.as_mut().unwrap().fencing_token -= 1;
    root::assert_refusal(
        root.probe(&materials, &request, &fixture.revision.config_hash, "agent"),
        "RUNTIME_AUTHORITY_CLIENT_DENIED",
    );
    assert!(
        root.probe(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "controller"
        )
        .get("snapshot")
        .is_some(),
        "healthy follow-up after both specific refusals"
    );
    assert_unchanged(fixture.bytes(), &before);

    fixture.expired_at_database_edge();
    let expired = fixture.bytes();
    root::assert_refusal(
        root.probe(
            &materials,
            &request,
            &fixture.revision.config_hash,
            "controller",
        ),
        "RUNTIME_AUTHORITY_CLIENT_REMOTE_REFUSAL",
    );
    assert_unchanged(fixture.bytes(), &expired);
    root.finish();
}

fn settle_evidence(fixture: &Fixture) {
    // The actual root runs its evidence relay independently of the callback.
    // Deliver the fixture's existing intent to its real durable outbox before
    // taking the byte baseline; do not disable the worker or weaken comparison.
    let outbox = apex_control_plane_api::ControlOutboxBackend::new(Box::new(
        apex_control_plane_api::RecoveringPostgresOutbox::connect(&fixture.database.url, 100)
            .unwrap(),
    ));
    assert_eq!(
        fixture
            .store
            .relay_proxy_evidence(&fixture.input.scope, &fixture.input.proxy_id, &outbox, 16,)
            .unwrap(),
        1,
    );
    assert_eq!(outbox.pending_batch(16).unwrap().len(), 1);
}

fn assert_unchanged(actual: Vec<(String, Vec<String>)>, expected: &[(String, Vec<String>)]) {
    assert_eq!(actual.len(), expected.len());
    for ((table, rows), (expected_table, expected_rows)) in actual.iter().zip(expected) {
        assert_eq!(table, expected_table);
        // Report the fixed table name only, never row values or secret references.
        assert!(
            rows == expected_rows,
            "read-only callback changed table {table}"
        );
    }
}
