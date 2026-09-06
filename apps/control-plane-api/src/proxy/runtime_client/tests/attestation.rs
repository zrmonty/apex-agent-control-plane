use super::*;

const INSTALLATION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1009";
fn attested_response(request: &proto::RuntimeReconcileRequest) -> proto::RuntimeReconcileResponse {
    let mut launch = proto::RuntimeLaunchContext {
        schema_version: 1,
        target: request.target.clone(),
        config_hash: request.config_hash.clone(),
        runtime_manifest_hash: "b".repeat(64),
        image_ref: format!("example.invalid/gateway@sha256:{}", "c".repeat(64)),
        process_instance_id: "0191b7f1-7f2c-7c13-9a61-2f29f2be1008".into(),
        health: Some(proto::RuntimeHealthBinding {
            port: 8081,
            credential_ref: "secret://runtime/material-1".into(),
        }),
        materials: (1..=13)
            .map(|role| proto::RuntimeMaterialBinding {
                role,
                reference: format!("secret://runtime/material-{role}"),
                version: "v1".into(),
            })
            .collect(),
        authority_profile_ref: "authority-1".into(),
        authority_profile_version: "v1".into(),
        ..Default::default()
    };
    launch.launch_context_hash = super::super::attestation::launch_hash(&launch).unwrap();
    proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::NotServing as i32,
        runtime: Some(proto::RuntimeObservation {
            target: request.target.clone(),
            runtime_id: "a".repeat(64),
            state: "not-serving".into(),
            observed_at_unix_us: 1,
            launch_attestation: Some(proto::RuntimeLaunchAttestation {
                schema_version: 1,
                installation_id: INSTALLATION.into(),
                launch: Some(launch),
                instance_proof_sha256: "d".repeat(64),
                staged_manifest_sha256: "e".repeat(64),
                image_id: format!("sha256:{}", "f".repeat(64)),
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn attestation_integrity_preserves_original_launch_and_checks_expected_installation() {
    let mut request = request();
    let good = attested_response(&request);
    validate_response(&request, &good, proto::ProxyDesiredState::Serving).unwrap();
    validate_installation(&good, INSTALLATION).unwrap();
    assert!(validate_installation(&good, "0191b7f1-7f2c-7c13-9a61-2f29f2be1007").is_err());
    // A higher lease fence cannot rewrite immutable installed launch evidence.
    request.target.as_mut().unwrap().fencing_token += 1;
    let mut adopted = good.clone();
    adopted.claims = Some(request.clone());
    validate_response(&request, &adopted, proto::ProxyDesiredState::Serving).unwrap();
    assert_ne!(adopted.runtime.as_ref().unwrap().target, request.target);
    for mutation in 0..12 {
        let mut bad = adopted.clone();
        let attestation = bad
            .runtime
            .as_mut()
            .unwrap()
            .launch_attestation
            .as_mut()
            .unwrap();
        match mutation {
            0 => attestation.schema_version = 2,
            1 => attestation.installation_id = "body-selected".into(),
            2 => attestation.instance_proof_sha256 = "raw-proof".into(),
            3 => attestation.staged_manifest_sha256.clear(),
            4 => attestation.image_id = "mutable:tag".into(),
            5 => attestation.launch = None,
            6 => {
                attestation.launch.as_mut().unwrap().process_instance_id = "not-an-instance".into()
            }
            7 => attestation.launch.as_mut().unwrap().launch_context_hash = "0".repeat(64),
            8 => attestation.launch.as_mut().unwrap().target = request.target.clone(),
            9 => attestation.launch.as_mut().unwrap().materials.clear(),
            10 => {
                attestation
                    .launch
                    .as_mut()
                    .unwrap()
                    .health
                    .as_mut()
                    .unwrap()
                    .port = 9999
            }
            11 => attestation.launch.as_mut().unwrap().config_hash = "0".repeat(64),
            _ => unreachable!(),
        }
        assert!(
            validate_response(&request, &bad, proto::ProxyDesiredState::Serving).is_err(),
            "mutation {mutation}"
        );
    }
    // This is wire/integrity component evidence, not enrollment or registration.
}

#[test]
fn malformed_installed_attestation_cannot_pass_authenticated_response_validation() {
    let request = request();
    let response = proto::RuntimeReconcileResponse {
        schema_version: 1,
        claims: Some(request.clone()),
        observed_state: proto::ProxyObservedState::NotServing as i32,
        runtime: Some(proto::RuntimeObservation {
            target: request.target.clone(),
            runtime_id: "a".repeat(64),
            state: "not-serving".into(),
            observed_at_unix_us: 1,
            launch_attestation: Some(proto::RuntimeLaunchAttestation {
                schema_version: 99,
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(
        validate_response(&request, &response, proto::ProxyDesiredState::Serving).is_err(),
        "malformed new evidence cannot be silently accepted alongside valid old fields"
    );
}

#[test]
fn attestation_material_roles_are_a_set_but_immutable_hash_preserves_array_order() {
    let mut request = request();
    let mut good = attested_response(&request);
    let launch = good
        .runtime
        .as_mut()
        .unwrap()
        .launch_attestation
        .as_mut()
        .unwrap()
        .launch
        .as_mut()
        .unwrap();
    launch.materials.swap(0, 12);
    launch.launch_context_hash = super::super::attestation::launch_hash(launch).unwrap();
    validate_response(&request, &good, proto::ProxyDesiredState::Serving).unwrap();
    request.target.as_mut().unwrap().fencing_token += 1;
    good.claims = Some(request.clone());
    validate_response(&request, &good, proto::ProxyDesiredState::Serving).unwrap();
    for mutation in 0..4 {
        let mut bad = good.clone();
        let launch = bad
            .runtime
            .as_mut()
            .unwrap()
            .launch_attestation
            .as_mut()
            .unwrap()
            .launch
            .as_mut()
            .unwrap();
        match mutation {
            0 => launch.materials.swap(0, 1), // Original hash must now fail.
            1 => launch.materials[0].role = launch.materials[1].role,
            2 => launch.materials[0].role = 99,
            3 => {
                launch.health.as_mut().unwrap().credential_ref =
                    launch.materials[0].reference.clone()
            }
            _ => unreachable!(),
        }
        // Generated ProtoJSON refuses unknown enum99 before hash serialization.
        if mutation != 0 && mutation != 2 {
            launch.launch_context_hash = super::super::attestation::launch_hash(launch).unwrap();
        }
        assert!(
            validate_response(&request, &bad, proto::ProxyDesiredState::Serving).is_err(),
            "mutation {mutation}"
        );
    }
}
