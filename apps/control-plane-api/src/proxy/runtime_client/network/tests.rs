use super::*;
#[allow(dead_code, clippy::duplicate_mod)]
#[path = "../../../../../proxy-runtime-agent/tests/runtime_peer_pair/pki.rs"]
mod pki;
mod transport;

#[test]
fn network_request_cannot_select_another_installation_or_scope_or_malformed_identity() {
    let good = request();
    let mut config = RuntimeExecutionConfig::ownership_test_value();
    config.installation_id = good.binding.as_ref().unwrap().installation_id.clone();
    config.scopes = vec![crate::ExactScope {
        workspace_id: "workspace".into(),
        namespace_id: "namespace".into(),
    }];
    validate_request(&good, &config).unwrap();
    for mutation in 0..8 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.schema_version = 0,
            1 => bad.nonce.pop().map(|_| ()).unwrap(),
            2 => {
                bad.binding.as_mut().unwrap().installation_id =
                    "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e09".into()
            }
            3 => {
                bad.binding
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .namespace_id = "other".into()
            }
            4 => {
                bad.binding
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .generation = u64::MAX
            }
            5 => bad.binding.as_mut().unwrap().process_instance_id.clear(),
            6 => bad.binding.as_mut().unwrap().launch_context_hash = "B".repeat(64),
            7 => {
                bad.binding
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .workspace_id = "x".repeat(5000)
            }
            _ => unreachable!(),
        }
        assert!(
            validate_request(&bad, &config).is_err(),
            "mutation {mutation}"
        );
    }
}

fn request() -> proto::RuntimeNetworkInspectionRequest {
    proto::RuntimeNetworkInspectionRequest {
        schema_version: 1,
        binding: Some(proto::ManagedDeploymentBinding {
            installation_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
            target: Some(proto::RuntimeTarget {
                workspace_id: "workspace".into(),
                namespace_id: "namespace".into(),
                proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02".into(),
                revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
                generation: 9_007_199_254_740_993,
                fencing_token: 9_007_199_254_740_995,
            }),
            process_instance_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
            config_hash: "a".repeat(64),
            launch_context_hash: "b".repeat(64),
        }),
        nonce: vec![7; 32],
    }
}
fn response(
    input: &proto::RuntimeNetworkInspectionRequest,
) -> proto::RuntimeNetworkInspectionResponse {
    proto::RuntimeNetworkInspectionResponse {
        schema_version: 1,
        binding: input.binding.clone(),
        nonce: input.nonce.clone(),
        network_binding_sha256: "c".repeat(64),
        gateway_process_sha256: "d".repeat(64),
        guard_process_sha256: "e".repeat(64),
        valid_for_us: 10_000_000,
        confined: true,
    }
}

#[test]
fn network_reply_requires_exact_original_binding_nonce_and_confinement() {
    let request = request();
    let good = response(&request);
    validate_response(&request, &good, Duration::from_nanos(999)).unwrap();
    for change in 0..14 {
        let mut bad = good.clone();
        match change {
            0 => bad.schema_version = 0,
            1 => bad.nonce[0] ^= 1,
            2 => bad.binding = None,
            3 => bad.binding.as_mut().unwrap().installation_id = "other".into(),
            4 => bad.binding.as_mut().unwrap().process_instance_id = "other".into(),
            5 => {
                bad.binding
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .fencing_token += 1
            }
            6 => {
                bad.binding
                    .as_mut()
                    .unwrap()
                    .target
                    .as_mut()
                    .unwrap()
                    .generation += 1
            }
            7 => bad.binding.as_mut().unwrap().config_hash = "f".repeat(64),
            8 => bad.network_binding_sha256 = "C".repeat(64),
            9 => bad.gateway_process_sha256.clear(),
            10 => bad.guard_process_sha256 = "bad".into(),
            11 => bad.confined = false,
            12 => bad.valid_for_us = 0,
            13 => bad.valid_for_us = 10_000_001,
            _ => unreachable!(),
        }
        assert!(
            validate_response(&request, &bad, Duration::ZERO).is_err(),
            "mutation {change}"
        );
    }
}

#[test]
fn network_reply_original_microsecond_expiry_never_receives_a_new_clock() {
    let request = request();
    for lifetime in [1, 7, 999, 10_000_000] {
        let mut reply = response(&request);
        reply.valid_for_us = lifetime;
        let edge = Duration::from_micros(lifetime);
        validate_response(&request, &reply, edge - Duration::from_nanos(1)).unwrap();
        assert!(validate_response(&request, &reply, edge).is_err());
        assert!(validate_response(&request, &reply, edge + Duration::from_nanos(1)).is_err());
    }
}
