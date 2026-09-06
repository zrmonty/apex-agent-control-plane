use super::*;
use prost::Message;
use sha2::{Digest, Sha256};

const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
const INSTANCE: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e02";
const OPERATION: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e05";
const COMMAND: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e06";
const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GENERATION: u64 = 9_007_199_254_740_993;
const FENCE: u64 = 9_007_199_254_740_995;

fn config() -> AuthorityClientConfig {
    AuthorityClientConfig {
        endpoint: "https://unused.invalid".into(),
        tls_server_name: "unused.invalid".into(),
        ca_pem: vec![],
        client_certificate_pem: vec![],
        client_key_pem: vec![],
        installation_id: INSTALL.into(),
        agent_identity_id: "client-agent".into(),
        enrollment_version: "enrollment-1".into(),
        host_policy_version: "host-1".into(),
    }
}
fn target() -> proto::RuntimeTarget {
    proto::RuntimeTarget {
        workspace_id: "work".into(),
        namespace_id: "ns".into(),
        proxy_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03".into(),
        revision_id: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04".into(),
        generation: GENERATION,
        fencing_token: FENCE,
    }
}
fn operation(target: &proto::RuntimeTarget) -> AuthorityOperation<'_> {
    AuthorityOperation {
        target,
        operation_id: OPERATION,
        command_id: COMMAND,
        config_hash: HASH,
    }
}
fn attestation() -> proto::RuntimeLaunchAttestation {
    let mut original = target();
    original.fencing_token -= 2;
    proto::RuntimeLaunchAttestation {
        schema_version: 1,
        installation_id: INSTALL.into(),
        instance_proof_sha256: "b".repeat(64),
        staged_manifest_sha256: "c".repeat(64),
        image_id: format!("sha256:{}", "d".repeat(64)),
        launch: Some(proto::RuntimeLaunchContext {
            schema_version: 1,
            target: Some(original),
            config_hash: HASH.into(),
            runtime_manifest_hash: "e".repeat(64),
            image_ref: format!("example.test/runtime@sha256:{HASH}"),
            process_instance_id: INSTANCE.into(),
            health: Some(proto::RuntimeHealthBinding {
                port: 8081,
                credential_ref: "secret://managed/material-1".into(),
            }),
            materials: (1..=13)
                .map(|role| proto::RuntimeMaterialBinding {
                    role,
                    reference: format!("secret://managed/material-{role}"),
                    version: "v1".into(),
                })
                .collect(),
            launch_context_hash: "f".repeat(64),
            authority_profile_ref: "profile:read".into(),
            authority_profile_version: "v1".into(),
        }),
    }
}
fn receipt() -> proto::RuntimeDeploymentRegistrationReceipt {
    // Hand-authored original binding and CURRENT snapshot, not copied from RPC.
    let mut original = target();
    original.fencing_token = 9_007_199_254_740_993;
    proto::RuntimeDeploymentRegistrationReceipt {
        binding: Some(proto::ManagedDeploymentBinding {
            installation_id: INSTALL.into(),
            target: Some(original),
            process_instance_id: INSTANCE.into(),
            config_hash: HASH.into(),
            launch_context_hash: "f".repeat(64),
        }),
        attestation_sha256: format!("{:x}", Sha256::digest(attestation().encode_to_vec())),
        authority: Some(proto::RuntimeAuthoritySnapshot {
            schema_version: 1,
            target: Some(target()),
            operation_id: OPERATION.into(),
            command_id: COMMAND.into(),
            action: 1,
            installation_id: INSTALL.into(),
            agent_identity_id: "client-agent".into(),
            observed_controller_identity_id: "client-controller".into(),
            peer_policy_version: "client-policy".into(),
            enrollment_version: "enrollment-1".into(),
            host_policy_version: "host-1".into(),
            desired_state: 1,
            observed_state: 1,
            config_hash: HASH.into(),
            checked_at_unix_us: GENERATION,
            lease_expires_at_unix_us: GENERATION + 10_000_000,
        }),
    }
}
fn validate(
    reply: &proto::RuntimeDeploymentRegistrationReceipt,
    elapsed: Duration,
) -> Result<(), Error> {
    validate_receipt(
        reply,
        &attestation(),
        &config(),
        &operation(&target()),
        "client-controller",
        "client-policy",
        elapsed,
    )
}

#[test]
fn exact_receipt_retry_preserves_original_binding_and_large_current_authority() {
    let reply = receipt();
    assert_eq!(validate(&reply, Duration::ZERO), Ok(()));
    assert_eq!(validate(&reply, Duration::from_millis(1)), Ok(()));
    assert_eq!(
        reply
            .binding
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .fencing_token,
        FENCE - 2
    );
    assert_eq!(
        reply
            .authority
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .fencing_token,
        FENCE
    );
    assert_eq!(
        reply
            .authority
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap()
            .generation,
        GENERATION
    );
}

#[test]
fn every_receipt_identity_hash_and_current_snapshot_binding_is_required() {
    let changes: &[fn(&mut proto::RuntimeDeploymentRegistrationReceipt)] = &[
        |r| r.binding = None,
        |r| r.binding.as_mut().unwrap().target = None,
        |r| r.binding.as_mut().unwrap().installation_id = INSTANCE.into(),
        |r| r.binding.as_mut().unwrap().process_instance_id = INSTALL.into(),
        |r| r.binding.as_mut().unwrap().config_hash = "b".repeat(64),
        |r| r.binding.as_mut().unwrap().launch_context_hash = "b".repeat(64),
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .workspace_id = "other".into()
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .namespace_id = "other".into()
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .proxy_id = INSTANCE.into()
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .revision_id = INSTANCE.into()
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .generation += 1
        },
        |r| {
            r.binding
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token = FENCE
        },
        |r| r.attestation_sha256 = "b".repeat(64),
        |r| r.attestation_sha256 = r.attestation_sha256.to_uppercase(),
        |r| {
            r.attestation_sha256 = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&attestation()).unwrap())
            )
        },
        |r| r.authority = None,
        |r| r.authority.as_mut().unwrap().schema_version = 0,
        |r| r.authority.as_mut().unwrap().action = 99,
        |r| r.authority.as_mut().unwrap().target = None,
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token = FENCE - 2
        },
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .generation += 1
        },
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .workspace_id = "other".into()
        },
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .namespace_id = "other".into()
        },
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .proxy_id = INSTANCE.into()
        },
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .revision_id = INSTANCE.into()
        },
        |r| r.authority.as_mut().unwrap().operation_id = INSTANCE.into(),
        |r| r.authority.as_mut().unwrap().command_id = INSTANCE.into(),
        |r| r.authority.as_mut().unwrap().installation_id = INSTANCE.into(),
        |r| r.authority.as_mut().unwrap().agent_identity_id = "other".into(),
        |r| {
            r.authority
                .as_mut()
                .unwrap()
                .observed_controller_identity_id = "other".into()
        },
        |r| r.authority.as_mut().unwrap().peer_policy_version = "other".into(),
        |r| r.authority.as_mut().unwrap().enrollment_version = "other".into(),
        |r| r.authority.as_mut().unwrap().host_policy_version = "other".into(),
        |r| r.authority.as_mut().unwrap().config_hash = "b".repeat(64),
        |r| r.authority.as_mut().unwrap().desired_state = 0,
        |r| r.authority.as_mut().unwrap().observed_state = 99,
        |r| r.authority.as_mut().unwrap().checked_at_unix_us = 0,
        |r| r.authority.as_mut().unwrap().lease_expires_at_unix_us = GENERATION,
        |r| r.attestation_sha256 = "private-canary".repeat(2048),
    ];
    for (index, change) in changes.iter().enumerate() {
        let mut reply = receipt();
        change(&mut reply);
        let error = validate(&reply, Duration::ZERO).unwrap_err();
        assert!(
            !format!("{error:?}").contains("private-canary"),
            "case {index}"
        );
    }
}

#[test]
fn original_launch_input_must_be_bounded_and_match_current_operation_except_fence() {
    let mutations: &[fn(&mut proto::RuntimeLaunchAttestation)] = &[
        |a| a.schema_version = 0,
        |a| a.installation_id = INSTANCE.into(),
        |a| a.instance_proof_sha256 = "B".repeat(64),
        |a| a.staged_manifest_sha256 = "c".repeat(63),
        |a| a.image_id = HASH.into(),
        |a| a.launch = None,
        |a| a.launch.as_mut().unwrap().schema_version = 0,
        |a| a.launch.as_mut().unwrap().target = None,
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .generation = 0
        },
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .generation = u64::MAX
        },
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token = 0
        },
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .fencing_token = FENCE + 1
        },
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .target
                .as_mut()
                .unwrap()
                .workspace_id = "other".into()
        },
        |a| a.launch.as_mut().unwrap().config_hash = "b".repeat(64),
        |a| a.launch.as_mut().unwrap().process_instance_id = "not-uuid".into(),
        |a| a.launch.as_mut().unwrap().launch_context_hash = "f".repeat(63),
        |a| a.launch.as_mut().unwrap().runtime_manifest_hash = "e".repeat(63),
        |a| a.launch.as_mut().unwrap().image_ref = "not-pinned".into(),
        |a| a.launch.as_mut().unwrap().authority_profile_ref = "a".repeat(129),
        |a| a.launch.as_mut().unwrap().authority_profile_version = "..".into(),
        |a| a.launch.as_mut().unwrap().health = None,
        |a| a.launch.as_mut().unwrap().health.as_mut().unwrap().port = 8082,
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .health
                .as_mut()
                .unwrap()
                .credential_ref = "secret://other".into()
        },
        |a| {
            a.launch
                .as_mut()
                .unwrap()
                .materials
                .pop()
                .map(|_| ())
                .unwrap()
        },
        |a| a.launch.as_mut().unwrap().materials[1].role = 1,
        |a| a.launch.as_mut().unwrap().materials[1].role = 99,
        |a| {
            a.launch.as_mut().unwrap().materials[1].reference = "secret://managed/material-1".into()
        },
        |a| a.launch.as_mut().unwrap().materials[1].reference = "secret://managed/../bad".into(),
        |a| a.launch.as_mut().unwrap().materials[1].version = "".into(),
        |a| a.staged_manifest_sha256 = "private-canary".repeat(2048),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut value = attestation();
        mutate(&mut value);
        assert_eq!(
            validate_input(&value, &config(), &operation(&target())),
            Err(Error::InvalidInput),
            "case {index}"
        );
    }
    for fence in [1, FENCE - 2, FENCE] {
        let mut value = attestation();
        value
            .launch
            .as_mut()
            .unwrap()
            .target
            .as_mut()
            .unwrap()
            .fencing_token = fence;
        assert_eq!(
            validate_input(&value, &config(), &operation(&target())),
            Ok(())
        );
    }
}

#[test]
fn reply_validity_uses_original_elapsed_with_exact_integer_microseconds() {
    let mut reply = receipt();
    reply.authority.as_mut().unwrap().lease_expires_at_unix_us = GENERATION + 1;
    assert_eq!(validate(&reply, Duration::from_nanos(999)), Ok(()));
    assert_eq!(
        validate(&reply, Duration::from_nanos(1000)),
        Err(Error::InvalidSnapshot)
    );
    assert_eq!(
        validate(&reply, Duration::from_nanos(1001)),
        Err(Error::InvalidSnapshot)
    );
}

#[tokio::test]
async fn whole_budget_catches_the_last_ready_poll_and_never_restarts_elapsed() {
    let started = Instant::now();
    let result = await_reply(started, Duration::from_millis(1), async {
        // Deliberately synchronous last poll: timeout_at alone returns Ok.
        std::thread::sleep(Duration::from_millis(10));
        Ok(receipt())
    })
    .await;
    assert_eq!(result.unwrap_err(), Error::Deadline);
    let expired = Instant::now() - Duration::from_millis(20);
    assert_eq!(
        await_reply(expired, Duration::from_millis(10), async {
            panic!("expired work must not poll")
        })
        .await
        .unwrap_err(),
        Error::Deadline
    );
}

mod server;
mod support;
mod transport;
