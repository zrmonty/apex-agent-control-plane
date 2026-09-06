//! Trusted metadata fixture, not agent authentication or launch validation.
use super::*;
use sha2::{Digest, Sha256};

fn evidence(
    f: &Fixture,
) -> (
    proto::RuntimeLaunchAttestation,
    proto::RuntimeAuthoritySnapshot,
) {
    let b = &f.registration.binding;
    (
        proto::RuntimeLaunchAttestation {
            schema_version: 1,
            installation_id: b.installation_id.clone(),
            launch: Some(proto::RuntimeLaunchContext {
                schema_version: 1,
                target: b.target.clone(),
                process_instance_id: b.process_instance_id.clone(),
                config_hash: b.config_hash.clone(),
                launch_context_hash: b.launch_context_hash.clone(),
                ..Default::default()
            }),
            instance_proof_sha256: "07".repeat(32),
            staged_manifest_sha256: "c".repeat(64),
            image_id: format!("sha256:{}", "d".repeat(64)),
        },
        proto::RuntimeAuthoritySnapshot {
            schema_version: 1,
            target: b.target.clone(),
            installation_id: b.installation_id.clone(),
            operation_id: f.lease.operation.operation_id.clone(),
            agent_identity_id: "agent-a".into(),
            config_hash: b.config_hash.clone(),
            ..Default::default()
        },
    )
}

#[test]
fn attested_registration_is_atomic_durable_and_exact_retries_preserve_first_provenance() {
    let f = Fixture::new();
    let (attestation, mut authority) = evidence(&f);
    let hash = f
        .store
        .register_attested_deployment_checked(
            &f.lease,
            &f.registration,
            &attestation,
            &authority,
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(
        hash,
        format!("{:x}", Sha256::digest(attestation.encode_to_vec()))
    );
    let read = || {
        f.client()
            .query_one(
                "SELECT attestation_bytes,authority_bytes FROM mcp_proxy_deployment_attestations",
                &[],
            )
            .unwrap()
    };
    let original = read().get::<_, Vec<u8>>(1);
    assert_eq!(read().get::<_, Vec<u8>>(0), attestation.encode_to_vec());
    authority.peer_policy_version = "rotated-policy".into();
    let restarted = PostgresProxyStore::connect(&f.url).unwrap();
    assert_eq!(
        restarted
            .register_attested_deployment_checked(
                &f.lease,
                &f.registration,
                &attestation,
                &authority,
                &|| Ok(())
            )
            .unwrap(),
        hash
    );
    assert_eq!(read().get::<_, Vec<u8>>(1), original);
    let mut changed = attestation.clone();
    changed.staged_manifest_sha256 = "e".repeat(64);
    assert!(
        restarted
            .register_attested_deployment_checked(
                &f.lease,
                &f.registration,
                &changed,
                &authority,
                &|| Ok(())
            )
            .is_err()
    );
    assert_eq!(read().get::<_, Vec<u8>>(0), attestation.encode_to_vec());
    assert_eq!(
        f.client()
            .query_one("SELECT count(*) FROM mcp_proxy_grant_decisions", &[])
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(
        f.client()
            .batch_execute(
                "UPDATE mcp_proxy_deployment_attestations SET attestation_bytes='bad'::bytea"
            )
            .is_err()
    );
    assert!(
        f.client()
            .batch_execute("DELETE FROM mcp_proxy_deployment_attestations")
            .is_err()
    );
}

#[test]
fn attested_registration_refuses_missing_provenance_on_an_existing_unattested_identity() {
    let f = Fixture::new();
    f.store
        .register_deployment_checked(&f.lease, &f.registration, &|| Ok(()))
        .unwrap();
    let (attestation, authority) = evidence(&f);
    assert!(
        f.store
            .register_attested_deployment_checked(
                &f.lease,
                &f.registration,
                &attestation,
                &authority,
                &|| Ok(())
            )
            .is_err()
    );
}

#[test]
fn attested_adoption_keeps_original_fence_and_unknown_old_first_registration_refuses() {
    let f = Fixture::new();
    let (attestation, mut authority) = evidence(&f);
    let hash = f
        .store
        .register_attested_deployment_checked(
            &f.lease,
            &f.registration,
            &attestation,
            &authority,
            &|| Ok(()),
        )
        .unwrap();
    f.client()
        .execute(
            "UPDATE mcp_proxy_controller_leases SET expires_at_micros=0",
            &[],
        )
        .unwrap();
    let key = BindingKey::new(&f.registration.binding).unwrap();
    let lease = f
        .store
        .lease_proxy_operation(
            &key.scope,
            &key.proxy,
            "controller-b",
            std::time::Duration::from_secs(300),
        )
        .unwrap()
        .unwrap();
    assert!(lease.fencing_token > f.lease.fencing_token);
    authority.target.as_mut().unwrap().fencing_token = lease.fencing_token;
    assert_eq!(
        f.store
            .register_attested_deployment_checked(
                &lease,
                &f.registration,
                &attestation,
                &authority,
                &|| Ok(())
            )
            .unwrap(),
        hash
    );
    let mut unknown = f.registration.clone();
    unknown.binding.process_instance_id = Uuid::now_v7().to_string();
    let mut unknown_attestation = attestation.clone();
    unknown_attestation
        .launch
        .as_mut()
        .unwrap()
        .process_instance_id = unknown.binding.process_instance_id.clone();
    assert!(
        f.store
            .register_attested_deployment_checked(
                &lease,
                &unknown,
                &unknown_attestation,
                &authority,
                &|| Ok(())
            )
            .is_err()
    );
    assert_eq!(
        f.client()
            .query_one(
                "SELECT count(*) FROM mcp_proxy_deployment_attestations",
                &[]
            )
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let stored = proto::RuntimeLaunchAttestation::decode(
        f.client()
            .query_one(
                "SELECT attestation_bytes FROM mcp_proxy_deployment_attestations",
                &[],
            )
            .unwrap()
            .get::<_, Vec<u8>>(0)
            .as_slice(),
    )
    .unwrap();
    assert_eq!(stored, attestation);
}
