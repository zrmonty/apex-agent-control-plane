use super::*;
use crate::proxy::{ProxySpec, runtime_manifest_hash, store::published_config_hash};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const GENERATION: u64 = 9_007_199_254_740_993;
const INSTALLATION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1003";
const INSTANCE: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1004";

// Independent test encoder: BTreeMap provides canonical key order recursively;
// arrays remain in producer order. Never call the validator's hash helper.
fn canonical(value: &Value) -> String {
    match value {
        Value::Object(fields) => {
            let sorted: std::collections::BTreeMap<_, _> = fields.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| {
                        format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v))
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        scalar => scalar.to_string(),
    }
}

fn seal(attestation: &mut proto::RuntimeLaunchAttestation) {
    let launch = attestation.launch.as_mut().unwrap();
    let mut value = serde_json::to_value(&*launch).unwrap();
    value.as_object_mut().unwrap().remove("launchContextHash");
    launch.launch_context_hash = format!("{:x}", Sha256::digest(canonical(&value).as_bytes()));
}

fn fixture() -> (
    Value,
    proto::RuntimeLaunchAttestation,
    proto::RuntimeConfiguration,
) {
    let mut configuration: proto::RuntimeConfiguration =
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/fixtures/mcp-proxy/runtime-revision.json"
        )))
        .unwrap();
    configuration.generation = GENERATION;
    configuration.config_hash =
        published_config_hash(&ProxySpec::try_from(configuration.spec.clone().unwrap()).unwrap());
    configuration.runtime_manifest_hash = runtime_manifest_hash(&configuration).unwrap();
    let materials: Vec<_> = (1..=13)
        .map(|role| proto::RuntimeMaterialBinding {
            role,
            reference: format!("secret://managed/material-{role}"),
            version: "v1".into(),
        })
        .collect();
    let mut attestation = proto::RuntimeLaunchAttestation {
        schema_version: 1,
        installation_id: INSTALLATION.into(),
        instance_proof_sha256: "b".repeat(64),
        staged_manifest_sha256: "c".repeat(64),
        image_id: format!("sha256:{}", "d".repeat(64)),
        launch: Some(proto::RuntimeLaunchContext {
            schema_version: 1,
            target: Some(proto::RuntimeTarget {
                workspace_id: configuration.workspace_id.clone(),
                namespace_id: configuration.namespace_id.clone(),
                proxy_id: configuration.proxy_id.clone(),
                revision_id: configuration.revision_id.clone(),
                generation: GENERATION,
                fencing_token: 7,
            }),
            config_hash: configuration.config_hash.clone(),
            runtime_manifest_hash: configuration.runtime_manifest_hash.clone(),
            image_ref: configuration.image_ref.clone(),
            process_instance_id: INSTANCE.into(),
            health: Some(proto::RuntimeHealthBinding {
                port: 8081,
                credential_ref: materials[0].reference.clone(),
            }),
            materials,
            launch_context_hash: String::new(),
            authority_profile_ref: "profile:read".into(),
            authority_profile_version: "v1".into(),
        }),
    };
    seal(&mut attestation);
    let launch = attestation.launch.as_ref().unwrap();
    let document = json!({"schema_version":1,"version":"managed-v1","valid_from_unix_us":"1",
    "expires_at_unix_us":"9223372036854775807", "profiles":[{
        "installation_id":INSTALLATION,"workspace_id":configuration.workspace_id,"namespace_id":configuration.namespace_id,
        "proxy_id":configuration.proxy_id,"revision_id":configuration.revision_id,
        "authority_profile_ref":"profile:read","authority_profile_version":"v1","evidence_agent_id":"proxy-reader",
        "credentials":[{"certificate_sha256":"a".repeat(64),"token_sha256":"b".repeat(64)}],
        "launch":{"config_hash":configuration.config_hash,"host_policy_version":"host-v1","deployment_bindings_version":"bindings-v1",
            "image_ref":configuration.image_ref,"image_id":attestation.image_id,
            "materials":launch.materials.iter().map(|m| json!({
                "role":proto::RuntimeMaterialRole::try_from(m.role).unwrap().as_str_name(),
                "reference":m.reference,"version":m.version
            })).collect::<Vec<_>>()}
    }]});
    (document, attestation, configuration)
}

fn entry(document: &Value) -> Entry {
    super::super::Profile::parse(&serde_json::to_vec(document).unwrap())
        .unwrap()
        .entries
        .remove(0)
}

#[test]
fn exact_launch_join_preserves_original_identity_and_large_generation() {
    let (document, attestation, configuration) = fixture();
    let result =
        entry(&document).registration(&attestation, &configuration, "host-v1", "bindings-v1");
    assert!(result.is_ok(), "exact protected enrollment must join");
    let result = result.unwrap();
    assert_eq!(
        result.binding.target,
        attestation.launch.as_ref().unwrap().target
    );
    assert_eq!(
        result.binding.target.as_ref().unwrap().generation,
        GENERATION
    );
    assert_eq!(result.binding.target.as_ref().unwrap().fencing_token, 7);
    assert_eq!(result.binding.process_instance_id, INSTANCE);
    assert_eq!(result.binding.installation_id, INSTALLATION);
    assert_eq!(result.configuration, configuration);
    assert_eq!(result.proof_sha256, [0xbb; 32]);
}

#[test]
fn absent_launch_does_not_enroll() {
    let (mut document, attestation, configuration) = fixture();
    document["profiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("launch");
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
}

#[test]
fn original_order_is_preserved_including_reverse_role_order() {
    let (mut document, mut attestation, configuration) = fixture();
    let original_hash = attestation
        .launch
        .as_ref()
        .unwrap()
        .launch_context_hash
        .clone();
    attestation.launch.as_mut().unwrap().materials.reverse();
    seal(&mut attestation);
    assert_ne!(
        attestation.launch.as_ref().unwrap().launch_context_hash,
        original_hash
    );
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err(),
        "one-sided reorder"
    );
    document["profiles"][0]["launch"]["materials"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_ok(),
        "original catalog may be reverse ordered"
    );
}

#[test]
fn resealed_attestation_mismatches_are_rejected_independently_of_self_hash() {
    let (document, attestation, configuration) = fixture();
    let entry = entry(&document);
    for (pointer, value) in [
        ("/schemaVersion", json!(2)),
        ("/installationId", json!(INSTANCE)),
        ("/instanceProofSha256", json!("B".repeat(64))),
        ("/instanceProofSha256", json!("a".repeat(63))),
        ("/stagedManifestSha256", json!("not-a-hash")),
        ("/imageId", json!(format!("sha256:{}", "e".repeat(64)))),
        (
            "/imageId",
            json!(configuration.image_ref.rsplit_once('@').unwrap().1),
        ),
        ("/launch/schemaVersion", json!(2)),
        ("/launch/target/workspaceId", json!("another")),
        ("/launch/target/namespaceId", json!("another")),
        ("/launch/target/proxyId", json!(INSTANCE)),
        ("/launch/target/revisionId", json!(INSTANCE)),
        (
            "/launch/target/generation",
            json!((GENERATION + 1).to_string()),
        ),
        ("/launch/target/generation", json!("0")),
        ("/launch/target/fencingToken", json!("0")),
        ("/launch/target/fencingToken", json!(u64::MAX.to_string())),
        (
            "/launch/processInstanceId",
            json!("0191b7f1-7f2c-4c13-9a61-2f29f2be1004"),
        ),
        ("/launch/authorityProfileRef", json!("profile:other")),
        ("/launch/authorityProfileVersion", json!("v2")),
        ("/launch/configHash", json!("e".repeat(64))),
        ("/launch/runtimeManifestHash", json!("e".repeat(64))),
        (
            "/launch/imageRef",
            json!(format!("example.test/other@sha256:{}", "a".repeat(64))),
        ),
        ("/launch/health/port", json!(8082)),
        (
            "/launch/health/credentialRef",
            json!("secret://other/health"),
        ),
        (
            "/launch/materials/1/role",
            json!("RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN"),
        ),
        (
            "/launch/materials/1/reference",
            json!("secret://other/material"),
        ),
        ("/launch/materials/1/version", json!("v2")),
        ("/launch/materials", json!([])),
        ("/launch/health", Value::Null),
        ("/launch/target", Value::Null),
    ] {
        let mut encoded = serde_json::to_value(&attestation).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        let mut changed: proto::RuntimeLaunchAttestation = serde_json::from_value(encoded).unwrap();
        seal(&mut changed);
        assert!(
            entry
                .registration(&changed, &configuration, "host-v1", "bindings-v1")
                .is_err(),
            "{pointer}"
        );
    }
    // Protobuf can carry unknown numeric roles; generated ProtoJSON refuses
    // them. Exercise the typed boundary without the JSON decoder preempting it.
    let mut unknown_role = attestation.clone();
    unknown_role.launch.as_mut().unwrap().materials[1].role = 999;
    assert!(
        entry
            .registration(&unknown_role, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
    let mut missing = attestation.clone();
    missing.launch = None;
    assert!(
        entry
            .registration(&missing, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
    let mut wrong_hash = attestation.clone();
    wrong_hash.launch.as_mut().unwrap().launch_context_hash = "e".repeat(64);
    assert!(
        entry
            .registration(&wrong_hash, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
    for (host, bindings) in [("host-v2", "bindings-v1"), ("host-v1", "bindings-v2")] {
        assert!(
            entry
                .registration(&attestation, &configuration, host, bindings)
                .is_err()
        );
    }
}

#[test]
fn fresh_configuration_must_match_original_target_and_both_recomputed_hashes() {
    let (document, attestation, configuration) = fixture();
    let entry = entry(&document);
    for (pointer, value) in [
        ("/schemaVersion", json!(2)),
        ("/workspaceId", json!("other")),
        ("/namespaceId", json!("other")),
        ("/proxyId", json!(INSTANCE)),
        ("/revisionId", json!(INSTANCE)),
        ("/generation", json!((GENERATION + 1).to_string())),
        ("/configHash", json!("e".repeat(64))),
        ("/runtimeManifestHash", json!("e".repeat(64))),
        (
            "/imageRef",
            json!(format!("example.test/other@sha256:{}", "a".repeat(64))),
        ),
        ("/cpuMillis", json!(999)),
        ("/spec", Value::Null),
    ] {
        let mut encoded = serde_json::to_value(&configuration).unwrap();
        *encoded.pointer_mut(pointer).unwrap() = value;
        let changed: proto::RuntimeConfiguration = serde_json::from_value(encoded).unwrap();
        // Echo even a stale supplied runtime hash and correctly re-seal launch:
        // body-only changes must fail the independent runtime hash recomputation.
        let mut changed_attestation = attestation.clone();
        changed_attestation
            .launch
            .as_mut()
            .unwrap()
            .runtime_manifest_hash = changed.runtime_manifest_hash.clone();
        seal(&mut changed_attestation);
        assert!(
            entry
                .registration(&changed_attestation, &changed, "host-v1", "bindings-v1")
                .is_err(),
            "{pointer}"
        );
    }
}

fn reseal_configuration(
    attestation: &mut proto::RuntimeLaunchAttestation,
    configuration: &mut proto::RuntimeConfiguration,
) {
    configuration.runtime_manifest_hash = runtime_manifest_hash(configuration).unwrap();
    attestation.launch.as_mut().unwrap().runtime_manifest_hash =
        configuration.runtime_manifest_hash.clone();
    seal(attestation);
}

#[test]
fn mutually_matching_hashes_image_and_material_metadata_do_not_bypass_source_checks() {
    let (mut document, mut attestation, mut configuration) = fixture();
    // All three claim the same well-shaped control hash; only actual canonical
    // published-spec hashing discriminates this from a valid joined record.
    document["profiles"][0]["launch"]["config_hash"] = json!("e".repeat(64));
    configuration.config_hash = "e".repeat(64);
    attestation.launch.as_mut().unwrap().config_hash = configuration.config_hash.clone();
    reseal_configuration(&mut attestation, &mut configuration);
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err(),
        "canonical control hash"
    );

    let (mut document, mut attestation, mut configuration) = fixture();
    let image = format!("example.test/runtime@sha256:{}", "e".repeat(64));
    document["profiles"][0]["launch"]["image_ref"] = json!(image);
    configuration.image_ref = image.clone();
    attestation.launch.as_mut().unwrap().image_ref = image;
    reseal_configuration(&mut attestation, &mut configuration);
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err(),
        "spec image digest differs"
    );

    let (mut document, mut attestation, configuration) = fixture();
    let secret = configuration
        .secret_refs
        .first()
        .expect("actual business material")
        .clone();
    document["profiles"][0]["launch"]["materials"][1]["reference"] = json!(secret);
    attestation.launch.as_mut().unwrap().materials[1].reference = secret;
    seal(&mut attestation);
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err(),
        "launch material overlaps business secrets"
    );
}

#[test]
fn enrollment_parse_eagerly_rejects_unknown_duplicate_and_bounded_shapes() {
    let (original, _, _) = fixture();
    let prefix = "/profiles/0/launch";
    for (suffix, value) in [
        ("/config_hash", json!("A".repeat(64))),
        ("/host_policy_version", json!("")),
        ("/host_policy_version", json!("a".repeat(129))),
        ("/deployment_bindings_version", json!("..")),
        ("/image_id", json!("a".repeat(64))),
        ("/image_id", json!(format!("sha256:{}", "A".repeat(64)))),
        (
            "/image_ref",
            json!(format!("localhost/repo@sha256:{}", "a".repeat(64))),
        ),
        (
            "/image_ref",
            json!(format!("example.test/../repo@sha256:{}", "a".repeat(64))),
        ),
        ("/image_ref", json!("a".repeat(513))),
        ("/materials", json!([])),
        (
            "/materials",
            json!(vec![
                original["profiles"][0]["launch"]["materials"][0]
                    .clone();
                14
            ]),
        ),
        ("/materials/0/role", json!(1)),
        (
            "/materials/0/role",
            json!("RUNTIME_MATERIAL_ROLE_UNSPECIFIED"),
        ),
        ("/materials/0/role", json!("RUNTIME_MATERIAL_ROLE_OTHER")),
        (
            "/materials/1/role",
            json!("RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN"),
        ),
        (
            "/materials/1/reference",
            json!("secret://managed/material-1"),
        ),
        (
            "/materials/0/reference",
            json!("secret://managed/../health"),
        ),
        ("/materials/0/reference", json!("secret://managed/./health")),
        ("/materials/0/reference", json!("secret://managed//health")),
        ("/materials/0/reference", json!("secret://_invalid/health")),
        (
            "/materials/0/reference",
            json!(format!("secret://{}", "a".repeat(248))),
        ),
        ("/materials/0/version", json!("a".repeat(129))),
        (
            "/materials/0",
            json!([
                "RUNTIME_MATERIAL_ROLE_HEALTH_TOKEN",
                "secret://managed/material-1",
                "v1"
            ]),
        ),
        ("", json!([])),
    ] {
        let mut document = original.clone();
        *document.pointer_mut(&format!("{prefix}{suffix}")).unwrap() = value;
        assert!(
            super::super::Profile::parse(&serde_json::to_vec(&document).unwrap()).is_err(),
            "{suffix}"
        );
    }
    for pointer in ["/profiles/0/launch", "/profiles/0/launch/materials/0"] {
        let mut document = original.clone();
        document.pointer_mut(pointer).unwrap()["source_name"] = json!("not-accepted");
        assert!(super::super::Profile::parse(&serde_json::to_vec(&document).unwrap()).is_err());
    }
    let encoded = serde_json::to_string(&original).unwrap();
    for (key, value) in [("host_policy_version", "host-v1"), ("version", "v1")] {
        let needle = format!("\"{key}\":\"{value}\"");
        let duplicate = encoded.replacen(&needle, &format!("{needle},{needle}"), 1);
        assert_ne!(duplicate, encoded);
        assert!(
            super::super::Profile::parse(duplicate.as_bytes()).is_err(),
            "duplicate {key}"
        );
    }
}

#[test]
fn bounds_and_null_enrollment_fail_closed_without_new_identity() {
    let (mut document, mut attestation, mut configuration) = fixture();
    document["profiles"][0]["launch"] = Value::Null;
    assert!(
        entry(&document)
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
    let (document, _, _) = fixture();
    let entry = entry(&document);
    attestation.launch.as_mut().unwrap().process_instance_id = "a".repeat(32_769);
    assert!(
        entry
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
    let (_, attestation, _) = fixture();
    configuration.resource_url = "a".repeat(262_145);
    assert!(
        entry
            .registration(&attestation, &configuration, "host-v1", "bindings-v1")
            .is_err()
    );
}
