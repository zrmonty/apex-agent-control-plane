use super::{decode_health_stdout, fixture};
use crate::proto;

#[test]
fn rejects_changes_to_every_original_binding_field_including_the_operation_fence() {
    let launch = fixture::launch();
    for field in 0..10 {
        let mut altered = launch.clone();
        let target = altered.target.as_mut().unwrap();
        match field {
            0 => target.workspace_id = "workspace-other".into(),
            1 => target.namespace_id = "namespace-other".into(),
            2 => target.proxy_id = launch.process_instance_id.clone(),
            3 => target.revision_id = launch.process_instance_id.clone(),
            4 => target.generation += 1,
            5 => target.fencing_token += 1,
            6 => altered.config_hash = "d".repeat(64),
            7 => altered.runtime_manifest_hash = "d".repeat(64),
            8 => altered.launch_context_hash = "d".repeat(64),
            9 => altered.process_instance_id = target.proxy_id.clone(),
            _ => unreachable!(),
        }
        assert!(
            decode_health_stdout(&fixture::stdout(&fixture::report(&altered)), &launch).is_err(),
            "report field {field}"
        );
        assert!(
            decode_health_stdout(&fixture::stdout(&fixture::report(&launch)), &altered).is_err(),
            "expected field {field}"
        );
    }
}

#[test]
fn rejects_self_consistent_invalid_expected_bindings() {
    let mutations: &[fn(&mut proto::RuntimeLaunchContext)] = &[
        |l| *l = proto::RuntimeLaunchContext::default(),
        |l| l.schema_version = 0,
        |l| l.schema_version = 2,
        |l| l.target = None,
        |l| l.target.as_mut().unwrap().workspace_id.clear(),
        |l| l.target.as_mut().unwrap().workspace_id = "../bad".into(),
        |l| l.target.as_mut().unwrap().namespace_id.clear(),
        |l| l.target.as_mut().unwrap().namespace_id = "x".repeat(257),
        |l| l.target.as_mut().unwrap().proxy_id.clear(),
        |l| l.target.as_mut().unwrap().revision_id = "0191b7f1-7f2c-4c13-9a61-2f29f2be1002".into(),
        |l| l.target.as_mut().unwrap().generation = 0,
        |l| l.target.as_mut().unwrap().fencing_token = 0,
        |l| l.config_hash.clear(),
        |l| l.runtime_manifest_hash = "A".repeat(64),
        |l| l.launch_context_hash = "c".repeat(63),
        |l| l.process_instance_id.clear(),
        |l| l.process_instance_id = "0191B7F1-7f2c-7c13-9a61-2f29f2be1003".into(),
        |l| l.image_ref = "registry.example/gateway:latest".into(),
        |l| l.authority_profile_ref.clear(),
        |l| l.authority_profile_version = "x".repeat(129),
        |l| l.health = None,
        |l| l.health.as_mut().unwrap().port = 0,
        |l| l.health.as_mut().unwrap().credential_ref = "secret://../token".into(),
        |l| l.materials.clear(),
        |l| l.materials.push(l.materials[0].clone()),
        |l| l.materials.resize(14, l.materials[0].clone()),
        |l| l.materials[0].role = 0,
        |l| l.materials[0].role = 999,
        |l| l.materials[0].role = proto::RuntimeMaterialRole::GovernanceCa.into(),
        |l| l.materials[0].reference = "secret://other/token".into(),
        |l| l.materials[0].version.clear(),
    ];
    for (index, mutation) in mutations.iter().enumerate() {
        let mut launch = fixture::launch();
        mutation(&mut launch);
        assert!(
            decode_health_stdout(&fixture::stdout(&fixture::report(&launch)), &launch).is_err(),
            "mutation {index}"
        );
    }
}
