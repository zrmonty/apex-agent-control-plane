use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const INSTALL: &str = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
fn fixture() -> Installed {
    let configuration = proto::RuntimeConfiguration {
        secret_refs: vec![
            "secret://tool/z-token".into(),
            "secret://tool/a-token".into(),
        ],
        ..Default::default()
    };
    let mut i = Installed {
        original: Default::default(), instance: INSTALL.into(), launch_json: "{}".into(),
        configuration_json: serde_json::to_string(&configuration).unwrap(),
        authority_json: json!({"schema_version":3,"catalog_version":"v1","profile":{"mode":"managed_ingress","installation_id":INSTALL}}).to_string(),
        tools_json: "{}".into(), publication_hash: "a".repeat(64), image_id: format!("sha256:{}", "b".repeat(64)),
        mount_profile: "private-stage-v1".into(), unset_env: vec![], container_id: String::new(),
        phase: super::super::super::record::Phase::CreateIntent, files: BTreeMap::new(), instance_proof_version: Some(1), network: None,
    };
    for name in [
        "instance-proof",
        "health-token",
        "governance-ca",
        "governance-cert",
        "governance-key",
        "governance-token",
        "evidence-ca",
        "evidence-cert",
        "evidence-key",
        "evidence-token",
        "inbound-jwks",
        "workload-ca",
        "workload-cert",
        "workload-key",
    ] {
        i.files.insert(name.into(), "c".repeat(64));
    }
    for (name, value) in [
        ("runtime-revision.json", &i.configuration_json),
        ("launch-context.json", &i.launch_json),
        ("authority-profile.json", &i.authority_json),
        ("tool-bindings.json", &i.tools_json),
    ] {
        i.files.insert(
            name.into(),
            format!("{:x}", Sha256::digest(value.as_bytes())),
        );
    }
    for reference in &configuration.secret_refs {
        i.files.insert(
            format!("tool-{:x}", Sha256::digest(reference.as_bytes())),
            "d".repeat(64),
        );
    }
    i
}

#[test]
fn sealed_stage_handoff_is_sorted_digest_only_and_preserves_the_fixed_profile() {
    let i = fixture();
    let result = environment(INSTALL, &i).expect("sealed stage metadata handoff");
    assert_eq!(&result[..6], ENV);
    assert_eq!(result.len(), 10);
    assert!(result.contains(&"APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v1".into()));
    assert!(result.contains(&format!("APEX_INSTALLATION_ID={INSTALL}")));
    assert!(result.contains(&format!(
        "APEX_STAGE_MANIFEST_SHA256={:x}",
        Sha256::digest(serde_json::to_vec(&i.files).unwrap())
    )));
    assert!(result.contains(
        &"APEX_TOOL_SECRET_REFERENCES=[\"secret://tool/a-token\",\"secret://tool/z-token\"]".into()
    ));
}

#[test]
fn legacy_modes_retain_exact_environment_without_retrofitting_a_stage() {
    for schema in [1, 2] {
        let mut i = fixture();
        let mut value = json!({"schema_version":schema,"profile":{}});
        if schema == 2 {
            value["profile"]["mode"] = json!("managed_preparation");
        }
        i.authority_json = value.to_string();
        i.instance_proof_version = None;
        i.files.clear();
        assert_eq!(environment(INSTALL, &i).unwrap(), ENV);
    }
}

#[test]
fn malformed_mode_or_installation_never_selects_bootstrap() {
    for value in [
        json!({"schema_version":1,"profile":{"mode":"managed_ingress"}}),
        json!({"schema_version":2,"profile":{"mode":"managed_ingress"}}),
        json!({"schema_version":3,"profile":{"mode":"managed_preparation"}}),
        json!({"schema_version":3,"profile":{"mode":{"managed_ingress":null}}}),
        json!({"schema_version":3,"profile":{"mode":null}}),
        json!({"schema_version":3,"profile":[]}),
        json!({"schema_version":4,"profile":{"mode":"managed_ingress"}}),
    ] {
        let mut i = fixture();
        i.authority_json = value.to_string();
        assert_eq!(environment(INSTALL, &i).err(), Some(ERROR));
    }
    for installation in ["", "canary", "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99"] {
        assert_eq!(environment(installation, &fixture()).err(), Some(ERROR));
    }
    let mut i = fixture();
    i.authority_json = i.authority_json.replacen(
        "\"schema_version\":3",
        "\"schema_version\":3,\"schema_version\":3",
        1,
    );
    assert_eq!(environment(INSTALL, &i).err(), Some(ERROR));
}

#[test]
fn every_sealed_file_and_metadata_digest_is_required_without_extra_files() {
    let original = fixture();
    for key in original.files.keys() {
        let mut i = original.clone();
        i.files.remove(key);
        assert_eq!(environment(INSTALL, &i).err(), Some(ERROR), "missing {key}");
        let mut i = original.clone();
        i.files.insert(key.clone(), "invalid".into());
        assert_eq!(
            environment(INSTALL, &i).err(),
            Some(ERROR),
            "malformed hash {key}"
        );
    }
    for key in [
        "runtime-revision.json",
        "launch-context.json",
        "authority-profile.json",
        "tool-bindings.json",
    ] {
        let mut i = original.clone();
        i.files.insert(key.into(), "f".repeat(64));
        assert_eq!(
            environment(INSTALL, &i).err(),
            Some(ERROR),
            "mismatched document {key}"
        );
    }
    for key in ["../escape", "tool-extra", "unexpected.json"] {
        let mut i = original.clone();
        i.files.insert(key.into(), "e".repeat(64));
        assert_eq!(environment(INSTALL, &i).err(), Some(ERROR));
    }
    for proof in [None, Some(0), Some(2)] {
        let mut i = original.clone();
        i.instance_proof_version = proof;
        assert_eq!(environment(INSTALL, &i).err(), Some(ERROR));
    }
}

fn references(i: &mut Installed, refs: Vec<String>) {
    let c = proto::RuntimeConfiguration {
        secret_refs: refs.clone(),
        ..Default::default()
    };
    i.configuration_json = serde_json::to_string(&c).unwrap();
    i.files.insert(
        "runtime-revision.json".into(),
        digest(i.configuration_json.as_bytes()),
    );
    i.files
        .retain(|name, _| !name.starts_with("tool-") || name == "tool-bindings.json");
    for r in &refs {
        i.files
            .insert(format!("tool-{}", digest(r.as_bytes())), "d".repeat(64));
    }
}

#[test]
fn published_reference_inventory_is_bounded_unique_and_canonical() {
    for refs in [
        vec!["secret://tool/a".into(); 2],
        vec!["plain-canary".into()],
        vec!["secret://tool/../x".into()],
        vec!["secret://tool//x".into()],
        vec!["secret://tool/a?token=canary".into()],
        vec!["secret://tool/é".into()],
        vec![format!("secret://{}", "x".repeat(248))],
        (0..33).map(|n| format!("secret://tool/key-{n}")).collect(),
    ] {
        let mut i = fixture();
        references(&mut i, refs);
        assert_eq!(environment(INSTALL, &i).err(), Some(ERROR));
    }
    for count in [0, 32] {
        let mut i = fixture();
        references(
            &mut i,
            (0..count)
                .map(|n| format!("secret://tool/key-{n}"))
                .collect(),
        );
        assert_eq!(environment(INSTALL, &i).unwrap().len(), 10);
    }
}

#[test]
fn handoff_is_stable_across_restart_phase_and_original_record_clones() {
    let original = fixture();
    let expected = environment(INSTALL, &original).unwrap();
    let mut adopted = original.clone();
    adopted.phase = super::super::super::record::Phase::Installed;
    adopted.container_id = "e".repeat(64);
    assert_eq!(environment(INSTALL, &adopted).unwrap(), expected);
    adopted
        .files
        .insert("instance-proof".into(), "f".repeat(64));
    assert_ne!(
        environment(INSTALL, &adopted).unwrap(),
        expected,
        "physical map changes cannot retain original digest"
    );
}
