use super::*;
pub(super) mod concurrency;
use crate::{
    execution::{
        metadata::strict::Object,
        network_owner::topology::Topology,
        record::{Installed, Record},
    },
    network_catalog::NetworkCatalog,
    proto,
};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = PathBuf::from("/root").join(format!("task4p-journal-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn setup() -> (Root, Journal, Installed, Document) {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let c = NetworkCatalog::parse(
        &serde_json::to_vec(&crate::network_catalog::tests::fixture()).unwrap(),
    )
    .unwrap();
    let request = proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "work".into(),
            namespace_id: "ns".into(),
            proxy_id: uuid::Uuid::now_v7().to_string(),
            revision_id: uuid::Uuid::now_v7().to_string(),
            generation: 1,
            fencing_token: 1,
        }),
        operation_id: uuid::Uuid::now_v7().to_string(),
        command_id: uuid::Uuid::now_v7().to_string(),
        config_hash: "a".repeat(64),
    };
    let mut r = Record::select(c.installation_id(), &request, None).unwrap();
    let l = proto::RuntimeLaunchContext {
        schema_version: 1,
        target: request.target.clone(),
        process_instance_id: r.instance.clone(),
        config_hash: request.config_hash.clone(),
        authority_profile_ref: "live".into(),
        authority_profile_version: "v1".into(),
        ..Default::default()
    };
    let target = request.target.as_ref().unwrap();
    let a = json!({"schema_version":3,"profile":{"mode":"managed_ingress","installation_id":c.installation_id(),"workspace_id":"work","namespace_id":"ns","proxy_id":target.proxy_id,"reference":"live","version":"v1","host_policy_version":"host-v1","managed":{"network_policy":{"reference":"net","version":"v1"}},"governance":{"endpoint":"https://governance.example"},"evidence":{"endpoint":"https://evidence.example"}}});
    let mut i = Installed {
        original: request,
        instance: r.instance.clone(),
        launch_json: serde_json::to_string(&l).unwrap(),
        configuration_json: "{}".into(),
        authority_json: a.to_string(),
        tools_json: "{}".into(),
        publication_hash: "b".repeat(64),
        image_id: String::new(),
        mount_profile: "private-stage-v1".into(),
        unset_env: vec![],
        container_id: String::new(),
        phase: crate::execution::record::Phase::Intent,
        files: Default::default(),
        instance_proof_version: Some(1),
        network: None,
        guard_stage: None,
    };
    i.network = Some(j.reserve_network(&c, c.installation_id(), &i).unwrap());
    r.installed = Some(i.clone());
    j.save(&r).unwrap();
    let t = Topology::new(&c, c.installation_id(), &i, "c".repeat(64), 1).unwrap();
    let d = Document::prepared(t).unwrap();
    j.prepare_topology(&d).unwrap();
    (root, j, i, d)
}
#[test]
fn durable_topology_intent_keeps_original_binding_and_reopens() {
    let (root, j, i, d) = setup();
    let mut intent = d.clone();
    intent.phase = Phase::CreateIntent;
    j.transition_topology(&d, &intent).unwrap();
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    let all = j.topology_history(&d.topology.0.installation).unwrap();
    assert!(all[&i.instance].phase == Phase::CreateIntent);
    assert_eq!(all[&i.instance].topology.0.binding.0, i.network.unwrap());
}
#[test]
fn recomputed_sidecar_cannot_change_global_committed_layout_geometry() {
    let (_root, j, i, mut d) = setup();
    let t = &mut d.topology.0;
    let mut c: serde_json::Value = serde_json::from_str(&t.selected_catalog_json).unwrap();
    c["internal_pool"] = json!("10.241.0.0/22");
    t.selected_catalog_json = c.to_string();
    t.internal_subnet = "10.241.0.0/29".into();
    t.ipam_gateway = "10.241.0.1".into();
    t.gateway_workload_address = "10.241.0.2".into();
    t.guard_internal_address = "10.241.0.3".into();
    d.topology_hash = t.digest().unwrap();
    disk::save(
        &j.root,
        &format!("network-topology-{}.json", i.instance),
        &d,
    )
    .unwrap();
    assert!(
        j.topology_history(&d.topology.0.installation).is_err(),
        "a new valid checksum is not the committed layout"
    );
}
#[test]
fn missing_seen_sidecar_poisons_even_optout_lookup() {
    let (root, j, i, d) = setup();
    fs::remove_file(root.0.join(format!("network-topology-{}.json", i.instance))).unwrap();
    assert!(j.network_reserved(&d.topology.0.installation, &i).is_err());
    disk::save(
        &j.root,
        &format!("network-topology-{}.json", i.instance),
        &d,
    )
    .unwrap();
    assert!(j.topology_history(&d.topology.0.installation).is_err());
}
#[test]
fn incomplete_temp_and_unindexed_history_refuse_on_fresh_restart() {
    for unknown in [false, true] {
        let (root, j, i, d) = setup();
        let install = d.topology.0.installation.clone();
        drop(j);
        let name = if unknown {
            format!("network-topology-{}.json", uuid::Uuid::now_v7())
        } else {
            format!("network-topology-{}.json.next", i.instance)
        };
        fs::write(root.0.join(name), b"{}").unwrap();
        let j = Journal::open(&root.0).unwrap();
        assert!(j.network_reserved(&install, &i).is_err());
    }
}
#[test]
fn sidecar_objects_unknown_fields_and_observation_shapes_refuse() {
    let (root, j, i, d) = setup();
    let name = format!("network-topology-{}.json", i.instance);
    let mut v = serde_json::to_value(&d).unwrap();
    v["topology"]["unexpected"] = json!(true);
    let bytes = serde_json::to_vec(&json!({"document":v,"checksum":"a".repeat(64)})).unwrap();
    fs::write(root.0.join(&name), bytes).unwrap();
    assert!(disk::load(&j.root, &name).is_err());
    for v in [
        json!([]),
        json!({"topology":[],"phase":"Prepared","observation":null,"topology_hash":"a".repeat(64)}),
    ] {
        assert!(serde_json::from_value::<Object<Document>>(v).is_err());
    }
}
#[test]
fn topology_change_under_same_policy_selector_is_not_equivalent() {
    let (_root, _j, _i, d) = setup();
    let mut fresh = d.topology.0.clone();
    let mut v: serde_json::Value = serde_json::from_str(&fresh.selected_catalog_json).unwrap();
    v["profiles"][0]["grants"][0]["cidrs"] = json!(["10.32.0.0/24"]);
    fresh.selected_catalog_json = v.to_string();
    assert!(!d.topology.0.matches_current(&fresh).unwrap());
}

#[test]
fn stored_selected_policy_must_still_join_original_authority_profile() {
    let (_root, j, i, mut d) = setup();
    let mut c: serde_json::Value =
        serde_json::from_str(&d.topology.0.selected_catalog_json).unwrap();
    c["profiles"][0]["reference"] = json!("unrelated");
    d.topology.0.selected_catalog_json = c.to_string();
    d.topology_hash = d.topology.0.digest().unwrap();
    disk::save(
        &j.root,
        &format!("network-topology-{}.json", i.instance),
        &d,
    )
    .unwrap();
    assert!(
        j.topology_history(&d.topology.0.installation).is_err(),
        "historical policy must retain its original selected join"
    );
}
#[test]
fn uncertain_write_fsync_and_rename_poison_without_releasing_history() {
    for point in 1..=3 {
        let (root, j, i, d) = setup();
        let mut intent = d.clone();
        intent.phase = Phase::CreateIntent;
        disk::FAIL_POINT.with(|p| p.set(point));
        assert!(j.transition_topology(&d, &intent).is_err());
        assert!(j.network_reserved(&d.topology.0.installation, &i).is_err());
        let before = fs::read(root.0.join("network-reservations.json")).unwrap();
        assert!(j.topology_history(&d.topology.0.installation).is_err());
        assert_eq!(
            fs::read(root.0.join("network-reservations.json")).unwrap(),
            before
        );
        drop(j);
        let j = Journal::open(&root.0).unwrap();
        if point < 3 {
            assert!(j.topology_history(&d.topology.0.installation).is_err());
        } else {
            assert!(
                j.topology_history(&d.topology.0.installation).unwrap()[&i.instance].phase
                    == Phase::CreateIntent
            );
        }
    }
}
#[test]
fn oversized_or_linked_topology_is_never_read_as_absent() {
    for kind in 0..3 {
        let (root, j, i, d) = setup();
        let path = root.0.join(format!("network-topology-{}.json", i.instance));
        if kind == 0 {
            fs::write(&path, vec![b' '; 262145]).unwrap();
        }
        if kind == 1 {
            fs::hard_link(&path, root.0.join("extra-link")).unwrap();
        }
        if kind == 2 {
            let other = root.0.join("replaced");
            fs::rename(&path, &other).unwrap();
            std::os::unix::fs::symlink(other, &path).unwrap();
        }
        assert!(j.network_reserved(&d.topology.0.installation, &i).is_err());
    }
}
