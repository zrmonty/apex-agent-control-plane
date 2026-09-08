use super::*;
mod binding;
mod failures;
mod lookup;
use crate::{execution::record::Phase, proto};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let r = Self(PathBuf::from("/root").join(format!("apex-task4n-{}", uuid::Uuid::now_v7())));
        fs::create_dir(&r.0).unwrap();
        fs::set_permissions(&r.0, fs::Permissions::from_mode(0o700)).unwrap();
        r
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn catalog() -> NetworkCatalog {
    NetworkCatalog::parse(&serde_json::to_vec(&crate::network_catalog::tests::fixture()).unwrap())
        .unwrap()
}
fn installed() -> Installed {
    let id = uuid::Uuid::now_v7().to_string();
    Installed {
        original: proto::RuntimeReconcileRequest {
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
        },
        instance: id,
        launch_json: "{}".into(),
        configuration_json: "{}".into(),
        authority_json: "{}".into(),
        tools_json: "{}".into(),
        publication_hash: "a".repeat(64),
        image_id: String::new(),
        mount_profile: "private-stage-v1".into(),
        unset_env: vec![],
        container_id: String::new(),
        phase: Phase::Intent,
        files: Default::default(),
        instance_proof_version: Some(1),
        network: None,
        guard_stage: None,
        gateway_stage: None,
        paired_containers: None,
    }
}
#[test]
fn network_reservation_is_durable_and_exact_retry_keeps_its_slot() {
    let root = Root::new();
    let c = catalog();
    let i = installed();
    let j = Journal::open(&root.0).unwrap();
    let first = j
        .reserve_network(&c, c.installation_id(), &i)
        .expect("valid fresh durable reservation");
    assert_eq!(first.slot, 0);
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    assert_eq!(
        j.reserve_network(&c, c.installation_id(), &i).unwrap(),
        first
    );
    assert_eq!(
        j.reserve_network(&c, c.installation_id(), &installed())
            .unwrap()
            .slot,
        1
    );
}

#[test]
fn network_reservation_concurrent_instances_have_distinct_durable_slots() {
    let root = Root::new();
    let j = std::sync::Arc::new(Journal::open(&root.0).unwrap());
    let c = std::sync::Arc::new(catalog());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let jobs: Vec<_> = (0..8)
        .map(|_| {
            let j = j.clone();
            let c = c.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let i = installed();
                barrier.wait();
                let b = j.reserve_network(&c, c.installation_id(), &i).unwrap();
                (i, b)
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    let slots: std::collections::BTreeSet<_> = results.iter().map(|(_, b)| b.slot).collect();
    assert_eq!(slots.len(), 8);
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    for (i, b) in results {
        assert_eq!(j.reserve_network(&c, c.installation_id(), &i).unwrap(), b);
    }
}
#[test]
fn network_reservation_conflicting_owner_layout_scope_and_capacity_do_not_evict() {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let c = catalog();
    let i = installed();
    let original = j.reserve_network(&c, c.installation_id(), &i).unwrap();
    let mut forged = i.clone();
    forged.original.config_hash = "c".repeat(64);
    assert!(j.reserve_network(&c, c.installation_id(), &forged).is_err());
    assert!(
        j.reserve_network(&c, &uuid::Uuid::now_v7().to_string(), &i)
            .is_err()
    );
    for (path, value) in [
        ("/internal_pool", serde_json::json!("10.244.0.0/22")),
        ("/outer/network_id", serde_json::json!("c".repeat(64))),
        ("/outer/edge_address", serde_json::json!("172.31.250.3")),
        ("/capacity", serde_json::json!(127)),
    ] {
        let mut v = crate::network_catalog::tests::fixture();
        *v.pointer_mut(path).unwrap() = value;
        let other = NetworkCatalog::parse(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(j.reserve_network(&other, c.installation_id(), &i).is_err());
    }
    for slot in 1..128 {
        assert_eq!(
            j.reserve_network(&c, c.installation_id(), &installed())
                .unwrap()
                .slot,
            slot
        );
    }
    assert!(
        j.reserve_network(&c, c.installation_id(), &installed())
            .is_err()
    );
    assert_eq!(
        j.reserve_network(&c, c.installation_id(), &i).unwrap(),
        original
    );
}
#[test]
fn network_reservation_missing_or_incomplete_journal_never_silently_reinitializes() {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let c = catalog();
    let i = installed();
    j.reserve_network(&c, c.installation_id(), &i).unwrap();
    let file = root.0.join(disk::NAME);
    let original = fs::read(&file).unwrap();
    fs::remove_file(&file).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    fs::write(&file, &original).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        j.reserve_network(&c, c.installation_id(), &i).is_err(),
        "process stays poisoned after replacement"
    );
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_ok());
    drop(j);
    fs::write(root.0.join(disk::TEMP), b"incomplete-owned-transaction").unwrap();
    fs::set_permissions(root.0.join(disk::TEMP), fs::Permissions::from_mode(0o600)).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(
        fs::read(root.0.join(disk::TEMP)).unwrap(),
        b"incomplete-owned-transaction"
    );
}
#[test]
fn network_reservation_corruption_cannot_be_adopted_even_with_recomputed_hash() {
    let root = Root::new();
    let c = catalog();
    let i = installed();
    let j = Journal::open(&root.0).unwrap();
    j.reserve_network(&c, c.installation_id(), &i).unwrap();
    drop(j);
    let file = root.0.join(disk::NAME);
    let original = fs::read(&file).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for (path, bad) in [
        ("/schema_version", serde_json::json!(2)),
        ("/installation", serde_json::json!("wrong")),
        ("/capacity", serde_json::json!(129)),
        ("/entries/0/slot", serde_json::json!(128)),
        ("/entries/0/instance", serde_json::json!("wrong")),
        ("/entries/0/owner_hash", serde_json::json!("CANARY")),
    ] {
        let mut v = value.clone();
        *v["document"].pointer_mut(path).unwrap() = bad;
        // Recompute through the exact struct serialization when semantically malformed but deserializable.
        let Object(d): Object<Document> = serde_json::from_value(v["document"].clone()).unwrap();
        v["digest"] = serde_json::json!(hash(&d).unwrap());
        fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
        let j = Journal::open(&root.0).unwrap();
        assert!(
            j.reserve_network(&c, c.installation_id(), &i).is_err(),
            "{path}"
        );
    }
    for bytes in [
        b"[]".to_vec(),
        vec![b' '; 65537],
        String::from_utf8(original.clone())
            .unwrap()
            .replacen("\"digest\":", "\"digest\":\"bad\",\"digest\":", 1)
            .into_bytes(),
    ] {
        fs::write(&file, bytes).unwrap();
        let j = Journal::open(&root.0).unwrap();
        assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    }
}
