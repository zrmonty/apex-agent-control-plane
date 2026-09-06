use super::*;
#[test]
fn network_reservation_failed_commit_preserves_original_and_poison_until_restart() {
    for point in [1, 2] {
        let root = Root::new();
        let c = catalog();
        let first = installed();
        let second = installed();
        let j = Journal::open(&root.0).unwrap();
        let old = j.reserve_network(&c, c.installation_id(), &first).unwrap();
        let before = fs::read(root.0.join(disk::NAME)).unwrap();
        disk::FAIL_POINT.set(point);
        assert!(j.reserve_network(&c, c.installation_id(), &second).is_err());
        assert!(j.reserve_network(&c, c.installation_id(), &first).is_err());
        drop(j);
        let j = Journal::open(&root.0).unwrap();
        if point == 1 {
            assert_eq!(fs::read(root.0.join(disk::NAME)).unwrap(), before);
            assert!(root.0.join(disk::TEMP).is_file());
            assert!(j.reserve_network(&c, c.installation_id(), &first).is_err());
        } else {
            assert!(!root.0.join(disk::TEMP).exists());
            assert_eq!(
                j.reserve_network(&c, c.installation_id(), &first).unwrap(),
                old
            );
            assert_eq!(
                j.reserve_network(&c, c.installation_id(), &second)
                    .unwrap()
                    .slot,
                1
            );
        }
    }
}
#[test]
fn network_reservation_protected_files_refuse_links_modes_and_preserve_targets() {
    use std::os::unix::fs::symlink;
    let root = Root::new();
    let c = catalog();
    let i = installed();
    let j = Journal::open(&root.0).unwrap();
    j.reserve_network(&c, c.installation_id(), &i).unwrap();
    drop(j);
    let file = root.0.join(disk::NAME);
    let original = fs::read(&file).unwrap();
    for mode in [0o644, 0o400, 0o4600] {
        fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
        let j = Journal::open(&root.0).unwrap();
        assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    }
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let copy = root.0.join("copy");
    fs::hard_link(&file, &copy).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    drop(j);
    fs::remove_file(&file).unwrap();
    symlink("copy", &file).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    drop(j);
    assert_eq!(fs::read(&copy).unwrap(), original);
    fs::remove_file(&file).unwrap();
    symlink("absent", &file).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
}
#[test]
fn network_reservation_duplicate_slots_instances_and_positional_objects_refuse() {
    use serde_json::json;
    let root = Root::new();
    let c = catalog();
    let i = installed();
    let j = Journal::open(&root.0).unwrap();
    j.reserve_network(&c, c.installation_id(), &i).unwrap();
    j.reserve_network(&c, c.installation_id(), &installed())
        .unwrap();
    drop(j);
    let file = root.0.join(disk::NAME);
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    for field in ["slot", "instance"] {
        let mut v = original.clone();
        v["document"]["entries"][1][field] = v["document"]["entries"][0][field].clone();
        let Object(d): Object<Document> = serde_json::from_value(v["document"].clone()).unwrap();
        v["digest"] = json!(hash(&d).unwrap());
        fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
        let j = Journal::open(&root.0).unwrap();
        assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    }
    let mut v = original.clone();
    v["document"]["entries"][0] = json!([i.instance, "a".repeat(64), 0]);
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
    drop(j);
    let mut v = original;
    v["document"]["entries"][0]["unexpected"] = json!("canary");
    fs::write(&file, serde_json::to_vec(&v).unwrap()).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.reserve_network(&c, c.installation_id(), &i).is_err());
}
