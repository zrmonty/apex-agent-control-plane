use super::*;

#[test]
fn catalog_free_lookup_distinguishes_orphans_attachments_and_unreserved_instances() {
    let root = Root::new();
    let c = catalog();
    let mut i = installed();
    let other = installed();
    let j = Journal::open(&root.0).unwrap();
    assert!(!j.network_reserved(c.installation_id(), &i).unwrap());
    assert!(
        !root.0.join(disk::NAME).exists(),
        "lookup never initializes history"
    );
    let binding = j.reserve_network(&c, c.installation_id(), &i).unwrap();
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    let bytes = fs::read(root.0.join(disk::NAME)).unwrap();
    assert!(j.network_reserved(c.installation_id(), &i).unwrap());
    assert!(!j.network_reserved(c.installation_id(), &other).unwrap());
    i.network = Some(binding);
    assert!(j.network_reserved(c.installation_id(), &i).unwrap());
    assert_eq!(fs::read(root.0.join(disk::NAME)).unwrap(), bytes);
}

#[test]
fn catalog_free_lookup_refuses_mismatched_owner_scope_and_attachment() {
    let root = Root::new();
    let c = catalog();
    let i = installed();
    let j = Journal::open(&root.0).unwrap();
    let binding = j.reserve_network(&c, c.installation_id(), &i).unwrap();
    let mut changed = i.clone();
    changed.original.config_hash = "b".repeat(64);
    assert!(j.network_reserved(c.installation_id(), &changed).is_err());
    assert!(
        j.network_reserved(&uuid::Uuid::now_v7().to_string(), &i)
            .is_err()
    );
    changed = i.clone();
    changed.network = Some(binding);
    changed.network.as_mut().unwrap().slot = 1;
    assert!(j.network_reserved(c.installation_id(), &changed).is_err());
    assert!(j.network_reserved(c.installation_id(), &i).unwrap());
}

#[test]
fn catalog_free_lookup_refuses_corrupt_incomplete_and_missing_loaded_history() {
    for fault in 0..3 {
        let root = Root::new();
        let c = catalog();
        let i = installed();
        let j = Journal::open(&root.0).unwrap();
        j.reserve_network(&c, c.installation_id(), &i).unwrap();
        let original = fs::read(root.0.join(disk::NAME)).unwrap();
        match fault {
            0 => fs::write(root.0.join(disk::NAME), b"[]").unwrap(),
            1 => fs::write(root.0.join(disk::TEMP), b"incomplete").unwrap(),
            _ => fs::remove_file(root.0.join(disk::NAME)).unwrap(),
        }
        assert!(
            j.network_reserved(c.installation_id(), &installed())
                .is_err()
        );
        if fault != 1 {
            fs::write(root.0.join(disk::NAME), &original).unwrap();
            fs::set_permissions(root.0.join(disk::NAME), fs::Permissions::from_mode(0o600))
                .unwrap();
            assert!(
                j.network_reserved(c.installation_id(), &installed())
                    .is_err(),
                "poison retained"
            );
        }
        assert!(
            j.reserve_network(&c, c.installation_id(), &installed())
                .is_err()
        );
    }
}

#[test]
fn catalog_free_lookup_cannot_approve_an_attachment_without_global_history() {
    let root = Root::new();
    let c = catalog();
    let mut i = installed();
    let j = Journal::open(&root.0).unwrap();
    i.network = Some(j.reserve_network(&c, c.installation_id(), &i).unwrap());
    drop(j);
    fs::remove_file(root.0.join(disk::NAME)).unwrap();
    let j = Journal::open(&root.0).unwrap();
    assert!(j.network_reserved(c.installation_id(), &i).is_err());
    assert!(!root.0.join(disk::NAME).exists());
}
