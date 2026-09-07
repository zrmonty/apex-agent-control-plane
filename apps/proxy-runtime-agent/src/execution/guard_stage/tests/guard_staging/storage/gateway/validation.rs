use super::*;
#[test]
fn task4x_journal_refuses_unknown_alternate_and_inconsistent_paired_shapes() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let original = serde_json::to_value(&s.record).unwrap();
    for bad in [json!(null), json!([]), json!({}), json!("Sealed")] {
        let mut v = original.clone();
        v["installed"]["gateway_stage"] = bad;
        assert!(serde_json::from_value::<Record>(v).is_err());
    }
    for (key, bad) in [
        ("phase", json!({"Sealed":null})),
        ("root", json!([])),
        ("identity", json!(null)),
        ("unknown", json!(1)),
    ] {
        let mut v = original.clone();
        v["installed"]["gateway_stage"][key] = bad;
        assert!(serde_json::from_value::<Record>(v).is_err(), "{key}");
    }
    for (key, bad) in [
        ("phase", json!("ProofIntent")),
        ("files", json!({})),
        ("schema_version", json!(2)),
        ("binding_hash", json!("a".repeat(64))),
        ("source_identity", json!(null)),
        ("image_ref", json!("changed")),
        ("certificate_identity", json!("changed")),
    ] {
        let mut v = original.clone();
        v["installed"]["gateway_stage"][key] = bad;
        let bad: Record = serde_json::from_value(v).unwrap();
        s.journal.save(&bad).unwrap();
        assert!(
            s.journal
                .load(INSTALL, s.record.claims.target.as_ref().unwrap())
                .is_err(),
            "{key}"
        );
    }
    s.journal.save(&s.record).unwrap();
    s.reload();
    let serialized = serde_json::to_string(&s.record).unwrap();
    let duplicate = serialized.replace(
        "\"binding_hash\":",
        "\"binding_hash\":\"duplicate\",\"binding_hash\":",
    );
    assert!(serde_json::from_str::<Record>(&duplicate).is_err());
}
#[test]
fn task4x_signer_source_metadata_guard_and_publication_changes_do_not_rebind_instance() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let original = serde_json::to_value(&s.record).unwrap();
    for key in [
        "publication_hash",
        "authority_json",
        "tools_json",
        "launch_json",
        "configuration_json",
    ] {
        let mut value = original.clone();
        value["installed"][key] = json!("changed");
        let bad: Record = serde_json::from_value(value).unwrap();
        s.journal.save(&bad).unwrap();
        assert!(
            s.journal
                .load(INSTALL, s.record.claims.target.as_ref().unwrap())
                .is_err(),
            "{key}"
        );
    }
    s.journal.save(&s.record).unwrap();
    let pristine =
        serde_json::to_value(&s.record.installed.as_ref().unwrap().gateway_stage).unwrap();
    for key in [
        "source_metadata_hash",
        "certificate_identity",
        "certificate_oidc_issuer",
        "image_ref",
        "image_catalog_id",
    ] {
        let mut value = pristine.clone();
        value[key] = json!("changed");
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .iter()
                .filter(|(k, v)| pristine[*k] != **v)
                .count(),
            1,
            "each mutation must be independent: {key}"
        );
        let fresh = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(
            gateway_staging::stage(
                &s.journal,
                &s.staging,
                &mut s.record,
                fresh,
                &s.fixture.launch,
                &s.fixture.selected,
                &mut || Ok(())
            ),
            Err("RUNTIME_GATEWAY_STAGE_QUARANTINED")
        );
    }
}
#[test]
fn task4x_schema1_and_schema2_cannot_be_reinterpreted_as_managed_ingress() {
    let s = Storage::new();
    materials(&s);
    for version in [1, 2] {
        let mut selected = crate::execution::metadata::Selected {
            authority_json: s.fixture.selected.authority_json.clone(),
            tools_json: s.fixture.selected.tools_json.clone(),
            tools: s.fixture.selected.tools.clone(),
            registration_required: true,
        };
        let mut a: serde_json::Value = serde_json::from_slice(&selected.authority_json).unwrap();
        a["schema_version"] = json!(version);
        selected.authority_json = serde_json::to_vec(&a).unwrap();
        assert!(
            s.staging
                .gateway_material(&s.fixture.launch, &selected, &mut || Ok(()))
                .is_err()
        );
        assert_eq!(fs::read_dir(s.root.join("staging")).unwrap().count(), 0);
    }
}
#[test]
fn task4x_complete_inventory_matches_consumer_contract_and_bounded_sources() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let dir = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}"));
    assert_eq!(
        fs::read_dir(&dir).unwrap().count(),
        18 + s.fixture.selected.tools.len()
    );
    assert_eq!(fs::metadata(dir.join("health-token")).unwrap().len(), 43);
    assert_eq!(
        fs::read(dir.join("runtime-revision.json")).unwrap(),
        s.fixture.launch.configuration_json()
    );
    assert_eq!(
        fs::read(dir.join("authority-profile.json")).unwrap(),
        s.fixture.selected.authority_json
    );
    for t in &s.fixture.selected.tools {
        use sha2::{Digest, Sha256};
        let file = format!("tool-{:x}", Sha256::digest(t.reference.as_bytes()));
        assert!(dir.join(file).is_file());
    }
    fs::write(s.root.join("material/m2"), vec![b'x'; 65_537]).unwrap();
    assert!(
        s.staging
            .gateway_material(&s.fixture.launch, &s.fixture.selected, &mut || Ok(()))
            .is_err()
    );
}
