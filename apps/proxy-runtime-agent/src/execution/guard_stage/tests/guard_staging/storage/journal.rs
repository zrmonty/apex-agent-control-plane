use super::*;

#[test]
fn task4w_guard_record_load_revalidates_joins_bounds_and_hashes() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let value = serde_json::to_value(&s.record.installed.as_ref().unwrap().guard_stage).unwrap();
    let cases = [
        ("config_json", json!("{}")),
        ("config_json", json!("x".repeat(262145))),
        ("files", json!({"guard-config.json": "a".repeat(64)})),
        ("manifest", json!("a".repeat(64))),
        ("environment", json!({})),
        ("image_ref", json!("registry.example/guard:latest")),
        ("certificate_identity", json!("")),
        ("phase", json!("Intent")),
    ];
    for (key, bad) in cases {
        let mut stage = value.clone();
        stage[key] = bad;
        let mut r: Record =
            serde_json::from_value(serde_json::to_value(&s.record).unwrap()).unwrap();
        let mut i = serde_json::to_value(&r.installed).unwrap();
        i["guard_stage"] = stage;
        r.installed = Some(serde_json::from_value(i).unwrap());
        // The checksum is freshly generated, so refusal must be semantic.
        s.journal.save(&r).unwrap();
        assert!(
            s.journal
                .load(INSTALL, r.claims.target.as_ref().unwrap())
                .is_err(),
            "malformed {key}"
        );
    }
}

#[test]
fn task4w_guard_record_cannot_cross_instance_or_topology_or_weaken_network_intent() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let original = serde_json::to_value(&s.record).unwrap();
    for fault in [
        "instance",
        "topology",
        "network",
        "gateway-phase",
        "gateway-files",
        "gateway-image",
        "gateway-container",
    ] {
        let mut value = original.clone();
        let i = &mut value["installed"];
        match fault {
            "instance" => {
                i["guard_stage"]["topology"]["topology"]["instance"] =
                    json!(uuid::Uuid::now_v7().to_string())
            }
            "topology" => i["guard_stage"]["topology"]["topology_hash"] = json!("a".repeat(64)),
            "network" => {
                i.as_object_mut().unwrap().remove("network");
            }
            "gateway-phase" => i["phase"] = json!("Staged"),
            "gateway-files" => i["files"] = json!({"guard-config.json": "a".repeat(64)}),
            "gateway-image" => i["image_id"] = json!("sha256:bad"),
            "gateway-container" => i["container_id"] = json!("a".repeat(64)),
            _ => unreachable!(),
        }
        let record: Record = serde_json::from_value(value).unwrap();
        s.journal.save(&record).unwrap();
        assert!(
            s.journal
                .load(INSTALL, record.claims.target.as_ref().unwrap())
                .is_err(),
            "cross-binding {fault}"
        );
    }
}

#[test]
fn task4w_legacy_checksum_roundtrip_and_owner_hash_are_unchanged() {
    let mut s = Storage::new();
    let before =
        crate::execution::network::owner_hash(s.record.installed.as_ref().unwrap()).unwrap();
    let original = serde_json::to_vec(&s.record).unwrap();
    s.reload();
    assert_eq!(serde_json::to_vec(&s.record).unwrap(), original);
    s.stage().unwrap();
    s.reload();
    assert_eq!(
        crate::execution::network::owner_hash(s.record.installed.as_ref().unwrap()).unwrap(),
        before
    );
}
