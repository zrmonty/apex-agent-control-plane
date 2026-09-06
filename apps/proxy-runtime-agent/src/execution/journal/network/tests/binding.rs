use super::*;
use serde_json::json;
fn selected() -> Installed {
    let mut i = installed();
    let c = catalog();
    let t = i.original.target.as_ref().unwrap();
    i.launch_json = serde_json::to_string(&proto::RuntimeLaunchContext {
        schema_version: 1,
        target: Some(t.clone()),
        config_hash: i.original.config_hash.clone(),
        process_instance_id: i.instance.clone(),
        authority_profile_ref: "live".into(),
        authority_profile_version: "v1".into(),
        ..Default::default()
    })
    .unwrap();
    i.authority_json=json!({"schema_version":3,"catalog_version":"v1","profile":{"mode":"managed_ingress",
        "installation_id":c.installation_id(),"workspace_id":t.workspace_id,"namespace_id":t.namespace_id,"proxy_id":t.proxy_id,
        "host_policy_version":"host-v1","reference":"live","version":"v1",
        "managed":{"network_policy":{"reference":"net","version":"v1"}},
        "governance":{"endpoint":"https://governance.example"},"evidence":{"endpoint":"https://evidence.example"}}}).to_string();
    i
}
#[test]
fn network_binding_selection_joins_purpose_origin_and_exact_selected_identity() {
    let c = catalog();
    let i = selected();
    let prepare = |i: &Installed| crate::execution::network::prepare(&c, c.installation_id(), i, 1);
    assert!(prepare(&i).is_ok());
    for (path, bad) in [
        ("/schema_version", json!(2)),
        ("/profile/mode", json!("managed_preparation")),
        (
            "/profile/installation_id",
            json!(uuid::Uuid::now_v7().to_string()),
        ),
        ("/profile/workspace_id", json!("wrong")),
        ("/profile/namespace_id", json!("wrong")),
        ("/profile/proxy_id", json!(uuid::Uuid::now_v7().to_string())),
        ("/profile/reference", json!("wrong")),
        ("/profile/version", json!("wrong")),
        ("/profile/host_policy_version", json!("wrong")),
        ("/profile/managed/network_policy/reference", json!("wrong")),
        ("/profile/managed/network_policy/version", json!("wrong")),
        (
            "/profile/governance/endpoint",
            json!("https://evidence.example"),
        ),
        (
            "/profile/evidence/endpoint",
            json!("https://evidence.example:444"),
        ),
        (
            "/profile/governance/endpoint",
            json!("https://governance.example/path"),
        ),
        (
            "/profile/governance/endpoint",
            json!("http://governance.example"),
        ),
    ] {
        let mut bad_i = i.clone();
        let mut value: serde_json::Value = serde_json::from_str(&i.authority_json).unwrap();
        *value.pointer_mut(path).unwrap() = bad;
        bad_i.authority_json = value.to_string();
        assert!(prepare(&bad_i).is_err(), "{path}");
    }
    let mut explicit = i.clone();
    let mut a: serde_json::Value = serde_json::from_str(&i.authority_json).unwrap();
    a["profile"]["governance"]["endpoint"] = json!("https://governance.example:443/");
    explicit.authority_json = a.to_string();
    assert!(prepare(&explicit).is_ok());
    assert!(crate::execution::network::prepare(&c, c.installation_id(), &i, 0).is_err());
}
#[test]
fn network_binding_cannot_reinterpret_existing_v1_stage_or_engine_identity() {
    let c = catalog();
    let i = selected();
    for phase in [
        Phase::ProofIntent,
        Phase::StageIntent,
        Phase::Staged,
        Phase::CreateIntent,
        Phase::Installed,
        Phase::Removed,
    ] {
        let mut bad = i.clone();
        bad.phase = phase;
        assert!(crate::execution::network::prepare(&c, c.installation_id(), &bad, 1).is_err());
    }
    for field in 0..4 {
        let mut bad = i.clone();
        match field {
            0 => {
                bad.files.insert("proof".into(), "a".repeat(64));
            }
            1 => bad.image_id = format!("sha256:{}", "a".repeat(64)),
            2 => bad.container_id = "a".repeat(64),
            _ => bad.instance_proof_version = None,
        }
        assert!(crate::execution::network::prepare(&c, c.installation_id(), &bad, 1).is_err());
    }
}
#[test]
fn network_binding_is_omitted_on_legacy_and_original_hash_excludes_only_attachment() {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let c = catalog();
    let mut i = selected();
    let v = serde_json::to_value(&i).unwrap();
    assert!(v.get("network").is_none());
    let binding = j.reserve_network(&c, c.installation_id(), &i).unwrap();
    binding.validate(c.installation_id(), &i).unwrap();
    i.network = Some(binding.clone());
    binding.validate(c.installation_id(), &i).unwrap();
    let mut r =
        crate::execution::record::Record::select(c.installation_id(), &i.original, None).unwrap();
    r.instance = i.instance.clone();
    r.installed = Some(i.clone());
    j.save(&r).unwrap();
    let t = i.original.target.as_ref().unwrap();
    assert!(
        j.load(c.installation_id(), t)
            .unwrap()
            .unwrap()
            .installed
            .unwrap()
            .network
            .is_some()
    );
    for bad in [
        json!(null),
        json!([]),
        json!({}),
        json!([1, 0, "a".repeat(64), "b".repeat(64), "c".repeat(64)]),
    ] {
        let mut v = v.clone();
        v["network"] = bad;
        assert!(serde_json::from_value::<Installed>(v).is_err());
    }
    for field in 0..5 {
        let mut bad = i.clone();
        match field {
            0 => bad.network.as_mut().unwrap().binding_hash = "a".repeat(64),
            1 => bad.network.as_mut().unwrap().schema_version = 2,
            2 => bad.network.as_mut().unwrap().slot = 128,
            3 => bad.original.config_hash = "d".repeat(64),
            _ => bad.phase = Phase::Staged,
        }
        r.installed = Some(bad);
        j.save(&r).unwrap();
        assert!(j.load(c.installation_id(), t).is_err());
    }
}
