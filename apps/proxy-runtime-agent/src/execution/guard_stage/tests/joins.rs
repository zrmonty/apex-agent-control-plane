use super::*;
use crate::execution::network_owner::topology::Phase;
use serde_json::{Value, json};

#[test]
fn original_join_tampering_refuses_before_guard_serialization() {
    for field in [
        "instance",
        "generation",
        "installation",
        "configuration",
        "tools",
        "authority",
        "launch",
        "config_hash",
        "binding",
        "topology_hash",
        "observed_id",
        "profile",
        "reference",
        "version",
    ] {
        let mut f = Fixture::new();
        match field {
            "instance" => f.i.instance = uuid::Uuid::now_v7().to_string(),
            "generation" => f.i.original.target.as_mut().unwrap().generation += 1,
            "installation" => f.document.topology.0.installation = uuid::Uuid::now_v7().to_string(),
            "configuration" => f.i.configuration_json.push(' '),
            "tools" => f.i.tools_json.push(' '),
            "authority" => f.i.authority_json.push(' '),
            "launch" => f.i.launch_json.push(' '),
            "config_hash" => f.i.original.config_hash = "c".repeat(64),
            "binding" => f.i.network.as_mut().unwrap().binding_hash = "c".repeat(64),
            "topology_hash" => f.document.topology_hash = "c".repeat(64),
            "observed_id" => f.document.observation = Some("d".repeat(12)),
            "profile" => {
                f.i.authority_json =
                    f.i.authority_json
                        .replace("managed_ingress", "managed_preparation")
            }
            "reference" => f.network_json["profiles"][0]["reference"] = json!("other"),
            "version" => f.network_json["profiles"][0]["version"] = json!("other"),
            _ => unreachable!(),
        }
        f.catalog = NetworkCatalog::parse(&serde_json::to_vec(&f.network_json).unwrap()).unwrap();
        assert!(produce(f.input()).is_err(), "{field}");
    }
}
#[test]
fn only_full_observed_original_geometry_and_current_semantics_produce() {
    for phase in [Phase::Prepared, Phase::CreateIntent] {
        let mut f = Fixture::new();
        f.document.phase = phase;
        f.document.observation = None;
        assert!(produce(f.input()).is_err());
    }
    for field in [
        "source_digest",
        "guard_internal_address",
        "guard_outer_address",
        "gateway_workload_address",
        "internal_subnet",
    ] {
        let mut f = Fixture::new();
        let mut v = serde_json::to_value(&f.document.topology.0).unwrap();
        v[field] = json!("wrong");
        f.document.topology.0 = serde_json::from_value(v).unwrap();
        f.document.topology_hash = f.document.topology.0.digest().unwrap();
        assert!(produce(f.input()).is_err(), "{field}");
    }
    let mut f = Fixture::new();
    f.network_json["profiles"][0]["grants"][0]["cidrs"] = json!(["10.30.0.0/25"]);
    f.catalog = NetworkCatalog::parse(&serde_json::to_vec(&f.network_json).unwrap()).unwrap();
    assert!(
        produce(f.input()).is_err(),
        "same selector with changed policy is not renewal"
    );
}
#[test]
fn renewed_current_interval_never_rewrites_historical_topology_or_hash() {
    let mut f = Fixture::new();
    let old = serde_json::to_vec(&f.document).unwrap();
    f.network_json["valid_from_unix_us"] = json!(NOW + 10);
    f.network_json["expires_at_unix_us"] = json!(NOW + 20);
    f.catalog = NetworkCatalog::parse(&serde_json::to_vec(&f.network_json).unwrap()).unwrap();
    for (now, expected) in [
        (NOW + 9, false),
        (NOW + 10, true),
        (NOW + 19, true),
        (NOW + 20, false),
        (i64::MAX as u64, false),
    ] {
        let mut input = f.input();
        input.now = now;
        input.source_digest = "e".repeat(64);
        let result = produce(input);
        assert_eq!(result.is_ok(), expected, "{now}");
        if let Ok(data) = result {
            let v: Value = serde_json::from_slice(&data.bytes).unwrap();
            assert_eq!(v["not_before_unix_us"], "9007199254741003");
            assert_eq!(v["not_after_unix_us"], "9007199254741013");
            assert_eq!(v["network_topology_sha256"], f.document.topology_hash);
        }
    }
    assert_eq!(serde_json::to_vec(&f.document).unwrap(), old);
}
#[test]
fn original_configuration_unknown_duplicate_and_inexact_integer_bytes_refuse() {
    let f = Fixture::new();
    let original = f.i.configuration_json.clone();
    for bad in [
        original.replacen('{', "{\"unknown\":true,", 1),
        original.replacen("\"generation\":", "\"generation\":\"1\",\"generation\":", 1),
        original.replace("\"generation\":\"1\"", "\"generation\":1.0"),
        original.replace("\"generation\":\"1\"", "\"generation\":\"01\""),
        original.replace("\"generation\":\"1\"", "\"generation\":\"1e0\""),
        " ".repeat(262145),
    ] {
        assert_ne!(bad, original);
        let mut f = Fixture::new();
        f.i.configuration_json = bad;
        assert!(produce(f.input()).is_err());
    }
}
#[test]
fn selected_guard_image_has_no_gateway_fallback() {
    let mut f = Fixture::new();
    for (key, value) in [
        ("guard_image_catalog_id", json!("missing")),
        (
            "guard_image_ref",
            json!(format!("registry.example/guard@sha256:{}", "e".repeat(64))),
        ),
    ] {
        f.network_json["profiles"][0][key] = value;
        f.rebind();
        assert!(produce(f.input()).is_err());
    }
}
#[test]
fn deterministic_exact_bytes_one_file_manifest_and_environment() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    let a = produce(f.input()).unwrap();
    let b = produce(f.input()).unwrap();
    assert_eq!(a.bytes, b.bytes);
    assert!(a.bytes.len() <= 262144);
    assert_eq!(
        a.files["guard-config.json"],
        format!("{:x}", Sha256::digest(&a.bytes))
    );
    let map = format!(
        "{{\"guard-config.json\":\"{}\"}}",
        a.files["guard-config.json"]
    );
    assert_eq!(a.manifest, format!("{:x}", Sha256::digest(map)));
    assert_eq!(
        a.environment,
        BTreeMap::from([
            ("NODE_ENV".into(), "production".into()),
            ("HOME".into(), "/tmp/apex".into()),
            ("APEX_MCP_PROFILE".into(), "guard".into()),
            ("APEX_MCP_GUARD_BOOTSTRAP".into(), "sealed-stage-v1".into()),
            ("APEX_INSTALLATION_ID".into(), INSTALL.into()),
            ("APEX_PROCESS_INSTANCE_ID".into(), INSTANCE.into()),
            ("APEX_STAGE_MANIFEST_SHA256".into(), a.manifest.clone()),
            (
                "APEX_NETWORK_BINDING_SHA256".into(),
                f.i.network.as_ref().unwrap().binding_hash.clone()
            ),
            (
                "APEX_NETWORK_TOPOLOGY_SHA256".into(),
                f.document.topology_hash.clone()
            )
        ])
    );
    assert_eq!(
        a.image_ref,
        format!("registry.example/guard@sha256:{}", "b".repeat(64))
    );
}
