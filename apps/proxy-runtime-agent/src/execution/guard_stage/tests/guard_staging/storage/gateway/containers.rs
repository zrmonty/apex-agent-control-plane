//! Paired journal and engine boundary regressions; signatures are not simulated grants.
use super::*;
use crate::execution::{
    engine::paired::{self as engine_pair, Role},
    paired::{Pair, Phase},
};
mod native;
mod network_inspection;
mod registration;
mod start;
mod topology;

fn prepared(s: &mut Storage) {
    materials(s);
    assert_eq!(
        paired(s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let i = s.record.installed.as_mut().unwrap();
    i.paired_containers = Some(
        Pair::new(
            i,
            (format!("sha256:{}", "b".repeat(64)), vec!["PATH".into()]),
            (format!("sha256:{}", "c".repeat(64)), vec!["PATH".into()]),
        )
        .unwrap(),
    );
    s.journal.save(&s.record).unwrap();
}

#[test]
fn task4y_paired_intent_roundtrips_without_changing_sealed_stages() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let mut value = serde_json::to_value(s.record.installed.as_ref().unwrap()).unwrap();
    let original = value.clone();
    value["paired_containers"] = json!({
        "schema_version": 1,
        "phase": "Prepared",
        "binding_hash": "a".repeat(64),
        "gateway_image_id": format!("sha256:{}", "b".repeat(64)),
        "guard_image_id": format!("sha256:{}", "c".repeat(64)),
        "gateway_unset_env": ["PATH"],
        "guard_unset_env": ["PATH"],
        "gateway_id": "",
        "guard_id": ""
    });
    let loaded = serde_json::from_value::<crate::execution::record::Installed>(value.clone());
    assert!(
        loaded.is_ok(),
        "verified stopped-pair creation needs durable additive intent"
    );
    assert_eq!(serde_json::to_value(loaded.unwrap()).unwrap(), value);
    value.as_object_mut().unwrap().remove("paired_containers");
    assert_eq!(
        value, original,
        "original stage and ownership bytes must remain unchanged"
    );
}

#[test]
fn task4y_v2_handoff_has_exact_consumer_network_fields_and_guard_has_no_gateway_secrets() {
    let mut s = Storage::new();
    prepared(&mut s);
    let i = s.record.installed.as_ref().unwrap();
    let gateway = engine_pair::environment(INSTALL, i, Role::Gateway).unwrap();
    assert_eq!(gateway.len(), 13);
    for expected in [
        "APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v2",
        "APEX_MCP_NETWORK_PROFILE=isolated-bridge-v1",
        "APEX_MCP_GUARD_ADDRESS=10.240.0.3",
    ] {
        assert!(gateway.iter().any(|e| e == expected), "missing {expected}");
    }
    assert!(gateway.contains(&format!(
        "APEX_MCP_NETWORK_BINDING_SHA256={}",
        i.network.as_ref().unwrap().binding_hash
    )));
    let guard = engine_pair::environment(INSTALL, i, Role::Guard).unwrap();
    assert_eq!(guard.len(), 9);
    assert!(guard.contains(&"APEX_MCP_PROFILE=guard".into()));
    for env in [gateway, guard] {
        assert!(!env.iter().any(|e| e.contains("canary")
            || e.contains("instance-proof")
            || e.contains("LISTEN_HOST")
            || e.contains("LISTEN_PORT")));
    }
}

#[test]
fn task4y_pair_journal_rejects_unknown_duplicate_null_arrays_and_invalid_phases() {
    let mut s = Storage::new();
    prepared(&mut s);
    s.reload();
    let i = s.record.installed.as_ref().unwrap();
    let original = serde_json::to_value(i).unwrap();
    for bad in [json!(null), json!([]), json!({}), json!("Prepared")] {
        let mut v = original.clone();
        v["paired_containers"] = bad;
        assert!(serde_json::from_value::<Installed>(v).is_err());
    }
    for bad in [
        json!(null),
        json!({"Prepared":null}),
        json!("Serving"),
        json!([]),
    ] {
        let mut v = original.clone();
        v["paired_containers"]["phase"] = bad;
        assert!(serde_json::from_value::<Installed>(v).is_err());
    }
    let mut v = original.clone();
    v["paired_containers"]["unexpected"] = json!(null);
    assert!(serde_json::from_value::<Installed>(v).is_err());
    let text = serde_json::to_string(i).unwrap().replace(
        "\"schema_version\":1,\"phase\":\"Prepared\"",
        "\"schema_version\":1,\"phase\":\"Prepared\",\"phase\":\"Prepared\"",
    );
    assert!(serde_json::from_str::<Installed>(&text).is_err());
    for (key, bad) in [
        ("phase", json!("Verified")),
        ("gateway_id", json!("a".repeat(64))),
        ("binding_hash", json!("f".repeat(64))),
        ("gateway_unset_env", json!(["PATH", "PATH"])),
        ("guard_image_id", json!("sha256:bad")),
    ] {
        let mut v = original.clone();
        v["paired_containers"][key] = bad;
        let changed: Installed = serde_json::from_value(v).unwrap();
        assert!(
            changed
                .paired_containers
                .as_ref()
                .unwrap()
                .validate(INSTALL, &changed)
                .is_err(),
            "{key}"
        );
    }
}

#[test]
fn task4y_pair_identity_survives_higher_fence_and_sealed_data_is_immutable() {
    let mut s = Storage::new();
    prepared(&mut s);
    let original = serde_json::to_vec(&s.record.installed).unwrap();
    let mut claims = s.record.claims.clone();
    claims.command_id = uuid::Uuid::now_v7().to_string();
    claims.target.as_mut().unwrap().fencing_token += 1;
    s.record = Record::select(INSTALL, &claims, Some(s.record)).unwrap();
    s.journal.save(&s.record).unwrap();
    s.reload();
    assert_eq!(serde_json::to_vec(&s.record.installed).unwrap(), original);
    let i = s.record.installed.as_ref().unwrap();
    for key in ["instance", "publication_hash", "mount_profile"] {
        let mut v = serde_json::to_value(i).unwrap();
        v[key] = json!("changed");
        let changed: Installed = serde_json::from_value(v).unwrap();
        assert!(
            changed
                .paired_containers
                .as_ref()
                .unwrap()
                .validate(INSTALL, &changed)
                .is_err()
        );
    }
}
