//! Start intent uses the real sealed-stage and journal boundaries.
use super::*;

fn verified(s: &mut Storage) {
    prepared(s);
    let p = s
        .record
        .installed
        .as_mut()
        .unwrap()
        .paired_containers
        .as_mut()
        .unwrap();
    p.phase = Phase::Verified;
    p.gateway_id = "d".repeat(64);
    p.guard_id = "e".repeat(64);
    p.start = Some(crate::execution::paired::start::Observation {
        schema_version: 1,
        phase: crate::execution::paired::start::Step::Running,
        gateway_id: p.gateway_id.clone(),
        guard_id: p.guard_id.clone(),
        guard: Some(crate::execution::paired::start::Receipt {
            process_hash: "a".repeat(64),
        }),
        gateway: Some(crate::execution::paired::start::Receipt {
            process_hash: "b".repeat(64),
        }),
    });
    s.journal.save(&s.record).unwrap();
}

#[test]
fn task4z_running_network_observation_requires_original_network_and_endpoint_identity() {
    let mut s = Storage::new();
    verified(&mut s);
    let i = s.record.installed.as_ref().unwrap();
    let mut v = topology::observation(Role::Gateway);
    v["Id"] = json!("d".repeat(64));
    v["State"] = json!({"Running":true});
    v["NetworkSettings"]["SandboxID"] = json!("f".repeat(64));
    v["NetworkSettings"]["SandboxKey"] = json!("/var/run/docker/netns/ffffffffffff");
    let name = format!("apex-net-{INSTANCE}");
    let e = &mut v["NetworkSettings"]["Networks"][&name];
    e["NetworkID"] = json!("d".repeat(64));
    e["EndpointID"] = json!("a".repeat(64));
    e["IPAddress"] = json!("10.240.0.2");
    e["IPPrefixLen"] = json!(29);
    e["MacAddress"] = json!("02:42:0a:f0:00:02");
    e["DNSNames"] = json!([format!("apex-runtime-{INSTANCE}"), "dddddddddddd"]);
    assert!(
        engine_pair::inspect::networks(&v, i, Role::Gateway, "protected-outer", false).is_ok(),
        "intended running gateway needs independently checked active endpoints"
    );
    for (key, bad) in [
        ("NetworkID", json!("b".repeat(64))),
        ("IPAddress", json!("10.240.0.4")),
        ("EndpointID", json!("")),
        ("IPPrefixLen", json!(24)),
        ("Gateway", json!("10.240.0.1")),
    ] {
        let mut bad_v = v.clone();
        bad_v["NetworkSettings"]["Networks"][&name][key] = bad;
        assert!(
            engine_pair::inspect::networks(&bad_v, i, Role::Gateway, "protected-outer", false)
                .is_err(),
            "{key}"
        );
    }
    let mut legacy = i.clone();
    legacy.paired_containers.as_mut().unwrap().start = None;
    assert!(
        engine_pair::inspect::networks(&v, &legacy, Role::Gateway, "protected-outer", false)
            .is_err()
    );
}

#[test]
fn task4z_start_intent_reopens_without_replacing_verified_pair_ownership() {
    let mut s = Storage::new();
    prepared(&mut s);
    let i = s.record.installed.as_mut().unwrap();
    let p = i.paired_containers.as_mut().unwrap();
    p.phase = Phase::Verified;
    p.gateway_id = "d".repeat(64);
    p.guard_id = "e".repeat(64);
    let original = serde_json::to_value(&i).unwrap();
    let mut value = original.clone();
    value["paired_containers"]["start"] = json!({
        "schema_version":1, "phase":"GuardIntent",
        "gateway_id":"d".repeat(64), "guard_id":"e".repeat(64)
    });
    let loaded = serde_json::from_value::<Installed>(value);
    assert!(
        loaded.is_ok(),
        "start intent must preserve the verified pair and reopen durably"
    );
    s.record.installed = Some(loaded.unwrap());
    s.journal.save(&s.record).unwrap();
    s.reload();
    let mut recovered = serde_json::to_value(&s.record.installed).unwrap();
    assert_eq!(
        recovered["paired_containers"]["start"]["phase"],
        "GuardIntent"
    );
    recovered["paired_containers"]
        .as_object_mut()
        .unwrap()
        .remove("start");
    assert_eq!(recovered, original);
}

#[test]
fn task4z_start_journal_refuses_invalid_observation_and_cross_pair_identity() {
    let mut s = Storage::new();
    verified(&mut s);
    s.reload();
    let i = s.record.installed.as_ref().unwrap();
    let original = serde_json::to_value(i).unwrap();
    for bad in [json!(null), json!([]), json!({}), json!("Running")] {
        let mut v = original.clone();
        v["paired_containers"]["start"] = bad;
        assert!(serde_json::from_value::<Installed>(v).is_err());
    }
    for (key, bad) in [
        ("phase", json!({"Running":null})),
        ("phase", json!("Serving")),
        ("phase", json!(null)),
        ("guard", json!(null)),
        ("guard", json!([])),
        ("extra", json!(false)),
    ] {
        let mut v = original.clone();
        v["paired_containers"]["start"][key] = bad;
        assert!(serde_json::from_value::<Installed>(v).is_err(), "{key}");
    }
    for (key, bad) in [
        ("phase", json!("GuardIntent")),
        ("schema_version", json!(2)),
        ("guard_id", json!("f".repeat(64))),
        ("gateway_id", json!("e".repeat(64))),
        ("guard", json!({"process_hash":"bad"})),
    ] {
        let mut v = original.clone();
        v["paired_containers"]["start"][key] = bad;
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
    let bytes = serde_json::to_string(i).unwrap().replace(
        "\"phase\":\"Running\"",
        "\"phase\":\"Running\",\"phase\":\"Running\"",
    );
    assert!(serde_json::from_str::<Installed>(&bytes).is_err());
}
