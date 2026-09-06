use super::*;

fn ingress_document() -> (Vec<u8>, Value, Value) {
    let (image, mut authority, tools) = documents();
    authority["schema_version"] = json!(3);
    authority["profiles"][0]["mode"] = json!("managed_ingress");
    authority["profiles"][0]["managed"] = json!({
        "evidence_agent_id":"managed-evidence",
        "upstream_credentials":"managed_upstream_v1",
        "network_policy":{"reference":"isolated-gateway","version":"v1"},
        "ingress":{"port":8080,"tls_server_name":"gateway.example",
            "edge_certificate_sha256":["a".repeat(64)]}
    });
    (image, authority, tools)
}

#[test]
fn explicit_ingress_profile_round_trips_without_changing_legacy_profiles() {
    let (i, a, t) = ingress_document();
    let parsed = parse(&i, &a, &t).expect("explicit managed ingress profile");
    assert_eq!(
        serde_json::to_value(&parsed.authority.profiles[0].0).unwrap(),
        a["profiles"][0]
    );
    let (i, mut a, t) = documents();
    for schema in [1, 2] {
        a["schema_version"] = json!(schema);
        if schema == 2 {
            a["profiles"][0]["mode"] = json!("managed_preparation");
        }
        let parsed = parse(&i, &a, &t).unwrap();
        assert_eq!(
            serde_json::to_value(&parsed.authority.profiles[0].0).unwrap(),
            a["profiles"][0]
        );
    }
}

#[test]
fn schema_mode_and_managed_presence_are_an_exact_contract() {
    let (i, valid, t) = ingress_document();
    for schema in [0, 1, 2, 3, 4] {
        for mode in [
            Value::Null,
            json!("managed_preparation"),
            json!("managed_ingress"),
            json!({"managed_ingress":null}),
            json!([]),
        ] {
            for managed in [
                Value::Null,
                json!([]),
                valid["profiles"][0]["managed"].clone(),
            ] {
                let mut a = valid.clone();
                a["schema_version"] = json!(schema);
                a["profiles"][0]["mode"] = mode.clone();
                a["profiles"][0]["managed"] = managed.clone();
                let expected =
                    schema == 3 && mode == json!("managed_ingress") && managed.is_object();
                assert_eq!(
                    parse(&i, &a, &t).is_ok(),
                    expected,
                    "schema={schema}, mode={mode}, managed={managed}"
                );
            }
        }
    }
    for key in ["mode", "managed"] {
        let mut a = valid.clone();
        a["profiles"][0].as_object_mut().unwrap().remove(key);
        assert!(parse(&i, &a, &t).is_err());
    }
}

#[test]
fn ingress_nested_shapes_pins_and_identifiers_are_strict() {
    let (i, valid, t) = ingress_document();
    for (path, bad) in [
        ("/profiles/0/managed/evidence_agent_id", json!("")),
        (
            "/profiles/0/managed/evidence_agent_id",
            json!("a".repeat(129)),
        ),
        ("/profiles/0/managed/evidence_agent_id", json!("a..b")),
        ("/profiles/0/managed/upstream_credentials", json!("legacy")),
        (
            "/profiles/0/managed/upstream_credentials",
            json!({"managed_upstream_v1":null}),
        ),
        (
            "/profiles/0/managed/network_policy",
            json!(["isolated-gateway", "v1"]),
        ),
        (
            "/profiles/0/managed/network_policy/reference",
            json!("../escape"),
        ),
        ("/profiles/0/managed/network_policy/version", Value::Null),
        (
            "/profiles/0/managed/ingress",
            json!([8080, "gateway.example", ["a".repeat(64)]]),
        ),
        ("/profiles/0/managed/ingress/port", json!(8081)),
        ("/profiles/0/managed/ingress/port", json!(8080.5)),
        ("/profiles/0/managed/ingress/port", json!("8080")),
    ] {
        let mut a = valid.clone();
        *a.pointer_mut(path).unwrap() = bad.clone();
        assert!(parse(&i, &a, &t).is_err(), "{path} {bad}");
    }
    for pins in [
        json!([]),
        Value::Null,
        json!("a".repeat(64)),
        json!(["a".repeat(64), "a".repeat(64)]),
        json!(["a".repeat(64), "b".repeat(64), "c".repeat(64)]),
        json!(["0".repeat(64)]),
        json!(["A".repeat(64)]),
        json!(["a".repeat(63)]),
        json!([false]),
    ] {
        let mut a = valid.clone();
        a["profiles"][0]["managed"]["ingress"]["edge_certificate_sha256"] = pins;
        assert!(parse(&i, &a, &t).is_err());
    }
    let mut rotation = valid.clone();
    rotation["profiles"][0]["managed"]["ingress"]["edge_certificate_sha256"] =
        json!(["a".repeat(64), "b".repeat(64)]);
    assert!(parse(&i, &rotation, &t).is_ok());
    for path in [
        "/profiles/0/managed",
        "/profiles/0/managed/ingress",
        "/profiles/0/managed/network_policy",
    ] {
        let mut a = valid.clone();
        a.pointer_mut(path).unwrap()["unknown"] = json!(true);
        assert!(parse(&i, &a, &t).is_err());
        let keys: Vec<_> = valid
            .pointer(path)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut a = valid.clone();
            a.pointer_mut(path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(parse(&i, &a, &t).is_err(), "missing {path}/{key}");
        }
    }
    let duplicate = serde_json::to_string(&valid).unwrap().replacen(
        "\"port\":8080",
        "\"port\":8080,\"port\":8080",
        1,
    );
    assert!(Catalogs::parse(&i, duplicate.as_bytes(), &serde_json::to_vec(&t).unwrap()).is_err());
}

#[test]
fn ingress_requires_exact_dns_names_without_narrowing_legacy_transports() {
    let (i, valid, t) = ingress_document();
    for name in [
        "",
        "GATEWAY.example",
        "*.example",
        "gateway.example.",
        "127.0.0.1",
        "::1",
        "-gateway",
        "gate_way",
        "a..b",
    ] {
        let mut a = valid.clone();
        a["profiles"][0]["managed"]["ingress"]["tls_server_name"] = json!(name);
        assert!(parse(&i, &a, &t).is_err(), "{name}");
    }
    for endpoint in [
        "https://127.0.0.1",
        "https://other.example",
        "https://GOVERNANCE.example",
        "https://governance.example/path",
        "https://governance.example?",
        "https://governance.example#",
    ] {
        let mut a = valid.clone();
        a["profiles"][0]["governance"]["endpoint"] = json!(endpoint);
        assert!(parse(&i, &a, &t).is_err(), "{endpoint}");
    }
    let (i, mut legacy, t) = documents();
    legacy["profiles"][0]["governance"]["endpoint"] = json!("https://127.0.0.1");
    legacy["profiles"][0]["governance"]["tls_server_name"] = json!("Original.EXAMPLE");
    assert!(parse(&i, &legacy, &t).is_ok());
}
