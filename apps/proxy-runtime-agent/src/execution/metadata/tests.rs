use super::*;
use serde_json::{Value, json};
mod ingress;
fn documents() -> (Vec<u8>, Value, Value) {
    let id = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
    let image=serde_json::to_vec(&json!({"schema_version":1,"images":[{"id":"gateway","image_ref":format!("example.com/image@sha256:{}","a".repeat(64)),
        "signing":{"certificate_oidc_issuer":"https://accounts.google.com","certificate_identity":"fixture@example.com"}}]})).unwrap();
    let authority = json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":99,"profiles":[{
        "installation_id":id,"workspace_id":"w","namespace_id":"n","proxy_id":id,"host_policy_version":"h1","reference":"live","version":"v1",
        "governance":{"endpoint":"https://governance.example","tls_server_name":"governance.example"},
        "evidence":{"endpoint":"https://evidence.example","tls_server_name":"evidence.example"}}]});
    let tools = json!({"schema_version":1,"version":"v1","valid_from_unix_us":1,"expires_at_unix_us":99,"profiles":[{
        "installation_id":id,"workspace_id":"w","namespace_id":"n","proxy_id":id,"revision_id":id,"host_policy_version":"h1",
        "deployment_bindings_version":"b1","config_hash":"a".repeat(64),"entries":[{"reference":"secret://tool/token","version":"v1","source_name":"token"}]}]});
    (image, authority, tools)
}
fn parse(i: &[u8], a: &Value, t: &Value) -> Result<Catalogs, &'static str> {
    Catalogs::parse(
        i,
        &serde_json::to_vec(a).unwrap(),
        &serde_json::to_vec(t).unwrap(),
    )
}

#[test]
fn managed_preparation_is_explicit_and_schema_one_remains_byte_compatible() {
    let (i, original, t) = documents();
    let legacy = parse(&i, &original, &t).unwrap();
    assert_eq!(
        serde_json::to_value(&legacy.authority.profiles[0].0).unwrap(),
        original["profiles"][0]
    );
    let mut preparation = original.clone();
    preparation["schema_version"] = json!(2);
    preparation["profiles"][0]["mode"] = json!("managed_preparation");
    assert!(
        parse(&i, &preparation, &t).is_ok(),
        "explicit preparation profile"
    );
    for schema in [1, 2, 3] {
        for mode in [
            Value::Null,
            json!(false),
            json!(1),
            json!("serving"),
            json!("managed_preparation"),
        ] {
            let mut invalid = original.clone();
            invalid["schema_version"] = json!(schema);
            invalid["profiles"][0]["mode"] = mode.clone();
            if schema == 2 && mode == json!("managed_preparation") {
                continue;
            }
            assert!(parse(&i, &invalid, &t).is_err(), "{schema}:{mode}");
        }
    }
    preparation["profiles"][0]
        .as_object_mut()
        .unwrap()
        .remove("mode");
    assert!(parse(&i, &preparation, &t).is_err());
    let mut invalid_tools = t.clone();
    invalid_tools["schema_version"] = json!(2);
    assert!(parse(&i, &original, &invalid_tools).is_err());
}
#[test]
fn managed_preparation_mode_refuses_object_and_array_representations() {
    let (image, mut authority, tools) = documents();
    authority["schema_version"] = json!(2);
    authority["profiles"][0]["mode"] = json!("managed_preparation");
    let valid = parse(&image, &authority, &tools).expect("valid schema-2 string control");
    assert!(matches!(
        valid.authority.profiles[0].0.mode,
        Some(AuthorityMode::ManagedPreparation)
    ));
    assert_eq!(
        serde_json::to_value(&valid.authority.profiles[0].0).unwrap()["mode"],
        json!("managed_preparation")
    );
    for mode in [
        json!({"managed_preparation": null}),
        json!({}),
        json!({"other": null}),
        json!({"managed_preparation": "managed_preparation"}),
        json!({"managed_preparation": null, "other": null}),
        json!([]),
        json!(["managed_preparation"]),
        json!([{"managed_preparation": null}]),
    ] {
        authority["profiles"][0]["mode"] = mode.clone();
        assert_eq!(
            parse(&image, &authority, &tools).err(),
            Some(ERROR),
            "mode must be a JSON string, not {mode}"
        );
    }
}

#[test]
fn strict_profiles_refuse_bad_transports_selectors_duplicate_and_oversized_tools() {
    let (i, a, t) = documents();
    let catalog = parse(&i, &a, &t).unwrap();
    assert!(catalog.current(1).is_ok());
    assert!(catalog.current(99).is_err());
    for bad in [
        "http://authority",
        "https://user:secret@authority",
        "https://authority/path",
        "https://authority?token=canary",
        "https://authority#x",
    ] {
        let mut a = a.clone();
        a["profiles"][0]["governance"]["endpoint"] = bad.into();
        assert!(parse(&i, &a, &t).is_err());
    }
    for bad in ["", "*.example", "https://authority", "-invalid.example"] {
        let mut a = a.clone();
        a["profiles"][0]["evidence"]["tls_server_name"] = bad.into();
        assert!(parse(&i, &a, &t).is_err());
    }
    for (field, bad) in [
        ("source_name", "../escape"),
        ("reference", "plain"),
        ("version", ""),
    ] {
        let mut t = t.clone();
        t["profiles"][0]["entries"][0][field] = bad.into();
        assert!(parse(&i, &a, &t).is_err());
    }
    for count in [2, 33] {
        let mut t = t.clone();
        t["profiles"][0]["entries"] = json!(vec![t["profiles"][0]["entries"][0].clone(); count]);
        assert!(parse(&i, &a, &t).is_err());
    }
    let mut extra = a.clone();
    extra["profiles"][0]["governance"]["headers"] = json!({"authorization":"canary"});
    assert!(parse(&i, &extra, &t).is_err());
    let mut duplicate = t.clone();
    duplicate["profiles"]
        .as_array_mut()
        .unwrap()
        .push(t["profiles"][0].clone());
    assert!(parse(&i, &a, &duplicate).is_err());
    let duplicate = serde_json::to_string(&a)
        .unwrap()
        .replacen('{', "{\"schema_version\":1,", 1);
    assert!(Catalogs::parse(&i, duplicate.as_bytes(), &serde_json::to_vec(&t).unwrap()).is_err());
    assert!(Catalogs::parse(&i, b"[]", &serde_json::to_vec(&t).unwrap()).is_err());
    assert!(Catalogs::parse(&i, &vec![b' '; 262_145], &serde_json::to_vec(&t).unwrap()).is_err());
}
