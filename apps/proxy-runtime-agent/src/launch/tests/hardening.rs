use super::*;

#[test]
fn rejects_material_grammar_and_types() {
    for (field, values) in [
        (
            "role",
            vec![
                json!(1),
                json!("1"),
                json!("HEALTH_TOKEN"),
                json!("RUNTIME_MATERIAL_ROLE_UNSPECIFIED"),
                json!("LAUNCH_CANARY"),
            ],
        ),
        (
            "reference",
            vec![
                json!("plain-id"),
                json!("secret://"),
                json!("secret://a//b"),
                json!("secret://a/../b"),
                json!("secret://a/./b"),
                json!("secret://-a/b"),
                json!("secret://a?LAUNCH_CANARY"),
                json!("secret://a/%2e"),
                json!("secret://a/"),
                json!(format!("secret://{}", "a".repeat(248))),
            ],
        ),
        (
            "source_name",
            vec![
                json!(""),
                json!("../LAUNCH_CANARY"),
                json!("/absolute"),
                json!("C:\\secret"),
                json!("a/b"),
                json!("a:b"),
                json!("a".repeat(256)),
            ],
        ),
        (
            "version",
            vec![
                json!(""),
                json!("v".repeat(129)),
                json!("../bad"),
                json!("https://LAUNCH_CANARY"),
            ],
        ),
    ] {
        for invalid in values {
            let mut value = document();
            value["profiles"][0]["materials"][0][field] = invalid;
            assert_eq!(
                parse(&value).unwrap_err(),
                LaunchError::InvalidCatalog,
                "{field}"
            );
        }
    }
}

#[test]
fn rejects_catalog_shape_limits_and_missing_fields() {
    for (field, invalid) in [
        ("schema_version", json!(0)),
        ("schema_version", json!(2)),
        ("version", json!("")),
        ("version", json!("v".repeat(129))),
        ("profiles", json!([])),
        ("expires_at_unix_us", json!(u64::MAX)),
        ("expires_at_unix_us", json!(CHECKED - 1)),
    ] {
        let mut value = document();
        value[field] = invalid;
        assert!(parse(&value).is_err());
    }
    for pointer in ["", "/profiles/0", "/profiles/0/materials/0"] {
        let value = document();
        for field in value.pointer(pointer).unwrap().as_object().unwrap().keys() {
            let mut value = value.clone();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(parse(&value).is_err(), "{field}");
        }
    }
    let mut value = document();
    let mut profiles = Vec::new();
    for index in 0..32 {
        let mut profile = value["profiles"][0].clone();
        profile["deployment_bindings_version"] = json!(format!("binding-{index}"));
        profiles.push(profile);
    }
    value["profiles"] = json!(profiles);
    assert!(parse(&value).is_ok());
    let mut extra = value["profiles"][0].clone();
    extra["deployment_bindings_version"] = json!("binding-32");
    value["profiles"].as_array_mut().unwrap().push(extra);
    assert!(parse(&value).is_err());
}

#[test]
fn rejects_decoded_duplicate_keys_and_trailing_documents() {
    let text = serde_json::to_string(&document()).unwrap();
    for (key, alias) in [
        ("schema_version", "schema_versi\\u006fn"),
        ("config_hash", "config_ha\\u0073h"),
        ("role", "ro\\u006ce"),
    ] {
        let duplicate = text.replacen(
            &format!("\"{key}\":"),
            &format!("\"{alias}\":null,\"{key}\":"),
            1,
        );
        assert!(LaunchCatalog::parse(duplicate.as_bytes()).is_err());
    }
    assert!(LaunchCatalog::parse(format!("{text}{{}}").as_bytes()).is_err());
}

#[test]
fn binds_all_output_materials_and_redacts_debug() {
    let mut value = document();
    value["version"] = json!("LAUNCH_CANARY");
    value["profiles"][0]["authority_profile_ref"] = json!("LAUNCH_CANARY");
    let catalog = parse(&value).unwrap();
    let (authority, configuration) = fixture();
    let prepared = catalog
        .prepare_data(&authority, &configuration, "bindings-v1", INSTANCE)
        .unwrap();
    let context = prepared.context();
    assert_eq!(context.target, authority.target);
    assert_eq!(context.config_hash, configuration.config_hash);
    assert_eq!(
        context.runtime_manifest_hash,
        configuration.runtime_manifest_hash
    );
    assert_eq!(context.image_ref, configuration.image_ref);
    for (binding, material) in context.materials.iter().zip(prepared.materials()) {
        assert_eq!(material.workspace_id, configuration.workspace_id);
        assert_eq!(material.namespace_id, configuration.namespace_id);
        assert_eq!(material.proxy_id, configuration.proxy_id);
        assert_eq!(binding.role, i32::from(material.role));
        assert_eq!(binding.reference, material.reference);
        assert_eq!(binding.version, material.version);
    }
    assert!(
        !format!("{catalog:?} {prepared:?} {:?}", prepared.materials()).contains("LAUNCH_CANARY")
    );
    assert!(!String::from_utf8_lossy(prepared.launch_json()).contains("source_name"));
    assert_eq!(
        serde_json::from_slice::<proto::RuntimeConfiguration>(prepared.configuration_json())
            .unwrap(),
        configuration
    );
}

#[test]
fn refuses_forged_configuration_and_target_bindings() {
    let catalog = parse(&document()).unwrap();
    let (authority, configuration) = fixture();
    for field in [
        "workspaceId",
        "namespaceId",
        "proxyId",
        "revisionId",
        "configHash",
        "runtimeManifestHash",
        "imageRef",
        "generation",
    ] {
        let mut json = serde_json::to_value(&configuration).unwrap();
        json[field] = if field == "generation" {
            json!("9007199254740993")
        } else {
            json!("forged")
        };
        let config = serde_json::from_value(json).unwrap();
        assert_eq!(
            catalog
                .prepare_data(&authority, &config, "bindings-v1", INSTANCE)
                .unwrap_err(),
            LaunchError::InvalidConfiguration,
            "{field}"
        );
    }
    for field in ["generation", "fencingToken"] {
        for invalid in [0, u64::MAX] {
            let mut json = serde_json::to_value(&authority).unwrap();
            json["target"][field] = json!(invalid.to_string());
            let authority = serde_json::from_value(json).unwrap();
            assert_eq!(
                catalog
                    .prepare_data(&authority, &configuration, "bindings-v1", INSTANCE)
                    .unwrap_err(),
                LaunchError::InvalidConfiguration
            );
        }
    }
}

#[test]
fn digest_retains_manifest_and_array_order_but_omits_only_launch_selfhash() {
    let prepared = prepared(&document()).unwrap();
    let mut context = prepared.context().clone();
    let expected = context.launch_context_hash.clone();
    context.launch_context_hash = "LAUNCH_CANARY".into();
    assert_eq!(super::super::hash::launch_hash(&context).unwrap(), expected);
    context.runtime_manifest_hash = "b".repeat(64);
    assert_ne!(super::super::hash::launch_hash(&context).unwrap(), expected);
    context = prepared.context().clone();
    context.materials.swap(0, 1);
    assert_ne!(super::super::hash::launch_hash(&context).unwrap(), expected);
    context = prepared.context().clone();
    context.image_ref = "x".repeat(16_384);
    assert_eq!(
        super::super::hash::launch_hash(&context).unwrap_err(),
        LaunchError::Encoding
    );
}
