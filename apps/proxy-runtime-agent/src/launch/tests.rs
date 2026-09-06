use super::*;
use serde_json::{Value, json};
use std::error::Error;

const INSTANCE: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1003";
const INSTALLATION: &str = "0191b7f1-7f2c-7c13-9a61-2f29f2be1004";
const CHECKED: u64 = 9_007_199_254_740_993;

fn fixture() -> (proto::RuntimeAuthoritySnapshot, proto::RuntimeConfiguration) {
    let path = std::env::var_os("APEX_RUNTIME_FIXTURE_PATH").expect("runtime export required");
    let config: proto::RuntimeConfiguration =
        serde_json::from_slice(&std::fs::read(path).expect("read runtime export"))
            .expect("generated runtime export");
    let authority = proto::RuntimeAuthoritySnapshot {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: config.workspace_id.clone(),
            namespace_id: config.namespace_id.clone(),
            proxy_id: config.proxy_id.clone(),
            revision_id: config.revision_id.clone(),
            generation: config.generation,
            fencing_token: CHECKED,
        }),
        installation_id: INSTALLATION.into(),
        host_policy_version: "host-v1".into(),
        config_hash: config.config_hash.clone(),
        checked_at_unix_us: CHECKED,
        lease_expires_at_unix_us: CHECKED + 100,
        ..Default::default()
    };
    (authority, config)
}

fn document() -> Value {
    let (authority, config) = fixture();
    json!({"schema_version":1,"version":"catalog-v1", "valid_from_unix_us":CHECKED,
        "expires_at_unix_us":CHECKED+100, "profiles":[{
        "installation_id":authority.installation_id, "workspace_id":config.workspace_id,
        "namespace_id":config.namespace_id, "proxy_id":config.proxy_id, "revision_id":config.revision_id,
        "host_policy_version":"host-v1", "deployment_bindings_version":"bindings-v1",
        "config_hash":config.config_hash, "authority_profile_ref":"deployment-live",
        "authority_profile_version":"authority-v1", "image_catalog_id":"managed-gateway",
        "materials":(1..=13).map(|n| json!({
            "role":proto::RuntimeMaterialRole::try_from(n).unwrap().as_str_name(),
            "reference":format!("secret://deployment/material-{n}"), "version":"material-v1",
            "source_name":format!("source-{n}")
        })).collect::<Vec<_>>()
    }]})
}

fn parse(value: &Value) -> Result<LaunchCatalog, LaunchError> {
    LaunchCatalog::parse(&serde_json::to_vec(value).unwrap())
}

fn prepared(value: &Value) -> Result<PreparedLaunch, LaunchError> {
    let (authority, config) = fixture();
    parse(value)?.prepare_data(&authority, &config, "bindings-v1", INSTANCE)
}

#[test]
fn prepares_exact_deployment_and_preserves_integer_target() {
    let prepared =
        prepared(&document()).expect("valid deployment must prepare through refusal stub");
    assert_eq!(
        prepared.context().target.as_ref().unwrap().fencing_token,
        CHECKED
    );
    assert_eq!(prepared.context().health.as_ref().unwrap().port, 8081);
    assert_eq!(prepared.context().process_instance_id, INSTANCE);
    assert_eq!(prepared.materials().len(), 13);
    assert_eq!(prepared.image_catalog_id(), "managed-gateway");
    assert_eq!(prepared.catalog_version(), "catalog-v1");
}

#[test]
fn rejects_forged_selector_fields() {
    for field in [
        "installation_id",
        "workspace_id",
        "namespace_id",
        "proxy_id",
        "revision_id",
        "host_policy_version",
        "deployment_bindings_version",
        "config_hash",
    ] {
        let mut value = document();
        value["profiles"][0][field] = json!(match field {
            "installation_id" | "proxy_id" | "revision_id" => INSTANCE.to_owned(),
            "config_hash" => "b".repeat(64),
            _ => "different".into(),
        });
        assert_eq!(
            prepared(&value).unwrap_err(),
            LaunchError::BindingMismatch,
            "{field}"
        );
    }
}

mod export;
mod hardening;

#[test]
fn rejects_invalid_metadata_at_parse_even_in_unselected_profile() {
    for (field, invalid) in [
        ("installation_id", json!("invalid")),
        ("proxy_id", json!("invalid")),
        ("revision_id", json!("invalid")),
        ("workspace_id", json!("../bad")),
        ("authority_profile_ref", json!("https://LAUNCH_CANARY")),
        ("authority_profile_version", json!("x".repeat(129))),
        ("image_catalog_id", json!("../image")),
        ("config_hash", json!("a".repeat(63))),
    ] {
        let mut value = document();
        let mut invalid_profile = value["profiles"][0].clone();
        invalid_profile[field] = invalid;
        value["profiles"]
            .as_array_mut()
            .unwrap()
            .push(invalid_profile);
        assert_eq!(parse(&value).unwrap_err(), LaunchError::InvalidCatalog);
    }
}

#[test]
fn rejects_missing_roles_and_ambiguous_materials_and_selectors() {
    let mut value = document();
    value["profiles"][0]["materials"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(parse(&value).is_err());
    for field in ["role", "reference", "source_name"] {
        let mut value = document();
        value["profiles"][0]["materials"][1][field] =
            value["profiles"][0]["materials"][0][field].clone();
        assert!(parse(&value).is_err());
    }
    let mut value = document();
    let duplicate = value["profiles"][0].clone();
    value["profiles"].as_array_mut().unwrap().push(duplicate);
    assert!(parse(&value).is_err());
}

#[test]
fn rejects_unknown_duplicate_fields_arrays_and_raw_canaries() {
    let text = serde_json::to_string(&document()).unwrap();
    for (key, insertion) in [
        ("schema_version", "\"schema_version\":1,"),
        ("installation_id", "\"installation_id\":\"duplicate\","),
        ("source_name", "\"source_name\":\"duplicate\","),
    ] {
        let duplicated =
            text.replacen(&format!("\"{key}\":"), &format!("{insertion}\"{key}\":"), 1);
        assert!(LaunchCatalog::parse(duplicated.as_bytes()).is_err());
    }
    for pointer in ["", "/profiles/0", "/profiles/0/materials/0"] {
        let mut value = document();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("raw_secret".into(), json!("LAUNCH_CANARY"));
        let error = parse(&value).unwrap_err();
        assert_eq!(error, LaunchError::InvalidCatalog);
        assert!(error.source().is_none());
        assert!(!format!("{error:?} {error}").contains("LAUNCH_CANARY"));
        let mut value = document();
        let object = value.pointer(pointer).unwrap().as_object().unwrap();
        let array = json!(object.values().cloned().collect::<Vec<_>>());
        *value.pointer_mut(pointer).unwrap() = array;
        assert!(parse(&value).is_err());
    }
}

#[test]
fn rejects_secret_overlap_and_invalid_instances() {
    let catalog = parse(&document()).unwrap();
    let (authority, mut config) = fixture();
    config
        .secret_refs
        .push("secret://deployment/material-1".into());
    config.runtime_manifest_hash = crate::runtime_manifest_hash(&config).unwrap();
    assert_eq!(
        catalog
            .prepare_data(&authority, &config, "bindings-v1", INSTANCE)
            .unwrap_err(),
        LaunchError::BindingMismatch
    );
    let (authority, config) = fixture();
    for instance in [
        "",
        "LAUNCH_CANARY",
        "0191B7F1-7f2c-7c13-9a61-2f29f2be1003",
        "0191b7f1-7f2c-4c13-9a61-2f29f2be1003",
    ] {
        assert_eq!(
            catalog
                .prepare_data(&authority, &config, "bindings-v1", instance)
                .unwrap_err(),
            LaunchError::InvalidInstance
        );
    }
}

#[test]
fn uses_exact_half_open_authority_time_and_sql_range() {
    let catalog = parse(&document()).unwrap();
    let (mut authority, config) = fixture();
    for time in [CHECKED - 1, CHECKED + 100] {
        authority.checked_at_unix_us = time;
        assert_eq!(
            catalog
                .prepare_data(&authority, &config, "bindings-v1", INSTANCE)
                .unwrap_err(),
            LaunchError::OutsideValidity
        );
    }
    authority.checked_at_unix_us = CHECKED + 99;
    assert!(
        catalog
            .prepare_data(&authority, &config, "bindings-v1", INSTANCE)
            .is_ok()
    );
    for invalid in [
        json!(0),
        json!(-1),
        json!(u64::MAX),
        json!(1.5),
        json!("9007199254740993"),
        json!(null),
    ] {
        let mut value = document();
        value["valid_from_unix_us"] = invalid;
        assert!(parse(&value).is_err());
    }
    let mut value = document();
    value["expires_at_unix_us"] = json!(CHECKED);
    assert!(parse(&value).is_err());
}

#[test]
fn bounds_original_catalog_and_configuration_bytes() {
    let mut bytes = serde_json::to_vec(&document()).unwrap();
    bytes.resize(262_144, b' ');
    assert!(LaunchCatalog::parse(&bytes).is_ok());
    bytes.push(b' ');
    assert_eq!(
        LaunchCatalog::parse(&bytes).unwrap_err(),
        LaunchError::InvalidCatalog
    );
    let catalog = parse(&document()).unwrap();
    let (authority, mut config) = fixture();
    config.resource_url = "x".repeat(262_144);
    config.runtime_manifest_hash = crate::runtime_manifest_hash(&config).unwrap();
    assert_eq!(
        catalog
            .prepare_data(&authority, &config, "bindings-v1", INSTANCE)
            .unwrap_err(),
        LaunchError::InvalidConfiguration
    );
}
