//! Positive storage tests use the real producer, never production admission.
use super::*;
use crate::execution::record::Installed;
use serde_json::json;
mod storage;

fn frozen(f: &Fixture) -> serde_json::Value {
    let data = produce(f.input()).unwrap();
    let image = f
        .catalogs
        .images
        .select(&data.image_catalog_id, &data.image_ref)
        .unwrap();
    json!({
        "schema_version": 1, "phase": "Intent",
        "config_json": String::from_utf8(data.bytes).unwrap(),
        "files": data.files, "manifest": data.manifest,
        "environment": data.environment, "image_catalog_id": data.image_catalog_id,
        "image_ref": data.image_ref, "certificate_identity": image.certificate_identity,
        "certificate_oidc_issuer": image.certificate_oidc_issuer, "topology": f.document
    })
}

#[test]
fn task4w_guard_intent_preserves_exact_producer_bytes_and_legacy_shape() {
    let f = Fixture::new();
    let legacy = serde_json::to_value(&f.i).unwrap();
    assert!(legacy.get("guard_stage").is_none());
    let loaded: Installed = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(loaded).unwrap(), legacy);
    let mut staged = legacy;
    staged["guard_stage"] = frozen(&f);
    let loaded = serde_json::from_value::<Installed>(staged.clone());
    assert!(
        loaded.is_ok(),
        "durable guard intent must deserialize as a strict optional object"
    );
    assert_eq!(serde_json::to_value(loaded.unwrap()).unwrap(), staged);
}

#[test]
fn task4w_guard_record_refuses_ambiguous_shapes() {
    let f = Fixture::new();
    let mut original = serde_json::to_value(&f.i).unwrap();
    original["guard_stage"] = frozen(&f);
    for bad in [json!(null), json!([]), json!({}), json!("Intent")] {
        let mut value = original.clone();
        value["guard_stage"] = bad;
        assert!(serde_json::from_value::<Installed>(value).is_err());
    }
    for key in ["unexpected", "sealed_identity"] {
        let mut value = original.clone();
        value["guard_stage"][key] = json!(null);
        assert!(serde_json::from_value::<Installed>(value).is_err());
    }
    let bytes = serde_json::to_string(&original).unwrap();
    let duplicate = bytes.replace(
        "\"phase\":\"Intent\"",
        "\"phase\":\"Intent\",\"phase\":\"Intent\"",
    );
    assert!(serde_json::from_str::<Installed>(&duplicate).is_err());
}

#[test]
fn task4w_guard_phases_must_be_strings() {
    let f = Fixture::new();
    let mut value = serde_json::to_value(&f.i).unwrap();
    value["guard_stage"] = frozen(&f);
    let mut guard = value.clone();
    guard["guard_stage"]["phase"] = json!({"Intent": null});
    assert!(
        serde_json::from_value::<Installed>(guard).is_err(),
        "guard phase must be a string"
    );
    value["guard_stage"]["topology"]["phase"] = json!({"Observed": null});
    assert!(
        serde_json::from_value::<Installed>(value).is_err(),
        "guard topology phase must be a string"
    );
}
