use super::*;
mod export;
mod fixture;
mod joins;
mod journal;
mod routes;
use fixture::*;

#[test]
fn guard_stage_produces_exact_bounded_data_for_original_observed_topology() {
    let f = Fixture::new();
    let data = produce(f.input()).expect("valid observed preparation must produce guard data");
    let value: serde_json::Value = serde_json::from_slice(&data.bytes).unwrap();
    assert_eq!(value["profile"], "isolated-bridge-v1");
    assert_eq!(value["not_before_unix_us"], "9007199254740993");
    assert_eq!(value["not_after_unix_us"], "9223372036854775807");
    assert_eq!(value["routes"].as_array().unwrap().len(), 3);
    assert_eq!(data.environment.len(), 9);
    assert_eq!(data.image_catalog_id, "guard-v1");
    assert_eq!(data.files.len(), 1);
}
