use super::*;
use std::{io::Write, path::PathBuf};
#[test]
#[ignore = "explicit Rust guard producer export; requires an existing APEX_GUARD_EXPORT_DIR"]
fn export_actual_guard_stage_producer() {
    let directory = PathBuf::from(std::env::var_os("APEX_GUARD_EXPORT_DIR").unwrap());
    assert!(directory.is_absolute() && directory.is_dir());
    let f = Fixture::new();
    let d = produce(f.input()).unwrap();
    for (name,bytes) in [("guard-config.json",d.bytes.clone()),("files.json",serde_json::to_vec(&d.files).unwrap()),
        ("environment.json",serde_json::to_vec(&d.environment).unwrap()),("producer.json",serde_json::to_vec(&serde_json::json!({
            "manifest":d.manifest,"image_catalog_id":d.image_catalog_id,"image_ref":d.image_ref,"now":NOW.to_string(),
            "binding":f.i.network.as_ref().unwrap().binding_hash,"topology":f.document.topology_hash})).unwrap())] {
        std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join(name)).unwrap().write_all(&bytes).unwrap();
    }
}
