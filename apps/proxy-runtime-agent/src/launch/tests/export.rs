//! Explicit local fixture export, never a trusted ResolvedDeployment constructor.
use super::*;
use std::{io::Write, path::PathBuf};

#[test]
#[ignore = "explicit scoped Rust-to-TS artifact export; requires APEX_LAUNCH_EXPORT_DIR"]
fn export_launch_parity_fixture() {
    let directory = PathBuf::from(
        std::env::var_os("APEX_LAUNCH_EXPORT_DIR").expect("export directory required"),
    );
    assert!(
        directory.is_absolute() && directory.is_dir(),
        "existing absolute directory required"
    );
    let prepared = prepared(&document()).unwrap();
    for (name, bytes) in [
        ("launch-context.json", prepared.launch_json()),
        ("runtime-revision.json", prepared.configuration_json()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .expect("new scoped fixture file");
        file.write_all(bytes).expect("write local parity fixture");
    }
}
