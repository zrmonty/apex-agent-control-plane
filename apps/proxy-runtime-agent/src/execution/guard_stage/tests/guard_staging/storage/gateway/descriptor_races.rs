//! Real substitutions at the checked-open/read and write/identity windows.
use super::*;
use crate::execution::testing::{self, Gate, Hooks, Point};
use sha2::{Digest, Sha256};
use std::sync::Arc;

fn reached(gate: &mut Gate) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(&mut gate.reached)
        .unwrap();
}

#[test]
#[ignore = "Task4X isolated Linux mount namespace with CAP_SYS_ADMIN; no Docker socket"]
fn task4x_source_read_uses_checked_descriptor_under_transient_bind_substitution() {
    let s = Storage::new();
    materials(&s);
    assert_eq!(s.fixture.launch.materials()[0].source_name, "m1");
    let source = s.root.join("material/m1");
    let alternate = s.root.join("alternate-source");
    fs::write(&alternate, [b'E'; 43]).unwrap();
    fs::set_permissions(&alternate, fs::Permissions::from_mode(0o400)).unwrap();
    let original = fs::metadata(&source).unwrap();
    let hooks = Arc::new(Hooks::default());
    let mut checked = hooks.arm(Point::GatewaySourceChecked);
    let material = std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            s.staging
                .gateway_material(&s.fixture.launch, &s.fixture.selected, &mut || Ok(()))
        });
        reached(&mut checked);
        assert!(
            std::process::Command::new("/bin/mount")
                .arg("--bind")
                .arg(&alternate)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        assert_ne!(fs::metadata(&source).unwrap().ino(), original.ino());
        let mut read = hooks.arm(Point::GatewaySourceRead);
        checked.release(false);
        reached(&mut read);
        assert!(
            std::process::Command::new("/bin/umount")
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        let restored = fs::metadata(&source).unwrap();
        assert_eq!(
            (restored.dev(), restored.ino()),
            (original.dev(), original.ino())
        );
        read.release(false);
        work.join().unwrap().unwrap()
    });
    // Literal fixture bytes, not the production assembler, define the expected hash.
    assert_eq!(
        material.hashes()["health-token"],
        format!("{:x}", Sha256::digest([b'A'; 43]))
    );
    assert_eq!(fs::read_dir(s.root.join("staging")).unwrap().count(), 0);
}

#[test]
fn task4x_writer_refuses_byte_identical_substitution_before_identity_capture() {
    let mut s = Storage::new();
    materials(&s);
    s.stage().unwrap(); // Guard already sealed; the next write is the gateway's.
    let directory = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}"));
    let file = directory.join("authority-profile.json");
    let original = s.root.join("original-written-metadata");
    let hooks = Arc::new(Hooks::default());
    let mut written = hooks.arm(Point::StageWriteComplete);
    let result = std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            paired(&mut s, &mut || Ok(()))
        });
        reached(&mut written);
        let before = fs::metadata(&file).unwrap();
        fs::rename(&file, &original).unwrap();
        fs::copy(&original, &file).unwrap();
        std::os::unix::fs::chown(&file, Some(10001), Some(10001)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(fs::metadata(&file).unwrap().ino(), before.ino());
        written.release(false);
        work.join().unwrap()
    });
    assert_eq!(result, Err("RUNTIME_GATEWAY_STAGE_QUARANTINED"));
    let before = recovery::hashes(&directory);
    s.reload();
    assert_eq!(
        serde_json::to_value(&s.record.installed).unwrap()["gateway_stage"]["phase"],
        "StageIntent"
    );
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_GATEWAY_STAGE_QUARANTINED")
    );
    assert_eq!(recovery::hashes(&directory), before);
}
