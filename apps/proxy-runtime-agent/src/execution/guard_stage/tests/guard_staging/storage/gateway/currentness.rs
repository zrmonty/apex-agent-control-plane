use super::*;
use crate::execution::testing::{self, Hooks, Point};
use std::sync::Arc;

#[test]
fn task4x_replacement_during_last_authority_callback_cannot_record_sealed() {
    let mut s = Storage::new();
    materials(&s);
    let file = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}/instance-proof"));
    let old = s.root.join("original-proof");
    let hooks = Arc::new(Hooks::default());
    let _scope = testing::enter(&hooks);
    let count = 18 + s.fixture.selected.tools.len();
    let mut after_read = 0;
    let result = paired(&mut s, &mut || {
        if hooks.count(Point::GatewayRead) == count {
            after_read += 1;
            // Last file check, final aggregate check, then the caller's
            // potentially slow authority callback before durable Sealed.
            if after_read == 3 {
                fs::rename(&file, &old).unwrap();
                fs::copy(&old, &file).unwrap();
                std::os::unix::fs::chown(&file, Some(10001), Some(10001)).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
            }
        }
        Ok(())
    });
    assert!(after_read >= 3);
    assert_ne!(
        result,
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"),
        "the last callback must not allow replacement between validation and journal commit"
    );
    s.reload();
    assert_ne!(
        serde_json::to_value(&s.record.installed).unwrap()["gateway_stage"]["phase"],
        "Sealed"
    );
}

#[test]
fn task4x_currentness_withdrawal_at_each_storage_boundary_stops_effects() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for point in [
        Point::GatewayProofGenerated,
        Point::GatewayBeforeDirectory,
        Point::GatewayFile,
        Point::GatewaySealIntent,
        Point::GatewaySealed,
        Point::GatewayRead,
    ] {
        let mut s = Storage::new();
        materials(&s);
        let dir = s
            .root
            .join("staging")
            .join(format!("apex-runtime-{INSTANCE}"));
        let current = AtomicBool::new(true);
        let hooks = Arc::new(Hooks::default());
        let mut gate = hooks.arm(point);
        std::thread::scope(|scope| {
            let work = scope.spawn(|| {
                let _scope = testing::enter(&hooks);
                paired(&mut s, &mut || {
                    if current.load(Ordering::Acquire) {
                        Ok(())
                    } else {
                        Err("CURRENT_AUTHORITY_CANCEL_DEADLINE_SHUTDOWN_REFUSED")
                    }
                })
            });
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(&mut gate.reached)
                .unwrap();
            let before = dir.exists().then(|| super::recovery::hashes(&dir));
            current.store(false, Ordering::Release);
            gate.release(false);
            assert_ne!(
                work.join().unwrap(),
                Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
            );
            assert_eq!(
                dir.exists().then(|| super::recovery::hashes(&dir)),
                before,
                "{point:?}"
            );
        });
        s.reload();
        assert_ne!(
            serde_json::to_value(&s.record.installed).unwrap()["gateway_stage"]["phase"],
            "Sealed"
        );
    }
}

#[test]
fn task4x_source_rotation_during_read_or_write_is_quarantined() {
    for point in [Point::GatewayFile, Point::GatewayRead] {
        let mut s = Storage::new();
        materials(&s);
        let path = s.root.join("material/m2");
        let hooks = Arc::new(Hooks::default());
        let mut gate = hooks.arm(point);
        std::thread::scope(|scope| {
            let work = scope.spawn(|| {
                let _scope = testing::enter(&hooks);
                paired(&mut s, &mut || Ok(()))
            });
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(&mut gate.reached)
                .unwrap();
            fs::write(&path, b"rotated-fixture-source").unwrap();
            gate.release(false);
            assert_eq!(
                work.join().unwrap(),
                Err("RUNTIME_GATEWAY_STAGE_QUARANTINED")
            );
        });
        s.reload();
        assert_ne!(
            serde_json::to_value(&s.record.installed).unwrap()["gateway_stage"]["phase"],
            "Sealed"
        );
    }
}

#[test]
#[ignore = "Task4X isolated Linux mount namespace with CAP_SYS_ADMIN; no Docker socket"]
fn task4x_same_inode_source_root_bind_mount_is_refused_before_mkdir() {
    let mut s = Storage::new();
    materials(&s);
    let source = s.root.join("material");
    let stage = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{INSTANCE}"));
    let hooks = Arc::new(Hooks::default());
    let mut gate = hooks.arm(Point::GatewayBeforeDirectory);
    let result = std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            paired(&mut s, &mut || Ok(()))
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(&mut gate.reached)
            .unwrap();
        assert!(
            std::process::Command::new("/bin/mount")
                .arg("--bind")
                .arg(&source)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        gate.release(false);
        work.join().unwrap()
    });
    assert!(
        std::process::Command::new("/bin/umount")
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(result, Err("RUNTIME_GATEWAY_STAGE_QUARANTINED"));
    assert!(
        !stage.exists(),
        "a replaced source mount must be refused before stage mkdir"
    );
}
