use super::*;
use crate::execution::testing::{self, Hooks, Point};
use std::{os::unix::fs::symlink, sync::Arc};

#[test]
fn task4w_sealed_recovery_refuses_substitution_links_extras_permissions_and_owner() {
    for fault in [
        "bytes",
        "replacement",
        "symlink",
        "hardlink",
        "extra",
        "file-mode",
        "dir-mode",
        "owner",
    ] {
        let mut s = Storage::new();
        s.stage().unwrap();
        let dir = s.directory();
        let file = dir.join("guard-config.json");
        match fault {
            "bytes" => fs::write(&file, b"{}").unwrap(),
            "replacement" => {
                let old = s.root.join("original-file");
                fs::rename(&file, &old).unwrap();
                fs::copy(&old, &file).unwrap();
                std::os::unix::fs::chown(&file, Some(10001), Some(10001)).unwrap();
                fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
            }
            "symlink" => {
                let old = s.root.join("original-file");
                fs::rename(&file, &old).unwrap();
                symlink(&old, &file).unwrap();
            }
            "hardlink" => fs::hard_link(&file, s.root.join("alias")).unwrap(),
            "extra" => fs::write(dir.join("extra"), b"unexpected").unwrap(),
            "file-mode" => fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap(),
            "dir-mode" => fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap(),
            "owner" => std::os::unix::fs::chown(&file, Some(0), Some(0)).unwrap(),
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&file).unwrap();
        s.reload();
        assert!(s.stage().is_err(), "recovery must refuse {fault}");
        let after = fs::symlink_metadata(&file).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.nlink()),
            (before.ino(), before.mode(), before.nlink())
        );
    }
}

#[test]
fn task4w_root_replacement_is_refused_even_with_identical_sealed_files() {
    let mut s = Storage::new();
    s.stage().unwrap();
    fs::rename(s.root.join("staging"), s.root.join("old-staging")).unwrap();
    fs::create_dir(s.root.join("staging")).unwrap();
    fs::set_permissions(s.root.join("staging"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(
        s.root
            .join("old-staging")
            .join(format!("apex-guard-{INSTANCE}")),
        s.directory(),
    )
    .unwrap();
    assert!(s.stage().is_err(), "held root must detect replacement");
    s.staging = StagingOwner::open(&s.root.join("staging"), &s.root.join("material")).unwrap();
    assert!(
        s.stage().is_err(),
        "durable identity must detect replacement after reopen"
    );
}

#[test]
fn task4w_interrupted_seal_cannot_adopt_under_replaced_root_after_restart() {
    let mut s = Storage::new();
    let hooks = Arc::new(Hooks::default());
    let mut gate = hooks.arm(Point::GuardSealed);
    std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            s.stage()
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(&mut gate.reached)
            .unwrap();
        gate.release(true);
        assert!(work.join().unwrap().is_err());
    });
    s.reload();
    fs::rename(s.root.join("staging"), s.root.join("old-staging")).unwrap();
    fs::create_dir(s.root.join("staging")).unwrap();
    fs::set_permissions(s.root.join("staging"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::rename(
        s.root
            .join("old-staging")
            .join(format!("apex-guard-{INSTANCE}")),
        s.directory(),
    )
    .unwrap();
    s.staging = StagingOwner::open(&s.root.join("staging"), &s.root.join("material")).unwrap();
    assert!(
        s.stage().is_err(),
        "intent must bind the original root across restart"
    );
}

#[test]
fn task4w_interrupted_intent_never_repairs_partial_stage_but_adopts_complete_seal() {
    for point in [
        Point::GuardIntent,
        Point::GuardDirectory,
        Point::GuardFile,
        Point::GuardSealed,
    ] {
        let mut s = Storage::new();
        let hooks = Arc::new(Hooks::default());
        let mut gate = hooks.arm(point);
        std::thread::scope(|scope| {
            let work = scope.spawn(|| {
                let _scope = testing::enter(&hooks);
                s.stage()
            });
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(&mut gate.reached)
                .unwrap();
            gate.release(true);
            assert!(work.join().unwrap().is_err());
        });
        s.reload();
        assert_eq!(
            serde_json::to_value(&s.record.installed).unwrap()["guard_stage"]["phase"],
            "Intent"
        );
        let before = fs::read_dir(s.root.join("staging")).unwrap().count();
        if point == Point::GuardSealed {
            s.stage().unwrap();
            s.reload();
            assert_eq!(
                serde_json::to_value(&s.record.installed).unwrap()["guard_stage"]["phase"],
                "Sealed"
            );
        } else {
            assert!(s.stage().is_err());
            assert_eq!(
                fs::read_dir(s.root.join("staging")).unwrap().count(),
                before
            );
        }
    }
}

#[test]
fn task4w_gate_withdrawal_after_directory_creation_keeps_quarantine() {
    let mut s = Storage::new();
    let hooks = Arc::new(Hooks::default());
    let mut gate = hooks.arm(Point::GuardDirectory);
    let current = std::sync::atomic::AtomicBool::new(true);
    let fresh = serde_json::from_value(frozen(&s.fixture)).unwrap();
    std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            guard_staging::stage(&s.journal, &s.staging, &mut s.record, fresh, &mut || {
                if current.load(std::sync::atomic::Ordering::Acquire) {
                    Ok(())
                } else {
                    Err("CURRENT_GATE_REFUSED")
                }
            })
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(&mut gate.reached)
            .unwrap();
        current.store(false, std::sync::atomic::Ordering::Release);
        gate.release(false);
        assert!(work.join().unwrap().is_err());
    });
    assert!(s.directory().is_dir());
    assert_eq!(fs::read_dir(s.directory()).unwrap().count(), 0);
    s.reload();
    assert!(s.stage().is_err());
}

#[test]
fn task4w_stat_recheck_detects_file_replacement_during_read() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let file = s.directory().join("guard-config.json");
    let old = s.root.join("before-read");
    let hooks = Arc::new(Hooks::default());
    let mut gate = hooks.arm(Point::GuardRead);
    std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            s.stage()
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(&mut gate.reached)
            .unwrap();
        fs::rename(&file, &old).unwrap();
        fs::copy(&old, &file).unwrap();
        std::os::unix::fs::chown(&file, Some(10001), Some(10001)).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
        gate.release(false);
        assert!(work.join().unwrap().is_err());
    });
}

#[test]
#[ignore = "Task4W isolated Linux mount namespace with CAP_SYS_ADMIN; no Docker socket"]
fn task4w_bind_mount_of_same_file_is_not_adopted_from_intent() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let guard = s
        .record
        .installed
        .as_mut()
        .unwrap()
        .guard_stage
        .as_mut()
        .unwrap();
    guard.phase = guard_staging::Phase::Intent;
    guard.sealed_identity = None;
    s.journal.save(&s.record).unwrap();
    s.reload();
    let file = s.directory().join("guard-config.json");
    let before = fs::metadata(&file).unwrap();
    assert!(
        std::process::Command::new("/bin/mount")
            .arg("--bind")
            .arg(&file)
            .arg(&file)
            .status()
            .unwrap()
            .success()
    );
    let same = fs::metadata(&file).unwrap();
    assert_eq!((same.dev(), same.ino()), (before.dev(), before.ino()));
    let result = s.stage();
    assert!(
        std::process::Command::new("/bin/umount")
            .arg(&file)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        result.is_err(),
        "identical inode/content cannot excuse a foreign file mount"
    );
    s.stage().unwrap();
}
