use super::*;
use crate::execution::testing::{self, Hooks, Point};
use std::sync::Arc;
fn directory(s: &Storage) -> PathBuf {
    s.root
        .join("staging")
        .join(format!("apex-runtime-{}", s.record.instance))
}
pub(super) fn hashes(path: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    use sha2::{Digest, Sha256};
    fs::read_dir(path)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            let bytes = zeroize::Zeroizing::new(fs::read(e.path()).unwrap());
            (
                e.file_name().into_string().unwrap(),
                format!("{:x}", Sha256::digest(&*bytes)),
            )
        })
        .collect()
}
fn interrupt(s: &mut Storage, point: Point, effect: impl FnOnce(&Storage)) {
    let hooks = Arc::new(Hooks::default());
    let mut gate = hooks.arm(point);
    // Paths only: the controller acts on the isolated test filesystem while
    // the worker is paused. No test proof bytes are sent through the hook.
    let root = s.root.clone();
    let result = std::thread::scope(|scope| {
        let work = scope.spawn(|| {
            let _scope = testing::enter(&hooks);
            paired(s, &mut || Ok(()))
        });
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(&mut gate.reached)
            .unwrap();
        gate.release(true);
        work.join().unwrap()
    });
    assert!(result.is_err());
    assert_eq!(s.root, root);
    effect(s);
}
#[test]
fn task4x_crash_boundaries_never_regenerate_or_repair_but_recover_complete_seal() {
    for point in [
        Point::GatewayProofIntent,
        Point::GatewayProofGenerated,
        Point::GatewayStageIntent,
        Point::GatewayBeforeDirectory,
        Point::GatewayFile,
        Point::GatewaySealIntent,
        Point::GatewaySealed,
    ] {
        let mut s = Storage::new();
        materials(&s);
        interrupt(&mut s, point, |_| {});
        let path = directory(&s);
        let before = path.exists().then(|| hashes(&path));
        s.reload();
        let root = s.root.clone();
        let claims = s.record.claims.clone();
        // Actually close and reacquire the exclusive journal lock.
        drop(s.journal);
        s.journal = Journal::open(&root.join("journal")).unwrap();
        s.record = s
            .journal
            .load(INSTALL, claims.target.as_ref().unwrap())
            .unwrap()
            .unwrap();
        let result = paired(&mut s, &mut || Ok(()));
        if point == Point::GatewaySealed {
            assert_eq!(result, Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"));
            assert_eq!(
                serde_json::to_value(&s.record.installed).unwrap()["gateway_stage"]["phase"],
                "Sealed"
            );
        } else {
            assert_ne!(
                result,
                Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"),
                "{point:?}"
            );
        }
        assert_eq!(
            path.exists().then(|| hashes(&path)),
            before,
            "retry must leave uncertain state untouched at {point:?}"
        );
    }
}
#[test]
fn task4x_reopen_and_higher_current_fence_preserve_original_hashes_and_proof() {
    let mut s = Storage::new();
    materials(&s);
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let before = hashes(&directory(&s));
    let original = serde_json::to_value(&s.record.installed).unwrap();
    let owner =
        crate::execution::network::owner_hash(s.record.installed.as_ref().unwrap()).unwrap();
    let mut claims = s.record.claims.clone();
    claims.command_id = uuid::Uuid::now_v7().to_string();
    claims.target.as_mut().unwrap().fencing_token += 1;
    s.record = Record::select(INSTALL, &claims, Some(s.record)).unwrap();
    s.journal.save(&s.record).unwrap();
    drop(s.journal);
    s.journal = Journal::open(&s.root.join("journal")).unwrap();
    s.reload();
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    assert_eq!(serde_json::to_value(&s.record.installed).unwrap(), original);
    assert_eq!(
        crate::execution::network::owner_hash(s.record.installed.as_ref().unwrap()).unwrap(),
        owner
    );
    assert_eq!(hashes(&directory(&s)), before);
    let record = serde_json::to_vec(&s.record).unwrap();
    for canary in [
        b"task4x-fixture-material-canary".as_slice(),
        b"task4x-fixture-tool-canary".as_slice(),
    ] {
        assert!(!record.windows(canary.len()).any(|v| v == canary));
    }
    let proof = zeroize::Zeroizing::new(fs::read(directory(&s).join("instance-proof")).unwrap());
    assert!(!record.windows(proof.len()).any(|v| v == *proof));
}
#[test]
fn task4x_recovery_refuses_file_directory_and_root_substitution_without_repair() {
    for fault in [
        "bytes",
        "replacement",
        "symlink",
        "hardlink",
        "missing",
        "extra",
        "file-mode",
        "dir-mode",
        "owner",
        "group",
        "missing-directory",
        "root",
    ] {
        let mut s = Storage::new();
        materials(&s);
        assert_eq!(
            paired(&mut s, &mut || Ok(())),
            Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
        );
        let dir = directory(&s);
        let file = dir.join("instance-proof");
        match fault {
            "bytes" => fs::write(&file, [0u8; 32]).unwrap(),
            "replacement" | "symlink" => {
                let old = s.root.join("original-proof");
                fs::rename(&file, &old).unwrap();
                if fault == "symlink" {
                    std::os::unix::fs::symlink(&old, &file).unwrap();
                } else {
                    fs::copy(&old, &file).unwrap();
                    std::os::unix::fs::chown(&file, Some(10001), Some(10001)).unwrap();
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
                }
            }
            "hardlink" => fs::hard_link(&file, s.root.join("alias")).unwrap(),
            "missing" => fs::rename(&file, s.root.join("original-proof")).unwrap(),
            "extra" => fs::write(dir.join("extra"), b"extra").unwrap(),
            "file-mode" => fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap(),
            "dir-mode" => fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap(),
            "owner" => std::os::unix::fs::chown(&file, Some(0), None).unwrap(),
            "group" => std::os::unix::fs::chown(&file, None, Some(0)).unwrap(),
            "missing-directory" => fs::rename(&dir, s.root.join("original-stage")).unwrap(),
            "root" => {
                fs::rename(s.root.join("staging"), s.root.join("old-root")).unwrap();
                fs::create_dir(s.root.join("staging")).unwrap();
                fs::set_permissions(s.root.join("staging"), fs::Permissions::from_mode(0o700))
                    .unwrap();
                for n in [
                    format!("apex-guard-{INSTANCE}"),
                    format!("apex-runtime-{INSTANCE}"),
                ] {
                    fs::rename(
                        s.root.join("old-root").join(&n),
                        s.root.join("staging").join(n),
                    )
                    .unwrap();
                }
                s.staging =
                    StagingOwner::open(&s.root.join("staging"), &s.root.join("material")).unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&file)
            .ok()
            .map(|v| (v.ino(), v.mode(), v.nlink(), v.uid(), v.gid()));
        s.reload();
        assert_ne!(
            paired(&mut s, &mut || Ok(())),
            Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE"),
            "{fault}"
        );
        assert_eq!(
            fs::symlink_metadata(&file).ok().map(|v| (
                v.ino(),
                v.mode(),
                v.nlink(),
                v.uid(),
                v.gid()
            )),
            before
        );
    }
}
#[test]
#[ignore = "Task4X isolated Linux mount namespace with CAP_SYS_ADMIN; no Docker socket"]
fn task4x_same_inode_file_bind_mount_is_refused_from_seal_intent() {
    let mut s = Storage::new();
    materials(&s);
    interrupt(&mut s, Point::GatewaySealed, |_| {});
    let file = directory(&s).join("instance-proof");
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
    s.reload();
    let result = paired(&mut s, &mut || Ok(()));
    assert!(
        std::process::Command::new("/bin/umount")
            .arg(&file)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(result, Err("RUNTIME_GATEWAY_STAGE_QUARANTINED"));
    assert_eq!(
        paired(&mut s, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
}

#[test]
fn task4x_two_instances_keep_distinct_proofs_and_quarantine_only_the_tampered_stage() {
    let mut one = Storage::new();
    let mut two = Storage::with_instance(&uuid::Uuid::now_v7().to_string());
    materials(&one);
    materials(&two);
    // Share the protected storage root, but retain the two installation-owned
    // journals so one fixture's proxy history never overwrites the other.
    two.staging =
        StagingOwner::open(&one.root.join("staging"), &two.root.join("material")).unwrap();
    assert_eq!(
        paired(&mut one, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    assert_eq!(
        paired(&mut two, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    let two_dir = one
        .root
        .join("staging")
        .join(format!("apex-runtime-{}", two.record.instance));
    let before = hashes(&two_dir);
    assert_ne!(
        hashes(&directory(&one))["instance-proof"],
        before["instance-proof"]
    );
    fs::write(directory(&one).join("instance-proof"), [0u8; 32]).unwrap();
    one.reload();
    two.reload();
    assert_eq!(
        paired(&mut one, &mut || Ok(())),
        Err("RUNTIME_GATEWAY_STAGE_QUARANTINED")
    );
    assert_eq!(
        paired(&mut two, &mut || Ok(())),
        Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
    );
    assert_eq!(hashes(&two_dir), before);
}
