use super::*;
use std::{fs, os::unix::fs::PermissionsExt};
mod lifetime;
#[test]
fn protected_journal_exclusivity_restart_and_corrupt_replacements() {
    let root =
        std::path::PathBuf::from("/root").join(format!("task3a-journal-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let install = uuid::Uuid::now_v7().to_string();
    let claims = proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: Some(proto::RuntimeTarget {
            workspace_id: "w".into(),
            namespace_id: "n".into(),
            proxy_id: uuid::Uuid::now_v7().to_string(),
            revision_id: uuid::Uuid::now_v7().to_string(),
            generation: 1,
            fencing_token: 1,
        }),
        operation_id: uuid::Uuid::now_v7().to_string(),
        command_id: uuid::Uuid::now_v7().to_string(),
        config_hash: "a".repeat(64),
    };
    let t = claims.target.as_ref().unwrap();
    let key = Journal::key(&install, t);
    let j = Journal::open(&root).unwrap();
    assert!(Journal::open(&root).is_err());
    assert!(j.load(&install, t).unwrap().is_none());
    let r = Record::select(&install, &claims, None).unwrap();
    let instance = r.instance.clone();
    j.save(&r).unwrap();
    drop(j);
    let mut j = Journal::open(&root).unwrap();
    assert_eq!(j.load(&install, t).unwrap().unwrap().instance, instance);
    let legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join(&key)).unwrap()).unwrap();
    assert!(
        legacy["record"].get("replay_floor").is_none(),
        "legacy serialized layout must omit None; reopening verified its original checksum"
    );
    for _ in 0..130 {
        let mut next = claims.clone();
        next.command_id = uuid::Uuid::now_v7().to_string();
        let r = Record::select(&install, &next, j.load(&install, t).unwrap()).unwrap();
        j.save(&r).unwrap();
        drop(j);
        j = Journal::open(&root).unwrap();
        let recovered = j.load(&install, t).unwrap().unwrap();
        assert_eq!(recovered.instance, instance);
        assert_eq!(recovered.original, claims);
        assert!(recovered.commands.len() <= 64);
    }
    assert!(Record::select(&install, &claims, j.load(&install, t).unwrap()).is_err());
    let retained = j.load(&install, t).unwrap().unwrap();
    for floor in ["invalid".to_owned(), retained.claims.command_id.clone()] {
        let mut poison: Record =
            serde_json::from_slice(&serde_json::to_vec(&retained).unwrap()).unwrap();
        poison.replay_floor = Some(floor);
        j.save(&poison).unwrap();
        assert!(
            j.load(&install, t).is_err(),
            "valid checksum cannot authorize invalid tombstone"
        );
    }
    j.save(&retained).unwrap();
    let original = fs::read(root.join(&key)).unwrap();
    let mut corrupt: serde_json::Value = serde_json::from_slice(&original).unwrap();
    corrupt["record"]["instance"] = uuid::Uuid::now_v7().to_string().into();
    for bytes in [
        serde_json::to_vec(&corrupt).unwrap(),
        b"[]".to_vec(),
        vec![b' '; LIMIT + 1],
        String::from_utf8(original.clone())
            .unwrap()
            .replacen('{', "{\"digest\":\"bad\",", 1)
            .into_bytes(),
    ] {
        fs::write(root.join(&key), bytes).unwrap();
        assert!(j.load(&install, t).is_err());
    }
    fs::write(root.join(&key), original).unwrap();
    fs::set_permissions(root.join(&key), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(j.load(&install, t).is_err());
    drop(j);
    fs::remove_file(root.join(&key)).unwrap();
    fs::remove_file(root.join("owner.lock")).unwrap();
    fs::remove_dir(root).unwrap();
}
