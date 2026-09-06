use super::*;
use crate::{
    execution::{guard_staging, journal::Journal, record::Record},
    secrets::StagingOwner,
};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

struct Storage {
    root: PathBuf,
    fixture: Fixture,
    record: Record,
    journal: Journal,
    staging: StagingOwner,
}
impl Storage {
    fn new() -> Self {
        let root = PathBuf::from("/root").join(format!("task4w-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["journal", "staging", "material"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let journal = Journal::open(&root.join("journal")).unwrap();
        let staging = StagingOwner::open(&root.join("staging"), &root.join("material")).unwrap();
        let mut fixture = Fixture::new();
        fixture.i.network = None;
        fixture.i.network = Some(
            journal
                .reserve_network(&fixture.catalog, INSTALL, &fixture.i)
                .unwrap(),
        );
        let mut record = Record::select(INSTALL, &fixture.i.original, None).unwrap();
        record.instance = INSTANCE.into();
        record.installed = Some(fixture.i.clone());
        journal.save(&record).unwrap();
        Self {
            root,
            fixture,
            record,
            journal,
            staging,
        }
    }
    fn stage(&mut self) -> Result<(), &'static str> {
        let fresh = serde_json::from_value(frozen(&self.fixture)).unwrap();
        guard_staging::stage(
            &self.journal,
            &self.staging,
            &mut self.record,
            fresh,
            &mut || Ok(()),
        )
    }
    fn directory(&self) -> PathBuf {
        self.root
            .join("staging")
            .join(format!("apex-guard-{INSTANCE}"))
    }
    fn reload(&mut self) {
        self.record = self
            .journal
            .load(INSTALL, self.record.claims.target.as_ref().unwrap())
            .unwrap()
            .unwrap();
    }
}

#[test]
fn task4w_protected_create_seal_and_journal_recovery() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let directory = s.directory();
    let file = directory.join("guard-config.json");
    assert_eq!(
        fs::read(&file).unwrap(),
        produce(s.fixture.input()).unwrap().bytes
    );
    for (p, mode) in [(&directory, 0o500), (&file, 0o400)] {
        let stat = fs::metadata(p).unwrap();
        assert_eq!(
            (stat.uid(), stat.gid(), stat.mode() & 0o7777),
            (10001, 10001, mode)
        );
    }
    assert_eq!(fs::metadata(&file).unwrap().nlink(), 1);
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    assert_eq!(fs::read_dir(s.root.join("material")).unwrap().count(), 0);
    let before = fs::metadata(&file).unwrap();
    s.reload();
    let state = serde_json::to_value(&s.record.installed).unwrap();
    assert_eq!(state["guard_stage"]["phase"], "Sealed");
    assert_eq!(state["phase"], "Intent");
    assert_eq!(state["files"], json!({}));
    assert_eq!(state["image_id"], "");
    assert_eq!(state["container_id"], "");
    s.stage().unwrap();
    assert_eq!(fs::metadata(file).unwrap().ino(), before.ino());
    let claims = s.record.claims.clone();
    let root = s.root.clone();
    drop(s);
    let journal = Journal::open(&root.join("journal")).unwrap();
    let mut record = journal
        .load(INSTALL, claims.target.as_ref().unwrap())
        .unwrap()
        .unwrap();
    let staging = StagingOwner::open(&root.join("staging"), &root.join("material")).unwrap();
    let fresh = serde_json::from_value(frozen(&Fixture::new())).unwrap();
    guard_staging::stage(&journal, &staging, &mut record, fresh, &mut || Ok(())).unwrap();
}

#[test]
fn task4w_intent_is_durable_before_any_stage_effect_and_absence_never_recreates() {
    let mut s = Storage::new();
    let fresh = serde_json::from_value(frozen(&s.fixture)).unwrap();
    let mut calls = 0;
    let result = guard_staging::stage(&s.journal, &s.staging, &mut s.record, fresh, &mut || {
        calls += 1;
        if calls == 2 {
            Err("CURRENT_GATE_REFUSED")
        } else {
            Ok(())
        }
    });
    assert!(result.is_err());
    assert!(!s.directory().exists());
    s.reload();
    assert_eq!(
        serde_json::to_value(&s.record.installed).unwrap()["guard_stage"]["phase"],
        "Intent"
    );
    assert!(s.stage().is_err());
    assert!(!s.directory().exists());
}

#[test]
fn task4w_missing_sealed_stage_stays_missing() {
    let mut s = Storage::new();
    s.stage().unwrap();
    fs::rename(s.directory(), s.root.join("retained-quarantine")).unwrap();
    s.reload();
    assert!(s.stage().is_err());
    assert!(!s.directory().exists());
    assert!(
        s.root
            .join("retained-quarantine/guard-config.json")
            .exists()
    );
}

#[test]
fn task4w_current_data_interval_image_signer_and_environment_changes_refuse() {
    let mut s = Storage::new();
    s.stage().unwrap();
    let bytes = fs::read(s.directory().join("guard-config.json")).unwrap();
    for key in [
        "config_json",
        "image_ref",
        "certificate_identity",
        "certificate_oidc_issuer",
    ] {
        let mut value = frozen(&s.fixture);
        value[key] = json!("changed");
        let fresh = serde_json::from_value(value).unwrap();
        assert!(
            guard_staging::stage(&s.journal, &s.staging, &mut s.record, fresh, &mut || Ok(()))
                .is_err()
        );
    }
    let mut value = frozen(&s.fixture);
    value["environment"]["NODE_ENV"] = json!("development");
    let fresh = serde_json::from_value(value).unwrap();
    assert!(
        guard_staging::stage(&s.journal, &s.staging, &mut s.record, fresh, &mut || Ok(())).is_err()
    );
    s.fixture.network_json["valid_from_unix_us"] = json!(NOW - 1);
    s.fixture.catalog =
        NetworkCatalog::parse(&serde_json::to_vec(&s.fixture.network_json).unwrap()).unwrap();
    assert!(
        s.stage().is_err(),
        "even a still-current interval requires a fresh instance"
    );
    assert_eq!(
        fs::read(s.directory().join("guard-config.json")).unwrap(),
        bytes
    );
}

mod faults;
mod journal;
