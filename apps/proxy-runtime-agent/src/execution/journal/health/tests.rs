use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = PathBuf::from("/root").join(format!("health-journal-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        assert_eq!(self.0.parent(), Some(std::path::Path::new("/root")));
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("health-journal-")
        );
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn durable_health_history_reopens_and_rejects_conflicting_transition() {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let intent = crate::execution::health_record::tests::record();
    j.health_transition(None, &intent).unwrap();
    let created = Record {
        phase: Phase::Created,
        exec_id: "d".repeat(64),
        ..intent.clone()
    };
    assert!(j.health_transition(None, &created).is_err());
    j.health_transition(Some(&intent), &created).unwrap();
    drop(j);
    let j = Journal::open(&root.0).unwrap();
    assert!(j.health_record(&intent.binding).unwrap().as_ref() == Some(&created));
    let mut wrong = intent.binding.clone();
    wrong.target.as_mut().unwrap().generation += 1;
    assert!(j.health_record(&wrong).is_err());
}
#[test]
fn health_history_disappearance_after_observation_is_quarantined() {
    let root = Root::new();
    let j = Journal::open(&root.0).unwrap();
    let intent = crate::execution::health_record::tests::record();
    j.health_transition(None, &intent).unwrap();
    assert!(j.health_record(&intent.binding).unwrap().is_some());
    fs::remove_file(root.0.join(health_name(&intent.binding).unwrap())).unwrap();
    assert!(j.health_record(&intent.binding).is_err());
    assert!(j.health_transition(None, &intent).is_err());
}
#[test]
fn uncertain_health_write_never_becomes_success_on_a_repeat_read() {
    for point in 1..=3 {
        let root = Root::new();
        let j = Journal::open(&root.0).unwrap();
        let intent = crate::execution::health_record::tests::record();
        document::FAIL_POINT.with(|p| p.set(point));
        assert!(j.health_transition(None, &intent).is_err());
        assert!(
            j.health_record(&intent.binding).is_err(),
            "write boundary {point}"
        );
    }
}
