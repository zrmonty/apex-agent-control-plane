use super::*;
use crate::execution::{
    journal::Journal,
    network_owner::topology::{Document, Phase, Topology},
    record::Record,
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        assert_eq!(self.0.parent(), Some(std::path::Path::new("/root")));
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("task4u-")
        );
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn protected_history_original_observation_produces_without_writing_stage_or_history() {
    let root = Root(PathBuf::from("/root").join(format!("task4u-{}", uuid::Uuid::now_v7())));
    fs::create_dir(&root.0).unwrap();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o700)).unwrap();
    let j = Journal::open(&root.0).unwrap();
    let mut f = Fixture::new();
    let mut r = Record::select(INSTALL, &f.i.original, None).unwrap();
    r.instance = f.i.instance.clone();
    f.i.network = None;
    f.i.network = Some(j.reserve_network(&f.catalog, INSTALL, &f.i).unwrap());
    r.installed = Some(f.i.clone());
    j.save(&r).unwrap();
    let d =
        Document::prepared(Topology::new(&f.catalog, INSTALL, &f.i, "c".repeat(64), NOW).unwrap())
            .unwrap();
    j.prepare_topology(&d).unwrap();
    let mut intent = d.clone();
    intent.phase = Phase::CreateIntent;
    j.transition_topology(&d, &intent).unwrap();
    let mut observed = intent.clone();
    observed.phase = Phase::Observed;
    observed.observation = Some("d".repeat(64));
    j.transition_topology(&intent, &observed).unwrap();
    drop(j);
    let contents = || -> BTreeMap<_, _> {
        fs::read_dir(&root.0)
            .unwrap()
            .map(|p| {
                let p = p.unwrap().path();
                (p.clone(), fs::read(p).unwrap())
            })
            .collect()
    };
    let before = contents();
    let j = Journal::open(&root.0).unwrap();
    let all = j.topology_history(INSTALL).unwrap();
    let mut input = f.input();
    input.observed = &all[INSTANCE];
    let data = produce(input).unwrap();
    assert!(!data.bytes.is_empty());
    assert_eq!(
        data.environment["APEX_NETWORK_TOPOLOGY_SHA256"],
        observed.topology_hash
    );
    assert_eq!(
        contents(),
        before,
        "data producer must leave protected history unchanged"
    );
    assert!(j.topology_history("wrong-installation").is_err());
    assert!(j.topology_history(INSTALL).is_ok());
}
