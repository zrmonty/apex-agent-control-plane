//! Original installed identity and physical sealed storage, without lease authority.
use super::*;
use crate::execution::{
    network_readiness as read,
    paired::start::{Observation, Receipt, Step},
};
pub(super) mod current;

fn installed() -> Storage {
    let mut s = Storage::new();
    prepared(&mut s);
    let p = s
        .record
        .installed
        .as_mut()
        .unwrap()
        .paired_containers
        .as_mut()
        .unwrap();
    p.phase = Phase::Verified;
    p.gateway_id = "d".repeat(64);
    p.guard_id = "e".repeat(64);
    p.start = Some(Observation {
        schema_version: 1,
        phase: Step::Running,
        gateway_id: p.gateway_id.clone(),
        guard_id: p.guard_id.clone(),
        gateway: Some(Receipt {
            process_hash: "a".repeat(64),
        }),
        guard: Some(Receipt {
            process_hash: "b".repeat(64),
        }),
    });
    s.journal.save(&s.record).unwrap();
    s
}
fn expected(i: &Installed) -> proto::ManagedDeploymentBinding {
    let l: proto::RuntimeLaunchContext = serde_json::from_str(&i.launch_json).unwrap();
    proto::ManagedDeploymentBinding {
        installation_id: INSTALL.into(),
        target: i.original.target.clone(),
        process_instance_id: i.instance.clone(),
        config_hash: i.original.config_hash.clone(),
        launch_context_hash: l.launch_context_hash,
    }
}
#[test]
fn network_inspection_matches_original_installation_after_current_fence_advances() {
    let mut s = installed();
    let b = expected(s.record.installed.as_ref().unwrap());
    s.record.claims.target.as_mut().unwrap().fencing_token += 1;
    s.journal.save(&s.record).unwrap();
    s.reload();
    let i = s.record.installed.as_ref().unwrap();
    assert!(read::binding(INSTALL, i, &b).is_ok());
    let mutations: &[fn(&mut proto::ManagedDeploymentBinding)] = &[
        |b| b.target.as_mut().unwrap().fencing_token += 1,
        |b| b.target.as_mut().unwrap().generation += 1,
        |b| b.target.as_mut().unwrap().workspace_id = "other".into(),
        |b| b.target.as_mut().unwrap().namespace_id = "other".into(),
        |b| b.target.as_mut().unwrap().revision_id = uuid::Uuid::now_v7().to_string(),
        |b| b.installation_id = uuid::Uuid::now_v7().to_string(),
        |b| b.process_instance_id = uuid::Uuid::now_v7().to_string(),
        |b| b.config_hash = "f".repeat(64),
        |b| b.launch_context_hash = "f".repeat(64),
    ];
    for mutate in mutations {
        let mut bad = b.clone();
        mutate(&mut bad);
        assert!(read::binding(INSTALL, i, &bad).is_err());
    }
}
#[test]
fn network_inspection_requires_complete_running_pair_and_never_falls_back() {
    let s = installed();
    let original = s.record.installed.as_ref().unwrap();
    let b = expected(original);
    assert!(read::binding(INSTALL, original, &b).is_ok());
    for field in [
        "pair", "guard", "gateway", "start", "partial", "receipt", "network",
    ] {
        let mut i = original.clone();
        match field {
            "pair" => i.paired_containers = None,
            "guard" => i.guard_stage = None,
            "gateway" => i.gateway_stage = None,
            "network" => i.network = None,
            "start" => i.paired_containers.as_mut().unwrap().start = None,
            "partial" => i.paired_containers.as_mut().unwrap().phase = Phase::ConnectIntent,
            _ => {
                i.paired_containers
                    .as_mut()
                    .unwrap()
                    .start
                    .as_mut()
                    .unwrap()
                    .guard = None
            }
        }
        assert!(read::binding(INSTALL, &i, &b).is_err(), "{field}");
    }
}
#[test]
fn network_inspection_rechecks_sealed_bytes_without_repair_or_journal_write() {
    let s = installed();
    let i = s.record.installed.as_ref().unwrap();
    let before = serde_json::to_vec(&s.record).unwrap();
    let check = |check: &mut dyn FnMut() -> Result<(), &'static str>| {
        read::stages(
            &s.staging,
            i,
            &s.fixture.launch,
            &s.fixture.selected,
            &mut || check(),
        )
    };
    assert!(check(&mut || Ok(())).is_ok());
    assert!(check(&mut || Err("cancelled")).is_err());
    let file = s
        .root
        .join("staging")
        .join(format!("apex-runtime-{}", i.instance))
        .join("instance-proof");
    let bytes = fs::read(&file).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, vec![b'x'; bytes.len()]).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(check(&mut || Ok(())).is_err());
    assert_eq!(fs::read(&file).unwrap(), vec![b'x'; bytes.len()]);
    assert_eq!(
        serde_json::to_vec(
            &s.journal
                .load(INSTALL, i.original.target.as_ref().unwrap())
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        before
    );
}
