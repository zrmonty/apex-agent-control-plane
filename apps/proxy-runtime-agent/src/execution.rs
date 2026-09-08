//! Concrete provisioning owner with guarded paired process start and recovery.
//! Process start does not establish readiness or admission.
#[cfg(target_os = "linux")]
mod engine;
#[cfg(target_os = "linux")]
mod gateway_staging;
#[cfg(target_os = "linux")]
mod guard_stage;
#[cfg(target_os = "linux")]
mod guard_staging;
#[cfg(target_os = "linux")]
pub(crate) mod health;
#[cfg(any(test, target_os = "linux"))]
mod health_record;
#[cfg(target_os = "linux")]
mod journal;
#[cfg(target_os = "linux")]
pub(crate) mod metadata;
mod network;
#[cfg(target_os = "linux")]
pub(crate) mod network_owner;
#[cfg(target_os = "linux")]
pub(crate) mod network_readiness;
#[cfg(target_os = "linux")]
mod paired;
#[cfg(target_os = "linux")]
mod pool;
#[cfg(target_os = "linux")]
mod provision;
mod record;
#[cfg(any(test, target_os = "linux"))]
mod reservation;
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod testing;
#[cfg(all(test, target_os = "linux"))]
pub(crate) use engine::fixture_handoff_inspect;
#[cfg(target_os = "linux")]
pub(crate) use pool::{Facility, Resources};

// Explicit private acceptance seam: replay a persisted lost-create-response
// boundary against the real existing container, never fake an engine success.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn fixture_lost_create(
    root: &std::path::Path,
    installation: &str,
    target: &crate::proto::RuntimeTarget,
) {
    let journal = journal::Journal::open(root).unwrap();
    let mut record = journal.load(installation, target).unwrap().unwrap();
    let installed = record.installed.as_mut().unwrap();
    assert!(installed.phase == record::Phase::Installed);
    let stage = root
        .parent()
        .unwrap()
        .join("staging")
        .join(format!("apex-runtime-{}", installed.instance));
    engine::acceptance::sandbox_refusals(installation, installed, &stage);
    installed.phase = record::Phase::CreateIntent;
    installed.container_id.clear();
    journal.save(&record).unwrap();
}

// Fault simulation only: restore the durable pre-attachment record while retaining
// the committed global reservation. Not a power-loss test or production recovery API.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn fixture_network_attachment_gap(
    case: &std::path::Path,
    installation: &str,
    target: &crate::proto::RuntimeTarget,
) {
    let base = std::path::PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap());
    assert_eq!(case.parent(), Some(base.as_path()));
    assert!(
        case.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("task4n-")
    );
    let journal = journal::Journal::open(&case.join("journal")).unwrap();
    let mut r = journal.load(installation, target).unwrap().unwrap();
    let i = r.installed.as_mut().unwrap();
    assert!(i.phase == record::Phase::Intent && i.files.is_empty());
    assert!(i.image_id.is_empty() && i.container_id.is_empty());
    assert!(i.network.take().is_some());
    journal.save(&r).unwrap();
}

// Fault simulation only: exact new fixture root, original record and real network.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn fixture_network_lost_observation(
    case: &std::path::Path,
    installation: &str,
    target: &crate::proto::RuntimeTarget,
) {
    let base = std::path::PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap());
    assert_eq!(case.parent(), Some(base.as_path()));
    assert!(
        case.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("task4p-")
    );
    let journal = journal::Journal::open(&case.join("journal")).unwrap();
    journal.fixture_lost_network_observation(installation, target);
}
