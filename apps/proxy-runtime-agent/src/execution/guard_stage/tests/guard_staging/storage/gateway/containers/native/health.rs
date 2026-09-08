//! Unsigned health dependency; actual sealed journal, worker, TLS and Docker exec.
use super::*;
use crate::execution::{network_readiness as read, paired::start as start_owner};

#[test]
#[ignore = "exclusive Docker window; exact owned mounted volume and health fixture image"]
fn health_collector_native_controller_worker_journal_and_packaged_probe() {
    let instance = std::env::var("APEX_NETWORK_INSPECTION_INSTANCE").unwrap();
    assert!(crate::shapes::uuid_v7(&instance));
    let mut n = Native::with_setup(
        instance,
        "task4z",
        "APEX_TASK4Z_PROCESS_IMAGE_ID",
        super::super::network_inspection::current::make_current,
    );
    n.finish(&mut || Ok(())).unwrap();
    let until = Instant::now() + Duration::from_secs(60);
    start_owner::run(
        &n.s.journal,
        &n.engine,
        &mut n.s.record,
        &mut || Ok(()),
        &|| Ok(until),
        &AtomicBool::new(false),
    )
    .unwrap();
    let installed = n.s.record.installed.as_ref().unwrap();
    let hashes = read::observe(
        &n.s.journal,
        &n.engine,
        INSTALL,
        installed,
        Instant::now(),
        &AtomicBool::new(false),
        &mut || Ok(()),
    )
    .unwrap();
    let launch = installed
        .attestation(INSTALL)
        .unwrap()
        .unwrap()
        .launch
        .unwrap();
    let binding = proto::ManagedDeploymentBinding {
        installation_id: INSTALL.into(),
        target: installed.original.target.clone(),
        process_instance_id: installed.instance.clone(),
        config_hash: installed.original.config_hash.clone(),
        launch_context_hash: launch.launch_context_hash.clone(),
    };
    let original = serde_json::to_vec(&n.s.record).unwrap();
    let metadata = super::super::network_inspection::current::metadata(&n.s.fixture);
    let reload = Box::new(super::super::network_inspection::current::reload(
        &n.s.fixture,
    ));
    let placeholder = n.s.root.join("health-placeholder-journal");
    fs::create_dir(&placeholder).unwrap();
    fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o700)).unwrap();
    drop(std::mem::replace(
        &mut n.s.journal,
        Journal::open(&placeholder).unwrap(),
    ));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(crate::service::tests::network_inspection::owned_health(
            &n.s.root,
            metadata,
            binding.clone(),
            &hashes,
            &launch,
            reload,
        ));
    }));
    n.s.journal = Journal::open(&n.s.root.join("journal")).unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    let history = n.s.journal.health_record(&binding).unwrap().unwrap();
    assert_eq!(
        history.phase,
        crate::execution::health_record::Phase::Finished
    );
    assert_eq!(history.binding, binding);
    assert!(crate::shapes::hex_hash(&history.exec_id));
    assert_eq!(
        history.container_id,
        n.s.record
            .installed
            .as_ref()
            .unwrap()
            .paired_containers
            .as_ref()
            .unwrap()
            .gateway_id
    );
    assert_eq!(
        serde_json::to_vec(
            &n.s.journal
                .load(INSTALL, binding.target.as_ref().unwrap())
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        original
    );
}
