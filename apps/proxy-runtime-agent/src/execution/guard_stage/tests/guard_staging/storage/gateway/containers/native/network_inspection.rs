//! Fresh unsigned native pair; actual read-only engine observations and exact cleanup.
use super::*;
use crate::execution::{network_readiness as read, paired::start as start_owner};

#[test]
#[ignore = "exclusive Docker window and fresh exact mounted volume required"]
fn network_inspection_native_pair_continuity_and_complete_memberships() {
    let instance =
        std::env::var("APEX_NETWORK_INSPECTION_INSTANCE").expect("fresh announced UUID required");
    assert!(crate::shapes::uuid_v7(&instance));
    eprintln!(
        "NETWORK INSPECTION creating fresh outer=task4z-native-{instance} inner=apex-net-{instance} gateway=apex-runtime-{instance} guard=apex-guard-{instance}"
    );
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
    let i = n.s.record.installed.as_ref().unwrap();
    let p = i.paired_containers.as_ref().unwrap();
    eprintln!(
        "NETWORK INSPECTION created outer={} inner={} gateway={} guard={}",
        n.outer, n.inner, p.gateway_id, p.guard_id
    );
    let original = serde_json::to_vec(&n.s.record).unwrap();
    let before = [
        inspect("network", &n.outer),
        inspect("network", &n.inner),
        inspect("container", &p.gateway_id),
        inspect("container", &p.guard_id),
    ];
    let inspect_pair = |n: &Native, started, cancel: &AtomicBool| {
        read::observe(
            &n.s.journal,
            &n.engine,
            INSTALL,
            i,
            started,
            cancel,
            &mut || Ok(()),
        )
    };
    let actual = inspect_pair(&n, Instant::now(), &AtomicBool::new(false))
        .expect("real complete running pair must inspect");
    assert_eq!(
        actual.0,
        p.start
            .as_ref()
            .unwrap()
            .gateway
            .as_ref()
            .unwrap()
            .process_hash
    );
    assert_eq!(
        actual.1,
        p.start
            .as_ref()
            .unwrap()
            .guard
            .as_ref()
            .unwrap()
            .process_hash
    );
    assert!(
        inspect_pair(
            &n,
            Instant::now() - Duration::from_secs(3),
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(inspect_pair(&n, Instant::now(), &AtomicBool::new(true)).is_err());
    for (kind, id, expected) in [
        ("network", &n.outer, &before[0]),
        ("network", &n.inner, &before[1]),
        ("container", &p.gateway_id, &before[2]),
        ("container", &p.guard_id, &before[3]),
    ] {
        assert_eq!(
            &inspect(kind, id),
            expected,
            "inspection cannot mutate {kind}"
        );
    }
    assert_eq!(
        serde_json::to_vec(
            &n.s.journal
                .load(INSTALL, i.original.target.as_ref().unwrap())
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        original
    );
    let binding = proto::ManagedDeploymentBinding {
        installation_id: INSTALL.into(),
        target: i.original.target.clone(),
        process_instance_id: i.instance.clone(),
        config_hash: i.original.config_hash.clone(),
        launch_context_hash: i
            .attestation(INSTALL)
            .unwrap()
            .unwrap()
            .launch
            .unwrap()
            .launch_context_hash,
    };
    // Transfer the exact journal's exclusive owner to the service, then restore
    // the fixture owner only after the service/physical workers have joined.
    let placeholder = n.s.root.join("inspection-placeholder-journal");
    fs::create_dir(&placeholder).unwrap();
    fs::set_permissions(&placeholder, fs::Permissions::from_mode(0o700)).unwrap();
    drop(std::mem::replace(
        &mut n.s.journal,
        Journal::open(&placeholder).unwrap(),
    ));
    let joined = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(crate::service::tests::network_inspection::owned_pair(
            &n.s.root,
            super::super::network_inspection::current::metadata(&n.s.fixture),
            binding,
            &actual,
        ));
    }));
    n.s.journal = Journal::open(&n.s.root.join("journal")).unwrap();
    if let Err(panic) = joined {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(
        serde_json::to_vec(
            &n.s.journal
                .load(INSTALL, i.original.target.as_ref().unwrap())
                .unwrap()
                .unwrap()
        )
        .unwrap(),
        original
    );
    // A new foreign stopped attachment is invisible to network .Containers, but
    // must be found by the production full configured-container inventory.
    let name = format!("network-inspection-intruder-{}", i.instance);
    eprintln!("NETWORK INSPECTION creating owned adversarial stopped container {name}");
    let foreign = docker(&[
        "container".into(),
        "create".into(),
        "--name".into(),
        name.clone(),
        "--label=io.apex.network-inspection.owner=20260908-a81f".into(),
        "--network".into(),
        n.inner.clone(),
        p.gateway_image_id.clone(),
    ])
    .trim()
    .to_owned();
    assert!(crate::shapes::hex_hash(&foreign));
    eprintln!("NETWORK INSPECTION owned stopped intruder id={foreign}");
    assert!(inspect_pair(&n, Instant::now(), &AtomicBool::new(false)).is_err());
    let v = inspect("container", &foreign);
    assert_eq!(v[0]["Name"], format!("/{name}"));
    assert_eq!(v[0]["State"]["Running"], false);
    assert_eq!(
        v[0]["Config"]["Labels"]["io.apex.network-inspection.owner"],
        "20260908-a81f"
    );
    docker(&["container".into(), "rm".into(), foreign]);
    // Restart is an intentional fixture mutation; identical image/config/network
    // must not hide a changed process identity in the original installed receipt.
    docker(&[
        "container".into(),
        "restart".into(),
        "--time=1".into(),
        p.gateway_id.clone(),
    ]);
    assert!(inspect_pair(&n, Instant::now(), &AtomicBool::new(false)).is_err());
}
