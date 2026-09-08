use super::*;
use crate::execution::testing::{Hooks, Point};

pub(super) fn interrupt(n: &mut Native, point: Point, ordinal: usize) -> Result<(), &'static str> {
    let hooks = Arc::new(Hooks::default());
    let _scope = crate::execution::testing::enter(&hooks);
    let gate = hooks.arm(point);
    std::thread::scope(|threads| {
        threads.spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut gate = gate;
            for step in 1..=ordinal {
                runtime
                    .block_on(async {
                        tokio::time::timeout(Duration::from_secs(60), &mut gate.reached).await
                    })
                    .unwrap()
                    .unwrap();
                if step == ordinal {
                    gate.release(true);
                    return;
                }
                let next = hooks.arm(point);
                gate.release(false);
                gate = next;
            }
        });
        n.finish(&mut || Ok(()))
    })
}

#[test]
#[ignore = "controller-owned native socket/volume; lost physical create/connect receipts"]
fn task4y_native_pair_recovers_each_completed_effect_without_recreation() {
    for (ordinal, phase) in [
        (1, Phase::GatewayIntent),
        (2, Phase::GuardIntent),
        (3, Phase::ConnectIntent),
    ] {
        let mut n = Native::new();
        assert!(interrupt(&mut n, Point::PairEffectReturned, ordinal).is_err());
        assert_eq!(n.phase(), phase);
        let i = n.s.record.installed.as_ref().unwrap();
        let name = if ordinal == 1 {
            Role::Gateway.name(i)
        } else {
            Role::Guard.name(i)
        };
        let id = inspect("container", &name)[0]["Id"]
            .as_str()
            .unwrap()
            .to_owned();
        let proof = fs::read(
            n.s.root
                .join("staging")
                .join(Role::Gateway.name(i))
                .join("instance-proof"),
        )
        .unwrap();
        let claims = n.s.record.claims.clone();
        let root = n.s.root.clone();
        // Reopen the actual journal owner, not just deserialize a synthetic record.
        fs::create_dir(root.join("reopen-holder")).unwrap();
        fs::set_permissions(
            root.join("reopen-holder"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let replacement = Journal::open(&root.join("reopen-holder")).unwrap();
        drop(std::mem::replace(&mut n.s.journal, replacement));
        n.s.journal = Journal::open(&root.join("journal")).unwrap();
        n.s.record =
            n.s.journal
                .load(INSTALL, claims.target.as_ref().unwrap())
                .unwrap()
                .unwrap();
        n.finish(&mut || Ok(())).unwrap();
        assert_eq!(n.phase(), Phase::Verified);
        assert_eq!(inspect("container", &name)[0]["Id"], id);
        let i = n.s.record.installed.as_ref().unwrap();
        assert_eq!(
            fs::read(
                n.s.root
                    .join("staging")
                    .join(Role::Gateway.name(i))
                    .join("instance-proof")
            )
            .unwrap(),
            proof
        );
        n.stopped();
    }
}

#[test]
#[ignore = "controller-owned native socket/volume; pre-dispatch refusal has no engine effect"]
fn task4y_native_pair_final_dispatch_refusal_rolls_back_only_known_no_dispatch() {
    for ordinal in 1..=3 {
        let mut n = Native::new();
        assert!(interrupt(&mut n, Point::NetworkSpawn, ordinal).is_err());
        let expected = [
            Phase::Prepared,
            Phase::GatewayObserved,
            Phase::GuardObserved,
        ][ordinal - 1];
        assert_eq!(n.phase(), expected);
        n.s.reload();
        assert_eq!(n.phase(), expected);
        n.finish(&mut || Ok(())).unwrap();
        assert_eq!(n.phase(), Phase::Verified);
    }
}

#[test]
#[ignore = "controller-owned native socket/volume; cancellation/deadline/shutdown refuse effects"]
fn task4y_native_pair_cancel_deadline_and_shutdown_remain_prepared() {
    let mut n = Native::new();
    for error in [
        "RUNTIME_CANCELLED",
        "RUNTIME_LEASE_EXPIRED",
        "RUNTIME_SHUTTING_DOWN",
    ] {
        assert_eq!(n.finish(&mut || Err(error)), Err(error));
        assert_eq!(n.phase(), Phase::Prepared);
    }
    let result = transition::finish(
        &n.s.journal,
        &n.engine,
        &mut n.s.record,
        &mut || Ok(()),
        &|| Ok(Instant::now() + Duration::from_secs(30)),
        &AtomicBool::new(true),
    );
    assert!(result.is_err());
    assert_eq!(n.phase(), Phase::Prepared);
    let result = transition::finish(
        &n.s.journal,
        &n.engine,
        &mut n.s.record,
        &mut || Ok(()),
        &|| Ok(Instant::now() - Duration::from_secs(1)),
        &AtomicBool::new(false),
    );
    assert!(result.is_err());
    assert_eq!(n.phase(), Phase::Prepared);
}

#[test]
#[ignore = "controller-owned stopped pair only; extra configured gateway attachment is quarantined"]
fn task4y_native_pair_quarantines_extra_stopped_membership_without_repair() {
    let mut n = Native::new();
    n.finish(&mut || Ok(())).unwrap();
    let original = serde_json::to_vec(&n.s.record.installed).unwrap();
    let p =
        n.s.record
            .installed
            .as_ref()
            .unwrap()
            .paired_containers
            .as_ref()
            .unwrap();
    let gateway = p.gateway_id.clone();
    let guard = p.guard_id.clone();
    docker(&[
        "network".into(),
        "connect".into(),
        "--ip=10.247.252.4".into(),
        n.outer.clone(),
        gateway.clone(),
    ]);
    assert!(n.finish(&mut || Ok(())).is_err());
    n.s.reload();
    assert_eq!(serde_json::to_vec(&n.s.record.installed).unwrap(), original);
    assert_eq!(
        inspect("container", &gateway)[0]["NetworkSettings"]["Networks"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        inspect("container", &guard)[0]["State"]["Status"],
        "created"
    );
}
