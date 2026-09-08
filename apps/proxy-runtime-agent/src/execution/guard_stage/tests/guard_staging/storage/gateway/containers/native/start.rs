//! Explicit unsigned native process evidence; requires the controller socket window.
use super::*;
use crate::execution::{
    paired::start as start_owner,
    testing::{Hooks, Point},
};
use std::ffi::OsString;
mod adversarial;

pub(super) fn bounded(args: &[String]) -> Vec<u8> {
    let mut arguments: Vec<OsString> = vec!["--host=unix:///run/apex-docker.sock".into()];
    arguments.extend(args.iter().map(OsString::from));
    crate::command::run_until(
        crate::command::CommandInput {
            executable: Path::new("/apex-engine-tools/docker"),
            arguments: &arguments,
            directory: Path::new("/"),
            home: None,
            budget: Duration::from_secs(10),
            cancelled: &AtomicBool::new(false),
        },
        Instant::now() + Duration::from_secs(10),
    )
    .expect("bounded fixture Docker operation refused")
}
pub(super) fn cleanup(n: &Native) {
    let i = n.s.record.installed.as_ref().unwrap();
    let p = i.paired_containers.as_ref().unwrap();
    for role in [Role::Gateway, Role::Guard] {
        let name = role.name(i);
        let ids = docker(&[
            "container".into(),
            "ls".into(),
            "-aq".into(),
            format!("--filter=name=^/{name}$"),
            "--no-trunc".into(),
        ]);
        let id = ids.trim();
        if id.is_empty() {
            continue;
        }
        assert!(crate::shapes::hex_hash(id));
        let v = inspect("container", id);
        assert_eq!(v[0]["Id"], id);
        assert_eq!(v[0]["Name"], format!("/{name}"));
        assert_eq!(v[0]["Image"], role.image(p));
        assert_eq!(
            v[0]["Config"]["Labels"]["io.apex.runtime.pair-binding-hash"],
            p.binding_hash
        );
        assert_eq!(
            v[0]["Config"]["Labels"]["io.apex.runtime.installation-id"],
            INSTALL
        );
        if !role.id(p).is_empty() {
            assert_eq!(id, role.id(p));
        }
        if v[0]["State"]["Running"] == true {
            docker(&[
                "container".into(),
                "stop".into(),
                "--time=2".into(),
                id.into(),
            ]);
        }
        let stopped = inspect("container", id);
        assert_eq!(stopped[0]["Id"], id);
        assert_eq!(stopped[0]["State"]["Running"], false);
        assert_eq!(stopped[0]["State"]["Pid"], 0);
        assert!(matches!(
            stopped[0]["State"]["Status"].as_str(),
            Some("created" | "exited")
        ));
        docker(&["container".into(), "rm".into(), id.into()]);
        eprintln!("TASK4Z removed owned container {id} name={name}");
    }
    for (id, key, expected) in [
        (
            &n.inner,
            "io.apex.runtime.network-topology-hash",
            &n.s.fixture.document.topology_hash,
        ),
        (&n.outer, "io.apex.task4z.owner", &n.outer_name),
    ] {
        let v = inspect("network", id);
        assert_eq!(v[0]["Id"], *id);
        assert_eq!(v[0]["Labels"][key], *expected);
        assert_eq!(v[0]["Containers"], json!({}));
        docker(&["network".into(), "rm".into(), id.clone()]);
        eprintln!("TASK4Z removed owned network {id}");
    }
    eprintln!("TASK4Z retained journal/stages root={}", n.s.root.display());
}
fn fixture(case: u8) -> Native {
    let instance = uuid::Uuid::now_v7().to_string();
    eprintln!("TASK4Z native case={case} fresh instance={instance}");
    let mut n = Native::with_instance(instance, "task4z", "APEX_TASK4Z_PROCESS_IMAGE_ID");
    n.finish(&mut || Ok(())).unwrap();
    n.stopped();
    n
}
fn run(n: &mut Native) -> Result<(), &'static str> {
    let until = Instant::now() + Duration::from_secs(60);
    start_owner::run(
        &n.s.journal,
        &n.engine,
        &mut n.s.record,
        &mut || Ok(()),
        &|| Ok(until),
        &AtomicBool::new(false),
    )
}
fn phase(n: &Native) -> Option<start_owner::Step> {
    n.s.record
        .installed
        .as_ref()
        .unwrap()
        .paired_containers
        .as_ref()
        .unwrap()
        .start
        .as_ref()
        .map(|s| s.phase)
}
fn interrupt(n: &mut Native, point: Point, ordinal: usize) -> Result<(), &'static str> {
    let hooks = Arc::new(Hooks::default());
    let _scope = crate::execution::testing::enter(&hooks);
    let gate = hooks.arm(point);
    std::thread::scope(|threads| {
        let worker = threads.spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let mut gate = gate;
            for index in 1..=ordinal {
                let reached = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(60), &mut gate.reached).await
                });
                if !matches!(reached, Ok(Ok(_))) {
                    drop(gate);
                    return false;
                }
                if index == ordinal {
                    gate.release(true);
                    return true;
                }
                let next = hooks.arm(point);
                gate.release(false);
                gate = next;
            }
            false
        });
        let result = run(n);
        assert!(
            worker.join().unwrap(),
            "native interruption did not reach its boundary"
        );
        result
    })
}
fn marker(id: &str, role: Role) {
    let title = if role == Role::Guard {
        "task4z-read-guard"
    } else {
        "task4z-read-gateway"
    };
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let top = docker(&[
            "container".into(),
            "top".into(),
            id.into(),
            "-eo".into(),
            "uid,gid,pid,args".into(),
        ]);
        let rows: Vec<_> = top.lines().skip(1).collect();
        if rows.len() == 1 {
            let fields: Vec<_> = rows[0].split_whitespace().collect();
            if fields.len() == 4
                && fields[0] == "10001"
                && fields[1] == "10001"
                && fields[2].parse::<u32>().is_ok_and(|pid| pid > 0)
                && fields[3] == title
            {
                return;
            }
        }
        assert!(
            Instant::now() < until,
            "native configured user did not finish sealed-file reads"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "controller window: real unsigned process fixture and exact cleanup"]
fn task4z_native_start_running_reopen_and_mounted_readability() {
    let mut n = fixture(1);
    let original = serde_json::to_value(&n.s.record.installed).unwrap();
    let proof_path =
        n.s.root
            .join("staging")
            .join(Role::Gateway.name(n.s.record.installed.as_ref().unwrap()))
            .join("instance-proof");
    let proof = fs::read(&proof_path).unwrap();
    run(&mut n).unwrap();
    assert_eq!(phase(&n), Some(start_owner::Step::Running));
    let i = n.s.record.installed.as_ref().unwrap();
    let p = i.paired_containers.as_ref().unwrap();
    for role in [Role::Guard, Role::Gateway] {
        marker(role.id(p), role);
        let v = inspect("container", role.id(p));
        assert_eq!(v[0]["State"]["Running"], true);
        adversarial::observations(&n, role, &v);
        eprintln!(
            "TASK4Z running owned container {} role={} readable=true",
            role.id(p),
            role.name(i)
        );
    }
    let recovered = serde_json::to_vec(&n.s.record.installed).unwrap();
    let holder = n.s.root.join("reopen-holder");
    fs::create_dir(&holder).unwrap();
    fs::set_permissions(&holder, fs::Permissions::from_mode(0o700)).unwrap();
    drop(std::mem::replace(
        &mut n.s.journal,
        Journal::open(&holder).unwrap(),
    ));
    n.s.journal = Journal::open(&n.s.root.join("journal")).unwrap();
    n.s.reload();
    // Includes the shared recovery path used ahead of paired provisioning.
    n.finish(&mut || Ok(())).unwrap();
    run(&mut n).unwrap();
    assert_eq!(
        serde_json::to_vec(&n.s.record.installed).unwrap(),
        recovered
    );
    let mut after = serde_json::to_value(&n.s.record.installed).unwrap();
    after["paired_containers"]
        .as_object_mut()
        .unwrap()
        .remove("start");
    assert_eq!(after, original);
    assert_eq!(fs::read(proof_path).unwrap(), proof);
}

#[test]
#[ignore = "controller window: each unknown start intent quarantines without restart"]
fn task4z_native_start_unknown_intents_never_restart() {
    for (case, ordinal, expected) in [
        (2, 1, start_owner::Step::GuardIntent),
        (3, 2, start_owner::Step::GatewayIntent),
    ] {
        let mut n = fixture(case);
        assert!(interrupt(&mut n, Point::StartIntent, ordinal).is_err());
        assert_eq!(phase(&n), Some(expected));
        let before = serde_json::to_vec(&n.s.record.installed).unwrap();
        n.s.reload();
        assert!(run(&mut n).is_err());
        assert_eq!(serde_json::to_vec(&n.s.record.installed).unwrap(), before);
    }
}

#[test]
#[ignore = "controller window: lost start receipts adopt only completed intended effects"]
fn task4z_native_start_completed_receipts_recover_without_restarting() {
    for (case, ordinal, role) in [(4, 1, Role::Guard), (5, 2, Role::Gateway)] {
        let mut n = fixture(case);
        assert!(interrupt(&mut n, Point::StartEffectReturned, ordinal).is_err());
        let p =
            n.s.record
                .installed
                .as_ref()
                .unwrap()
                .paired_containers
                .as_ref()
                .unwrap();
        let id = role.id(p).to_owned();
        let before = inspect("container", &id)[0]["State"].clone();
        n.s.reload();
        run(&mut n).unwrap();
        assert_eq!(phase(&n), Some(start_owner::Step::Running));
        assert_eq!(inspect("container", &id)[0]["State"], before);
    }
}

#[test]
#[ignore = "controller window: only same physical owner can roll back no dispatch"]
fn task4z_native_start_known_no_dispatch_can_retry() {
    for (case, ordinal, expected) in [(6, 1, None), (7, 2, Some(start_owner::Step::GuardObserved))]
    {
        let mut n = fixture(case);
        assert!(interrupt(&mut n, Point::NetworkSpawn, ordinal).is_err());
        assert_eq!(phase(&n), expected);
        n.s.reload();
        run(&mut n).unwrap();
        assert_eq!(phase(&n), Some(start_owner::Step::Running));
    }
}

#[test]
#[ignore = "controller window: exited pair quarantines untouched"]
fn task4z_native_start_exited_guard_is_not_restarted() {
    let mut n = fixture(8);
    run(&mut n).unwrap();
    let id =
        n.s.record
            .installed
            .as_ref()
            .unwrap()
            .paired_containers
            .as_ref()
            .unwrap()
            .guard_id
            .clone();
    docker(&[
        "container".into(),
        "stop".into(),
        "--time=2".into(),
        id.clone(),
    ]);
    let before = inspect("container", &id);
    n.s.reload();
    assert!(run(&mut n).is_err());
    assert_eq!(inspect("container", &id), before);
}
