//! Mutated native observations and owned-resource negative recovery cases.
use super::*;

pub(super) fn observations(n: &Native, role: Role, original: &serde_json::Value) {
    let i = n.s.record.installed.as_ref().unwrap();
    let stage = n.s.root.join("staging").join(role.name(i));
    let check = |v: &serde_json::Value| {
        engine_pair::inspect::check(
            &serde_json::to_vec(v).unwrap(),
            INSTALL,
            i,
            role,
            &stage,
            &n.outer_name,
            role == Role::Guard,
        )
    };
    assert!(check(original).is_ok());
    for (pointer, bad) in [
        ("/0/Id", json!("f".repeat(64))),
        ("/0/Image", json!(format!("sha256:{}", "f".repeat(64)))),
        ("/0/State/Status", json!("exited")),
        ("/0/State/Dead", json!(true)),
        ("/0/State/Restarting", json!(true)),
        ("/0/RestartCount", json!(1)),
        ("/0/State/Pid", json!(0)),
        ("/0/State/StartedAt", json!("2026-09-01T00:00:00Z")),
        ("/0/Config/User", json!("0:0")),
        ("/0/Config/Env", json!([])),
        ("/0/Config/Cmd", json!(["wrong.js"])),
        ("/0/HostConfig/ReadonlyRootfs", json!(false)),
        ("/0/HostConfig/CapAdd", json!(["NET_ADMIN"])),
        ("/0/HostConfig/SecurityOpt", json!([])),
        ("/0/HostConfig/Memory", json!(0)),
        ("/0/HostConfig/PidsLimit", json!(-1)),
        (
            "/0/HostConfig/Mounts/0/BindOptions/NonRecursive",
            json!(false),
        ),
        ("/0/Mounts/0/RW", json!(true)),
        ("/0/HostConfig/NetworkMode", json!("host")),
        ("/0/HostConfig/Sysctls/net.ipv4.ip_forward", json!("1")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = bad;
        assert!(
            check(&changed).is_err(),
            "accepted changed running observation: {pointer}"
        );
    }
    for field in ["NetworkID", "EndpointID", "IPAddress", "DNSNames"] {
        let mut changed = original.clone();
        changed[0]["NetworkSettings"]["Networks"][format!("apex-net-{}", i.instance)][field] =
            json!("foreign");
        assert!(check(&changed).is_err(), "accepted running {field}");
    }
    let mut missing = original.clone();
    missing[0]["NetworkSettings"]["Networks"]
        .as_object_mut()
        .unwrap()
        .remove(&format!("apex-net-{}", i.instance));
    assert!(check(&missing).is_err());
    let mut extra = original.clone();
    extra[0]["NetworkSettings"]["Networks"]["foreign-network"] = json!({});
    assert!(check(&extra).is_err());
}

#[test]
#[ignore = "controller window: extra attachment is only within this fixture's owned outer network"]
fn task4z_native_start_extra_gateway_attachment_quarantines_untouched() {
    let mut n = fixture(9);
    run(&mut n).unwrap();
    let id =
        n.s.record
            .installed
            .as_ref()
            .unwrap()
            .paired_containers
            .as_ref()
            .unwrap()
            .gateway_id
            .clone();
    docker(&[
        "network".into(),
        "connect".into(),
        "--ip=10.247.252.4".into(),
        n.outer.clone(),
        id.clone(),
    ]);
    let before = inspect("container", &id);
    let record = serde_json::to_vec(&n.s.record.installed).unwrap();
    n.s.reload();
    assert!(run(&mut n).is_err());
    assert_eq!(inspect("container", &id), before);
    assert_eq!(serde_json::to_vec(&n.s.record.installed).unwrap(), record);
}

#[test]
#[ignore = "controller window: remove only original stopped gateway then prove no recreation"]
fn task4z_native_start_missing_gateway_is_not_recreated_or_guard_stopped() {
    let mut n = fixture(10);
    run(&mut n).unwrap();
    let i = n.s.record.installed.as_ref().unwrap();
    let p = i.paired_containers.as_ref().unwrap();
    let gateway = p.gateway_id.clone();
    let guard = p.guard_id.clone();
    let v = inspect("container", &gateway);
    assert_eq!(v[0]["Id"], gateway);
    assert_eq!(v[0]["Image"], p.gateway_image_id);
    assert_eq!(v[0]["Name"], format!("/{}", Role::Gateway.name(i)));
    assert_eq!(
        v[0]["Config"]["Labels"]["io.apex.runtime.installation-id"],
        INSTALL
    );
    assert_eq!(
        v[0]["Config"]["Labels"]["io.apex.runtime.pair-binding-hash"],
        p.binding_hash
    );
    docker(&[
        "container".into(),
        "stop".into(),
        "--time=2".into(),
        gateway.clone(),
    ]);
    let stopped = inspect("container", &gateway);
    assert_eq!(stopped[0]["Id"], gateway);
    assert_eq!(stopped[0]["State"]["Running"], false);
    assert_eq!(stopped[0]["State"]["Pid"], 0);
    assert_eq!(stopped[0]["State"]["Status"], "exited");
    docker(&["container".into(), "rm".into(), gateway.clone()]);
    eprintln!("TASK4Z removed owned gateway for missing-resource test {gateway}");
    let before = inspect("container", &guard);
    n.s.reload();
    assert!(run(&mut n).is_err());
    assert_eq!(inspect("container", &guard), before);
    let ids = docker(&[
        "container".into(),
        "ls".into(),
        "-aq".into(),
        format!("--filter=id={gateway}"),
        "--no-trunc".into(),
    ]);
    assert!(ids.trim().is_empty());
}
