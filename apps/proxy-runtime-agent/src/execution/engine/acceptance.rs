//! Mutate a real engine observation privately; never mutate/start its container.
use super::*;
use serde_json::json;
pub(in crate::execution) fn sandbox_refusals(installation: &str, i: &Installed, stage: &Path) {
    let output = std::process::Command::new("/apex-engine-tools/docker")
        .args([
            "--host=unix:///run/apex-docker.sock",
            "container",
            "inspect",
            &i.container_id,
        ])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.len() <= 262_144);
    assert_eq!(
        inspect::check(&output.stdout, installation, i, stage).unwrap(),
        i.container_id
    );
    let original: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for (pointer, value) in [
        ("/0/HostConfig/CgroupnsMode", json!("host")),
        ("/0/HostConfig/Privileged", json!(true)),
        ("/0/HostConfig/NetworkMode", json!("host")),
        ("/0/HostConfig/ReadonlyRootfs", json!(false)),
        ("/0/HostConfig/CapAdd", json!(["SYS_ADMIN"])),
        ("/0/HostConfig/Memory", json!(0)),
        ("/0/HostConfig/PidsLimit", json!(-1)),
        ("/0/HostConfig/Mounts/0/ReadOnly", json!(false)),
        (
            "/0/HostConfig/Mounts/0/BindOptions/NonRecursive",
            json!(false),
        ),
        ("/0/Mounts/0/RW", json!(true)),
        ("/0/Mounts/0/Propagation", json!("rshared")),
        ("/0/Config/User", json!("0:0")),
        ("/0/Config/Env", json!(["SECRET=engine-secret-canary"])),
        ("/0/Config/Entrypoint", json!(["/bin/sh"])),
        ("/0/State/Running", json!(true)),
        ("/0/Image", json!(format!("sha256:{}", "0".repeat(64)))),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).expect("real daemon field") = value;
        assert!(
            inspect::check(
                &serde_json::to_vec(&changed).unwrap(),
                installation,
                i,
                stage
            )
            .is_err(),
            "sandbox substitution accepted: {pointer}"
        );
    }
}
