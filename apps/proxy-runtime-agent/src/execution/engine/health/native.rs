//! Explicit unsigned fixture: actual daemon exec of the packaged health process.
use super::*;
use crate::{
    config::{Directory, ExecutionConfig},
    proto,
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let p = PathBuf::from("/root").join(format!("health-daemon-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
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
                .starts_with("health-daemon-")
        );
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
#[ignore = "controller-owned unsigned packaged gateway and exact Docker socket fixture"]
fn actual_daemon_fixed_health_process_produces_bound_sample_and_terminal_inspection() {
    assert_eq!(
        std::env::var("APEX_HEALTH_DAEMON_FIXTURE").as_deref(),
        Ok("owned-daemon-health-v1")
    );
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let container = std::env::var("APEX_HEALTH_DAEMON_CONTAINER").unwrap();
    exact_id(&container).unwrap();
    let fixture = std::env::var("APEX_HEALTH_DAEMON_OWNER").unwrap();
    assert!(
        fixture.len() == 32
            && fixture
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let image = std::env::var("APEX_HEALTH_DAEMON_IMAGE").unwrap();
    exact_id(image.strip_prefix("sha256:").unwrap()).unwrap();
    let root = Root::new();
    let paths = ExecutionConfig {
        docker_socket: "/run/apex-health-docker.sock".into(),
        docker_config_root: root.0.clone(),
        docker_executable: "/bin/false".into(),
        journal_root: root.0.join("journal"),
        staging_root: root.0.join("stage"),
        material_root: root.0.join("material"),
        cosign_executable: "/bin/false".into(),
        cosign_cache_root: root.0.join("cosign"),
        network_profile: None,
    };
    // Only fixed Unix HTTP is exercised; no Docker CLI or signature result is
    // substituted. This private constructor creates no provisioning permission.
    let engine = Engine {
        executable: fs::File::open("/bin/false").unwrap().into(),
        config: Directory::open(&root.0).unwrap(),
        socket: super::super::socket(&paths.docker_socket).unwrap(),
        paths,
        mount: super::super::mount::Profile::Private,
    };
    let cancel = AtomicBool::new(false);
    let started = Instant::now();
    let deadline = started + Duration::from_secs(10);
    // Independently refuse any container outside the wrapper's exact owned
    // fixture before issuing create or start. Body bytes never enter diagnostics.
    engine
        .health_io(deadline, &cancel, async {
            let reply = engine
                .health_request(
                    Method::GET,
                    &format!("/containers/{container}/json"),
                    None,
                    200,
                    deadline,
                    &cancel,
                )
                .await?;
            let bytes = engine
                .health_body(reply, 1_048_576, deadline, &cancel)
                .await?;
            let value = Json::bounded(&bytes, 1_048_576).map_err(|_| ERROR)?;
            let v = &value.0;
            if v["Id"] != container
                || v["Image"] != image
                || v["State"]["Running"] != true
                || v["Config"]["Labels"]["io.apex.application-fixture"] != fixture
                || v["Config"]["User"] != "10001:10001"
                || v["HostConfig"]["ReadonlyRootfs"] != true
                || v["HostConfig"]["Privileged"] != false
                || v["HostConfig"]["CapDrop"] != json!(["ALL"])
            {
                return Err(ERROR);
            }
            Ok(())
        })
        .unwrap();
    let launch: proto::RuntimeLaunchContext =
        serde_json::from_slice(&fs::read("/apex/runtime/launch-context.json").unwrap()).unwrap();
    let exec = engine.health_create(&container, deadline, &cancel).unwrap();
    let before = engine.health_inspect(&exec, &container, deadline, &cancel);
    if before.is_err() {
        engine.health_io(deadline, &cancel, async {
            let reply = engine.health_request(Method::GET, &format!("/exec/{exec}/json"),
                None, 200, deadline, &cancel).await?;
            let bytes = engine.health_body(reply, 16_384, deadline, &cancel).await?;
            let value = Json::bounded(&bytes, 16_384).map_err(|_| ERROR)?;
            let v = &value.0; let p = &v["ProcessConfig"];
            // Fixed fixture metadata only, never return untrusted strings/body.
            println!("exec inspection shape {}", json!({
                "idMatches":v["ID"].as_str()==Some(exec.as_str()),
                "containerMatches":v["ContainerID"].as_str()==Some(container.as_str()),
                "stdin":v["OpenStdin"].as_bool(), "stdout":v["OpenStdout"].as_bool(), "stderr":v["OpenStderr"].as_bool(),
                "entrypointMatches":p["entrypoint"]==NODE, "argumentsMatch":p["arguments"]==json!([PROCESS]),
                "userMatches":p["user"]=="10001:10001", "privileged":p["privileged"].as_bool(), "tty":p["tty"].as_bool(),
                "running":v["Running"].as_bool(), "exit":v["ExitCode"].as_i64(), "pid":v["Pid"].as_u64()
            }));
            Ok(())
        }).unwrap();
    }
    let before = before.unwrap();
    assert!(!before.running);
    assert_eq!(before.pid, 0);
    assert_eq!(before.exit_code, None);
    let bytes = engine.health_start(&exec, deadline, &cancel).unwrap();
    let terminal = loop {
        let state = engine
            .health_inspect(&exec, &container, deadline, &cancel)
            .unwrap();
        if !state.running && state.pid > 0 {
            break state;
        }
        assert!(Instant::now() < deadline, "daemon completion not proved");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(terminal.exit_code, Some(0));
    let sample = crate::readiness_report::decode_health_sample_stdout(&bytes, &launch).unwrap();
    assert!(sample.report().ready && sample.report().live);
    assert_eq!(sample.report().target, launch.target);
    assert_eq!(sample.report().checks.len(), 9);
    assert_eq!(sample.report().stages.len(), 9);
    assert!(u128::from(sample.valid_for_ns()) > started.elapsed().as_nanos());
    println!(
        "actual daemon packaged health: exit=0 pid={} stages=9 elapsed_ns={} remaining_ns={}",
        terminal.pid,
        started.elapsed().as_nanos(),
        sample.valid_for_ns()
    );
}
