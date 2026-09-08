//! Explicit unsigned component fixture. Real Docker effects, no production signature grant.
use super::*;
use crate::{
    config::ExecutionConfig,
    execution::{engine::Engine, network_owner::topology, paired::transition},
};
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
mod health;
mod interruptions;
mod network_inspection;
mod start;

fn docker(args: &[String]) -> String {
    String::from_utf8(start::bounded(args)).unwrap()
}
fn inspect(kind: &str, id: &str) -> serde_json::Value {
    serde_json::from_str(&docker(&[kind.into(), "inspect".into(), id.into()])).unwrap()
}
struct Native {
    s: Storage,
    engine: Engine,
    outer: String,
    outer_name: String,
    inner: String,
}
impl Native {
    fn new() -> Self {
        let instance = uuid::Uuid::now_v7().to_string();
        Self::with_instance(instance, "task4y", "APEX_TASK4Y_COMPONENT_IMAGE_ID")
    }
    fn with_instance(instance: String, prefix: &str, image_variable: &str) -> Self {
        Self::with_setup(instance, prefix, image_variable, |_| {})
    }
    fn with_setup(
        instance: String,
        prefix: &str,
        image_variable: &str,
        setup: impl FnOnce(&mut Fixture),
    ) -> Self {
        let outer_name = format!("{prefix}-native-{instance}");
        let outer = docker(&[
            "network".into(),
            "create".into(),
            "--driver=bridge".into(),
            "--ipv4=true".into(),
            "--ipv6=false".into(),
            "--subnet=10.247.252.0/24".into(),
            "--gateway=10.247.252.1".into(),
            format!("--label=io.apex.{prefix}.owner={outer_name}"),
            outer_name.clone(),
        ])
        .trim()
        .to_owned();
        let base = PathBuf::from(
            std::env::var_os("APEX_TASK3A_ROOT").expect("native controller-owned root required"),
        );
        let root = base.join(format!("{prefix}-{instance}"));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["journal", "staging", "material", "docker-config"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let paths: ExecutionConfig = serde_json::from_value(json!({
            "journal_root":root.join("journal"),"staging_root":root.join("staging"),"material_root":root.join("material"),
            "docker_executable":"/apex-engine-tools/docker","docker_socket":"/run/apex-docker.sock","docker_config_root":root.join("docker-config"),
            "cosign_executable":"/apex-engine-tools/cosign","cosign_cache_root":root.join("unused-cosign-cache"),"network_profile":"isolated-bridge-v1"})).unwrap();
        let engine = Engine::open(&paths, INSTALL).unwrap();
        let mut fixture = Fixture::with_instance(&instance);
        fixture.network_json["internal_pool"] = json!("10.246.0.0/22");
        fixture.network_json["outer"] = json!({"network_id":outer,"subnet":"10.247.252.0/24","gateway":"10.247.252.1","edge_address":"10.247.252.2"});
        fixture.i.mount_profile = engine.mount_profile().into();
        setup(&mut fixture);
        fixture.rebind();
        let journal = Journal::open(&root.join("journal")).unwrap();
        fixture.i.network = None;
        fixture.i.network = Some(
            journal
                .reserve_network(&fixture.catalog, INSTALL, &fixture.i)
                .unwrap(),
        );
        let mut record = Record::select(INSTALL, &fixture.i.original, None).unwrap();
        record.instance = instance;
        record.installed = Some(fixture.i.clone());
        journal.save(&record).unwrap();
        let t = topology::Topology::new(&fixture.catalog, INSTALL, &fixture.i, "c".repeat(64), NOW)
            .unwrap();
        let mut d = topology::Document::prepared(t).unwrap();
        journal.prepare_topology(&d).unwrap();
        let old = d.clone();
        d.phase = topology::Phase::CreateIntent;
        journal.transition_topology(&old, &d).unwrap();
        let t = &d.topology.0;
        let mut args: Vec<String> = [
            "network",
            "create",
            "--driver=bridge",
            "--scope=local",
            "--internal",
            "--ipv4=true",
            "--ipv6=false",
            "--attachable=false",
            "--ipam-driver=default",
            "--opt=com.docker.network.bridge.gateway_mode_ipv4=isolated",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        args.extend([
            format!("--subnet={}", t.internal_subnet),
            format!("--gateway={}", t.ipam_gateway),
        ]);
        args.extend(
            t.labels()
                .unwrap()
                .into_iter()
                .map(|(k, v)| format!("--label={k}={v}")),
        );
        args.push(t.name());
        let inner = docker(&args).trim().to_owned();
        let old = d.clone();
        d.phase = topology::Phase::Observed;
        d.observation = Some(inner.clone());
        journal.transition_topology(&old, &d).unwrap();
        fixture.document = d;
        let staging = StagingOwner::open(&root.join("staging"), &root.join("material")).unwrap();
        let mut s = Storage {
            root,
            fixture,
            record,
            journal,
            staging,
        };
        materials(&s);
        assert_eq!(
            paired(&mut s, &mut || Ok(())),
            Err("RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE")
        );
        let image = std::env::var(image_variable).expect("explicit unsigned component image ID");
        assert!(crate::shapes::image_id(&image));
        let actual = inspect("image", &image);
        assert_eq!(actual[0]["Id"], image);
        assert!(actual[0]["Config"]["Volumes"].is_null());
        let keys = actual[0]["Config"]["Env"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e.as_str().unwrap().split_once('=').unwrap().0.to_owned())
            .collect::<Vec<_>>();
        let i = s.record.installed.as_mut().unwrap();
        i.paired_containers =
            Some(Pair::new(i, (image.clone(), keys.clone()), (image, keys)).unwrap());
        s.journal.save(&s.record).unwrap();
        Self {
            s,
            engine,
            outer,
            outer_name,
            inner,
        }
    }
    fn finish(
        &mut self,
        check: &mut dyn FnMut() -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        let until = Instant::now() + Duration::from_secs(60);
        transition::finish(
            &self.s.journal,
            &self.engine,
            &mut self.s.record,
            check,
            &|| Ok(until),
            &AtomicBool::new(false),
        )
    }
    fn phase(&self) -> Phase {
        self.s
            .record
            .installed
            .as_ref()
            .unwrap()
            .paired_containers
            .as_ref()
            .unwrap()
            .phase
    }
    fn stopped(&self) {
        let i = self.s.record.installed.as_ref().unwrap();
        let p = i.paired_containers.as_ref().unwrap();
        for role in [Role::Gateway, Role::Guard] {
            let v = inspect("container", role.id(p));
            assert_eq!(v[0]["State"]["Status"], "created");
            assert_eq!(v[0]["State"]["Pid"], 0);
            assert_eq!(v[0]["State"]["StartedAt"], "0001-01-01T00:00:00Z");
            assert_eq!(v[0]["Config"]["Entrypoint"], json!(["/usr/local/bin/node"]));
            assert_eq!(
                v[0]["NetworkSettings"]["Networks"]
                    .as_object()
                    .unwrap()
                    .len(),
                if role == Role::Gateway { 1 } else { 2 }
            );
            assert_eq!(v[0]["HostConfig"]["NetworkMode"], self.inner);
            assert_eq!(v[0]["HostConfig"]["Sysctls"]["net.ipv4.ip_forward"], "0");
            assert_eq!(
                v[0]["Mounts"][0]["Source"],
                json!(self.s.root.join("staging").join(role.name(i)))
            );
            mutations(
                &serde_json::to_vec(&v).unwrap(),
                i,
                role,
                &self.s.root.join("staging").join(role.name(i)),
                &self.outer_name,
            );
        }
        assert_eq!(inspect("network", &self.inner)[0]["Containers"], json!({}));
        assert_eq!(inspect("network", &self.outer)[0]["Containers"], json!({}));
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        if self.outer_name.starts_with("task4z-native-") {
            start::cleanup(self);
            return;
        }
        let i = self.s.record.installed.as_ref().unwrap();
        for role in [Role::Guard, Role::Gateway] {
            let name = role.name(i);
            let ids = docker(&[
                "container".into(),
                "ls".into(),
                "-aq".into(),
                format!("--filter=name=^/{name}$"),
                "--no-trunc".into(),
            ]);
            if ids.trim().is_empty() {
                continue;
            }
            let v = inspect("container", ids.trim());
            assert_eq!(v[0]["Name"], format!("/{name}"));
            assert_eq!(
                v[0]["Config"]["Labels"]["io.apex.runtime.pair-binding-hash"],
                i.paired_containers.as_ref().unwrap().binding_hash
            );
            assert_eq!(v[0]["State"]["Status"], "created");
            docker(&["container".into(), "rm".into(), ids.trim().into()]);
        }
        for (id, key, value) in [
            (
                &self.inner,
                "io.apex.runtime.network-topology-hash",
                &self.s.fixture.document.topology_hash,
            ),
            (&self.outer, "io.apex.task4y.owner", &self.outer_name),
        ] {
            let v = inspect("network", id);
            assert_eq!(v[0]["Id"], *id);
            assert_eq!(v[0]["Labels"][key], *value);
            assert_eq!(v[0]["Containers"], json!({}));
            docker(&["network".into(), "rm".into(), id.clone()]);
        }
        eprintln!(
            "TASK4Y native retained root={} (unsigned component; no start)",
            self.s.root.display()
        );
    }
}
fn mutations(bytes: &[u8], i: &Installed, role: Role, stage: &Path, outer: &str) {
    let connected = role == Role::Guard;
    assert!(engine_pair::inspect::check(bytes, INSTALL, i, role, stage, outer, connected).is_ok());
    let original: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    for (pointer, value) in [
        ("/0/Image", json!(format!("sha256:{}", "0".repeat(64)))),
        ("/0/Config/Entrypoint", json!(["/bin/sh"])),
        ("/0/Config/Env", json!(["SECRET=task4y-engine-canary"])),
        ("/0/Config/Cmd", json!(["wrong.js"])),
        ("/0/HostConfig/NetworkMode", json!("host")),
        ("/0/HostConfig/Dns", json!(["8.8.8.8"])),
        ("/0/HostConfig/Sysctls/net.ipv4.ip_forward", json!("1")),
        ("/0/HostConfig/Mounts/0/Source", json!("/run/docker.sock")),
        ("/0/Mounts/0/RW", json!(true)),
        (
            "/0/HostConfig/Mounts/0/BindOptions/NonRecursive",
            json!(false),
        ),
        ("/0/State/Running", json!(true)),
        ("/0/State/StartedAt", json!("2026-09-08T00:00:00Z")),
        ("/0/HostConfig/CapAdd", json!(["NET_ADMIN"])),
        ("/0/HostConfig/ReadonlyRootfs", json!(false)),
        ("/0/HostConfig/Memory", json!(0)),
        ("/0/HostConfig/PidsLimit", json!(-1)),
        (
            "/0/Config/Labels/io.apex.runtime.paired-container-name",
            json!("foreign-peer"),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            engine_pair::inspect::check(
                &serde_json::to_vec(&changed).unwrap(),
                INSTALL,
                i,
                role,
                stage,
                outer,
                connected
            )
            .is_err(),
            "accepted {pointer}"
        );
    }
    for (field, value) in [
        ("EndpointID", json!("a".repeat(64))),
        ("NetworkID", json!("d".repeat(64))),
        ("IPAMConfig", json!({"IPv4Address":"10.246.0.7"})),
        ("Aliases", json!(["extra"])),
    ] {
        let mut changed = original.clone();
        let networks = changed[0]["NetworkSettings"]["Networks"]
            .as_object_mut()
            .unwrap();
        networks.values_mut().next().unwrap()[field] = value;
        assert!(
            engine_pair::inspect::check(
                &serde_json::to_vec(&changed).unwrap(),
                INSTALL,
                i,
                role,
                stage,
                outer,
                connected
            )
            .is_err(),
            "accepted endpoint {field}"
        );
    }
}

#[test]
#[ignore = "controller-owned native socket/volume; explicit unsigned component image; never starts"]
fn task4y_native_pair_create_recover_and_reject_substitutions() {
    let mut n = Native::new();
    let original = serde_json::to_value(&n.s.record.installed).unwrap();
    let result = n.finish(&mut || Ok(()));
    if result.is_err() {
        let i = n.s.record.installed.as_ref().unwrap();
        for role in [Role::Gateway, Role::Guard] {
            let ids = docker(&[
                "container".into(),
                "ls".into(),
                "-aq".into(),
                format!("--filter=name=^/{}$", role.name(i)),
                "--no-trunc".into(),
            ]);
            if !ids.trim().is_empty() {
                fs::write(
                    n.s.root.join(format!("inspect-{}.json", role.name(i))),
                    serde_json::to_vec_pretty(&inspect("container", ids.trim())).unwrap(),
                )
                .unwrap();
            }
        }
    }
    assert!(
        result.is_ok(),
        "native stopped pair refused at {:?}: {result:?}",
        n.phase()
    );
    assert_eq!(n.phase(), Phase::Verified);
    n.stopped();
    let verified = serde_json::to_vec(&n.s.record.installed).unwrap();
    n.s.reload();
    n.finish(&mut || Ok(())).unwrap();
    assert_eq!(serde_json::to_vec(&n.s.record.installed).unwrap(), verified);
    for field in [
        "original",
        "instance",
        "launch_json",
        "guard_stage",
        "gateway_stage",
        "network",
        "files",
        "container_id",
        "image_id",
    ] {
        assert_eq!(
            serde_json::to_value(&n.s.record.installed).unwrap()[field],
            original[field]
        );
    }
    // Simulate a lost connect receipt only; physical containers are untouched.
    n.s.record
        .installed
        .as_mut()
        .unwrap()
        .paired_containers
        .as_mut()
        .unwrap()
        .phase = Phase::ConnectIntent;
    n.s.journal.save(&n.s.record).unwrap();
    n.s.reload();
    n.finish(&mut || Ok(())).unwrap();
    assert_eq!(serde_json::to_vec(&n.s.record.installed).unwrap(), verified);
}

#[test]
#[ignore = "controller-owned native socket/volume; durable ambiguity and no-dispatch fixtures"]
fn task4y_native_pair_intent_absence_and_no_dispatch() {
    for (ordinal, phase) in [
        (1, Phase::GatewayIntent),
        (2, Phase::GuardIntent),
        (3, Phase::ConnectIntent),
    ] {
        let mut n = Native::new();
        assert!(
            interruptions::interrupt(
                &mut n,
                crate::execution::testing::Point::PairIntent,
                ordinal
            )
            .is_err()
        );
        assert_eq!(n.phase(), phase);
        n.s.reload();
        assert!(n.finish(&mut || Ok(())).is_err());
        assert_eq!(
            n.phase(),
            phase,
            "missing resource/attachment cannot authorize recreation or reconnect"
        );
    }
}
