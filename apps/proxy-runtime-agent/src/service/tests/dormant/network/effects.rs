//! Real daemon/production agent empty-network acceptance; new fixture resources only.
use super::*;
mod collision;
mod gate;
mod recovery;
fn docker(args: &[&str]) -> Value {
    let out = Command::new("/apex-engine-tools/docker")
        .arg("--host=unix:///run/apex-docker.sock")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "native fixture command failed");
    serde_json::from_slice(&out.stdout).unwrap()
}
struct Fabric {
    id: String,
    name: String,
}
impl Fabric {
    fn new() -> Self {
        let name = format!("apex-task4p-{}", uuid::Uuid::now_v7());
        let out = Command::new("/apex-engine-tools/docker")
            .arg("--host=unix:///run/apex-docker.sock")
            .args([
                "network",
                "create",
                "--driver=bridge",
                "--ipv4=true",
                "--ipv6=false",
                "--subnet=10.247.0.0/24",
                "--gateway=10.247.0.1",
                "--label",
            ])
            .arg(format!("apex.fixture.owner={name}"))
            .arg(&name)
            .output()
            .unwrap();
        assert!(out.status.success(), "new outer fixture refused");
        Self {
            id: String::from_utf8(out.stdout).unwrap().trim().into(),
            name,
        }
    }
    fn configure(&self, root: &Path) {
        enable(root);
        let a_path = root.join("config/authority-profiles.json");
        let mut a: Value = serde_json::from_slice(&fs::read(&a_path).unwrap()).unwrap();
        let managed = a["profiles"][0]["managed"].clone();
        for p in a["profiles"].as_array_mut().unwrap() {
            p["mode"] = json!("managed_ingress");
            p["managed"] = managed.clone();
        }
        write(
            &root.join("config"),
            "authority-profiles.json",
            &serde_json::to_vec(&a).unwrap(),
        );
        let p = root.join("config/network-catalog.json");
        let mut n: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
        n["internal_pool"] = json!("10.248.0.0/22");
        n["outer"] = json!({"network_id":self.id,"subnet":"10.247.0.0/24","gateway":"10.247.0.1","edge_address":"10.247.0.2"});
        write(
            &root.join("config"),
            "network-catalog.json",
            &serde_json::to_vec(&n).unwrap(),
        );
    }
}
fn documents_at(root: &Path) -> Vec<(PathBuf, Value)> {
    let mut out: Vec<_> = fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("network-topology-")
                && p.extension().is_some_and(|s| s == "json")
        })
        .map(|p| {
            let v = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
            (p, v)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}
fn bind(f: &Fixture, r: &proto::RuntimeReconcileRequest) {
    current(f, r, proto::ProxyDesiredState::Serving);
    f.callback.targets.lock().unwrap().insert(
        r.target.as_ref().unwrap().proxy_id.clone(),
        f.callback.reply.lock().unwrap().clone(),
    );
}
fn remove_owned(t: &Value) {
    let d = &t["document"];
    let id = d["observation"].as_str().unwrap();
    let n = docker(&["network", "inspect", id]);
    assert_eq!(n[0]["Id"], id);
    assert_eq!(
        n[0]["Name"],
        format!("apex-net-{}", d["topology"]["instance"].as_str().unwrap())
    );
    assert_eq!(
        n[0]["Labels"]["io.apex.runtime.network-topology-hash"],
        d["topology_hash"]
    );
    assert_eq!(n[0]["Labels"]["io.apex.runtime.installation-id"], INSTALL);
    assert_eq!(n[0]["Containers"], json!({}));
    assert!(
        Command::new("/apex-engine-tools/docker")
            .arg("--host=unix:///run/apex-docker.sock")
            .args(["network", "rm", id])
            .status()
            .unwrap()
            .success()
    );
}
impl Drop for Fabric {
    fn drop(&mut self) {
        let v = docker(&["network", "inspect", &self.id]);
        assert_eq!(v[0]["Id"], self.id);
        assert_eq!(v[0]["Labels"]["apex.fixture.owner"], self.name);
        assert_eq!(v[0]["Containers"], json!({}));
        assert!(
            Command::new("/apex-engine-tools/docker")
                .arg("--host=unix:///run/apex-docker.sock")
                .args(["network", "rm", &self.id])
                .status()
                .unwrap()
                .success()
        );
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Task4P new uniquely labelled fixture networks and retained owned root only"]
async fn actual_empty_network_is_durable_without_container_effects() {
    let f = Fixture::start().await;
    let req = request();
    current(&f, &req, proto::ProxyDesiredState::Serving);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4p-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    let fabric = Fabric::new();
    fabric.configure(&root);
    fs::remove_file(root.join("material/m1")).unwrap();
    let (agent, mut client) = start_network(&root, &f).await;
    let error = client.reconcile_runtime(req).await.unwrap_err();
    assert_eq!(error.message(), "RUNTIME_NETWORK_ENFORCEMENT_UNAVAILABLE");
    drop(client);
    agent.stop();
    let paths: Vec<_> = fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|p| p.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("network-topology-")
                && p.extension().is_some_and(|s| s == "json")
        })
        .collect();
    assert_eq!(
        paths.len(),
        1,
        "production owner must persist observed empty topology"
    );
    let t: Value = serde_json::from_slice(&fs::read(&paths[0]).unwrap()).unwrap();
    assert_eq!(t["document"]["phase"], "Observed");
    let id = t["document"]["observation"].as_str().unwrap();
    let actual = docker(&["network", "inspect", id]);
    assert_eq!(actual[0]["IPAM"]["Config"][0]["Subnet"], "10.248.0.0/29");
    assert_eq!(actual[0]["IPAM"]["Config"][0]["Gateway"], "10.248.0.1");
    assert_eq!(actual[0]["Containers"], json!({}));
    assert_eq!(
        actual[0]["Labels"]["io.apex.runtime.network-topology-hash"],
        t["document"]["topology_hash"]
    );
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    remove_owned(&t);
    eprintln!("TASK4P root={}", root.display());
    f.stop().await;
}
