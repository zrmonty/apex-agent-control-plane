//! Real schema-3 dormant create; the callback fixture deliberately has no registry.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, panic::AssertUnwindSafe, sync::atomic::AtomicBool};

fn installed_record(root: &Path) -> Value {
    let entries: Vec<_> = fs::read_dir(root.join("journal"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|suffix| suffix == "json"))
        .collect();
    assert_eq!(entries.len(), 1, "only this test's one proxy journal");
    let envelope: Value = serde_json::from_slice(&fs::read(&entries[0]).unwrap()).unwrap();
    envelope["record"].clone()
}

fn inspect(root: &Path, id: &str) -> Value {
    assert!(crate::shapes::hex_hash(id));
    let args = [
        "--host=unix:///run/apex-docker.sock",
        "container",
        "inspect",
        id,
    ]
    .map(std::ffi::OsString::from);
    let bytes = crate::command::run(crate::command::CommandInput {
        executable: Path::new("/apex-engine-tools/docker"),
        arguments: &args,
        directory: root,
        home: None,
        budget: Duration::from_secs(10),
        cancelled: &AtomicBool::new(false),
    })
    .expect("bounded read-only Docker observation");
    assert!(bytes.len() <= 262_144);
    serde_json::from_slice(&bytes).unwrap()
}

fn schema_three(root: &Path) {
    let config = root.join("config");
    let mut authority: Value =
        serde_json::from_slice(&fs::read(config.join("authority-profiles.json")).unwrap()).unwrap();
    authority["schema_version"] = json!(3);
    authority["profiles"][0]["mode"] = json!("managed_ingress");
    authority["profiles"][0]["managed"] = json!({
        "evidence_agent_id":"managed-evidence",
        "upstream_credentials":"managed_upstream_v1",
        "network_policy":{"reference":"isolated-gateway","version":"v1"},
        "ingress":{"port":8080,"tls_server_name":"gateway.example",
            "edge_certificate_sha256":["a".repeat(64)]}
    });
    write(
        &config,
        "authority-profiles.json",
        &serde_json::to_vec(&authority).unwrap(),
    );
}

fn assert_handoff(root: &Path, record: &Value, observed: &Value) {
    let installed = &record["installed"];
    assert_eq!(
        installed["phase"], "Installed",
        "actual inspect persisted before registry refusal"
    );
    assert_eq!(installed["instance_proof_version"], 1);
    let stage = root.join("staging").join(format!(
        "apex-runtime-{}",
        record["instance"].as_str().unwrap()
    ));
    let authority: Value =
        serde_json::from_str(installed["authority_json"].as_str().unwrap()).unwrap();
    assert_eq!(authority["schema_version"], 3);
    assert_eq!(authority["profile"]["mode"], "managed_ingress");
    let config: proto::RuntimeConfiguration =
        serde_json::from_str(installed["configuration_json"].as_str().unwrap()).unwrap();
    let mut refs = config.secret_refs.clone();
    refs.sort();
    assert_eq!(
        refs.len(),
        refs.iter().collect::<std::collections::BTreeSet<_>>().len()
    );
    // Independent compact sorted map, never the engine's expected-env builder.
    let files: BTreeMap<String, String> =
        serde_json::from_value(installed["files"].clone()).unwrap();
    assert_eq!(files.len(), 18 + refs.len());
    for (name, digest) in &files {
        assert_eq!(
            &format!("{:x}", Sha256::digest(fs::read(stage.join(name)).unwrap())),
            digest
        );
    }
    let manifest = format!("{:x}", Sha256::digest(serde_json::to_vec(&files).unwrap()));
    let extra = [
        "APEX_MCP_MANAGED_BOOTSTRAP=sealed-stage-v1".to_owned(),
        format!("APEX_INSTALLATION_ID={INSTALL}"),
        format!("APEX_STAGE_MANIFEST_SHA256={manifest}"),
        format!(
            "APEX_TOOL_SECRET_REFERENCES={}",
            serde_json::to_string(&refs).unwrap()
        ),
    ];
    let mut expected: Vec<String> = [
        "NODE_ENV=production",
        "HOME=/tmp/apex",
        "APEX_MCP_PROFILE=managed",
        "APEX_MCP_GOVERNANCE_MODE=live",
        "APEX_RUNTIME_CONFIG_FILE=/apex/runtime/runtime-revision.json",
        "APEX_RUNTIME_LAUNCH_FILE=/apex/runtime/launch-context.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(extra.iter().cloned())
    .collect();
    // Independently observed Config.Env keys of the exact pinned IMAGE above.
    // Never let a poisoned journal authorize an arbitrary extra bare ENV key.
    let mut unset: Vec<_> = installed["unset_env"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    unset.sort();
    assert_eq!(unset, ["KO_DATA_PATH", "PATH", "SSL_CERT_FILE"]);
    expected.extend(["KO_DATA_PATH", "PATH", "SSL_CERT_FILE"].map(str::to_owned));
    expected.sort();
    let actual = observed[0]["Config"]["Env"].as_array().unwrap();
    let mut actual: Vec<_> = actual
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    actual.sort();
    assert_eq!(
        actual, expected,
        "actual Docker create must carry the exact four sealed-stage handoff assignments"
    );
    assert_eq!(observed[0]["State"]["Status"], "created");
    assert_eq!(observed[0]["State"]["Running"], false);
    assert_eq!(observed[0]["State"]["Pid"], 0);
    assert_eq!(observed[0]["HostConfig"]["NetworkMode"], "none");
    assert_eq!(observed[0]["State"]["StartedAt"], "0001-01-01T00:00:00Z");
    let installed_bytes = serde_json::to_vec(installed).unwrap();
    let check = |value: &Value| {
        crate::execution::fixture_handoff_inspect(
            INSTALL,
            &installed_bytes,
            &serde_json::to_vec(value).unwrap(),
            &stage,
        )
    };
    assert_eq!(
        check(observed).unwrap(),
        installed["container_id"].as_str().unwrap()
    );
    for (assignment, changed) in extra.iter().zip([
        "sealed-stage-v2".to_owned(),
        "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e99".to_owned(),
        "d".repeat(64),
        r#"["secret://vault/upstreams/other-reader"]"#.to_owned(),
    ]) {
        for mutation in ["missing", "changed", "duplicate"] {
            let mut altered = observed.clone();
            let env = altered[0]["Config"]["Env"].as_array_mut().unwrap();
            let index = env.iter().position(|value| value == assignment).unwrap();
            match mutation {
                "missing" => {
                    env.remove(index);
                }
                "changed" => {
                    env[index] = json!(format!(
                        "{}={changed}",
                        assignment.split_once('=').unwrap().0
                    ));
                }
                "duplicate" => env.push(json!(assignment)),
                _ => unreachable!(),
            }
            assert_eq!(
                check(&altered),
                Err("RUNTIME_ENGINE_REFUSED"),
                "{mutation} handoff metadata"
            );
        }
    }
    for injected in [
        "APEX_STAGE_MANIFEST_SHA256",
        "APEX_HANDOFF_EXTRA=canary",
        "NODE_OPTIONS=--inspect",
    ] {
        let mut altered = observed.clone();
        altered[0]["Config"]["Env"]
            .as_array_mut()
            .unwrap()
            .push(json!(injected));
        assert_eq!(check(&altered), Err("RUNTIME_ENGINE_REFUSED"));
    }
    // Observation-only mutation probes never change the real daemon target.
    assert_eq!(
        inspect(root, installed["container_id"].as_str().unwrap()),
        *observed
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign handoff acceptance"]
async fn actual_schema_three_handoff_survives_registry_refusal_and_higher_fence_retry() {
    let f = Fixture::start().await;
    current(&f, &request(), proto::ProxyDesiredState::Serving);
    let root = PathBuf::from(std::env::var_os("APEX_TASK3A_ROOT").unwrap())
        .join(format!("task4e-handoff-{}", uuid::Uuid::now_v7()));
    setup(&root, &f);
    schema_three(&root);
    let (agent, mut client) = start(&root, &f).await;
    let first = client.reconcile_runtime(request()).await;
    let before = installed_record(&root);
    let container = before["installed"]["container_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let observed = inspect(&root, &container);
    // Retire even when the handoff assertion is RED; never delete by broad shell cleanup.
    let first_checks = std::panic::catch_unwind(AssertUnwindSafe(|| {
        assert_eq!(first.unwrap_err().message(), "RUNTIME_REGISTRATION_REFUSED");
        assert_handoff(&root, &before, &observed);
    }));
    drop(client);
    agent.stop();
    let mut retry = request();
    retry.command_id = uuid::Uuid::now_v7().to_string();
    retry.target.as_mut().unwrap().fencing_token += 1;
    current(&f, &retry, proto::ProxyDesiredState::Serving);
    let (agent, mut client) = start(&root, &f).await;
    let retried = client.reconcile_runtime(retry.clone()).await;
    let after = installed_record(&root);
    let retry_checks = std::panic::catch_unwind(AssertUnwindSafe(|| {
        assert_eq!(
            retried.unwrap_err().message(),
            "RUNTIME_REGISTRATION_REFUSED"
        );
        assert_eq!(before["instance"], after["instance"]);
        assert_eq!(before["original"], after["original"]);
        assert_eq!(
            before["installed"], after["installed"],
            "retry must not synthesize a new sealed identity"
        );
        assert_eq!(after["claims"], serde_json::to_value(&retry).unwrap());
        assert_handoff(&root, &after, &inspect(&root, &container));
        assert_eq!(*f.callback.pin.lock().unwrap(), f.pki.pin(CONTROLLER));
    }));
    let retire = new_operation(retry);
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    let retired = client.reconcile_runtime(retire).await.unwrap().into_inner();
    assert_eq!(
        retired.observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert!(fs::read_dir(root.join("staging")).unwrap().next().is_none());
    assert!(
        root.join("material/m1").exists(),
        "original source material remains owned by fixture"
    );
    drop(client);
    agent.stop();
    eprintln!(
        "TASK4E handoff boundary root={} container={} registry=REFUSED retired=true",
        root.display(),
        container
    );
    f.stop().await;
    if let Err(panic) = first_checks {
        std::panic::resume_unwind(panic);
    }
    if let Err(panic) = retry_checks {
        std::panic::resume_unwind(panic);
    }
}
