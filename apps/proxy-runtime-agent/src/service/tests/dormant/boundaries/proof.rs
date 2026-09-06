//! Actual separately compiled production owner; no test RNG or injected proof.
use super::*;
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_instance_proof_is_private_immutable_and_digest_only() {
    let f = Fixture::start().await;
    let root = root(&f);
    let (agent, mut client) = start(&root, &f).await;
    let response = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        response.observed_state,
        i32::from(proto::ProxyObservedState::NotServing)
    );
    let initial = record(&root);
    let file = stage(&root, &initial).join("instance-proof");
    assert!(
        file.is_file(),
        "new instance must contain an agent-generated private proof"
    );
    let proof = fs::read(&file).unwrap();
    assert_eq!(proof.len(), 32);
    let metadata = fs::metadata(&file).unwrap();
    assert_eq!(
        (
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
            metadata.nlink()
        ),
        (10001, 10001, 0o400, 1)
    );
    let digest = format!("{:x}", Sha256::digest(&proof));
    assert_eq!(initial["installed"]["files"]["instance-proof"], digest);
    let attestation = response
        .runtime
        .as_ref()
        .unwrap()
        .launch_attestation
        .as_ref()
        .expect("a sealed proof-bearing instance must attest its digest and original launch");
    assert_eq!(attestation.schema_version, 1);
    assert_eq!(attestation.installation_id, INSTALL);
    assert_eq!(attestation.instance_proof_sha256, digest);
    let launch = attestation.launch.as_ref().unwrap();
    assert_eq!(launch.target, request().target);
    assert_eq!(launch.process_instance_id, initial["instance"]);
    assert_eq!(
        attestation.staged_manifest_sha256,
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&initial["installed"]["files"]).unwrap())
        )
    );
    let json = serde_json::to_vec(&initial).unwrap();
    assert!(!json.windows(proof.len()).any(|window| window == proof));
    drop(client);
    agent.stop();
    let (agent, mut client) = start(&root, &f).await;
    let retry = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        retry.runtime.unwrap().runtime_id,
        response.runtime.unwrap().runtime_id
    );
    assert_eq!(fs::read(&file).unwrap(), proof);
    assert_eq!(
        record(&root)["installed"]["files"],
        initial["installed"]["files"]
    );
    let retire = new_operation(request());
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    let removed = client.reconcile_runtime(retire).await.unwrap().into_inner();
    assert_eq!(
        removed.observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert!(!file.exists());
    assert!(root.join("material/m1").exists());
    drop(client);
    agent.stop();
    eprintln!("TASK4A instance proof lifecycle root={}", root.display());
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_legacy_stage_adopts_without_synthesizing_instance_proof() {
    let f = Fixture::start().await;
    let root = root(&f);
    // Real previously reviewed production binary creates its original schema1 stage.
    let (legacy, mut client) = start_binary(&root, &f, "/binding-tests/task3a-legacy-agent").await;
    let old = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    let before = record(&root);
    let staged = stage(&root, &before);
    assert!(before["installed"].get("instance_proof_version").is_none());
    assert!(!staged.join("instance-proof").exists());
    drop(client);
    legacy.stop();
    let (agent, mut client) = start(&root, &f).await;
    let adopted = client
        .reconcile_runtime(request())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        adopted.runtime.as_ref().unwrap().runtime_id,
        old.runtime.unwrap().runtime_id
    );
    assert!(adopted.runtime.unwrap().launch_attestation.is_none());
    assert!(!staged.join("instance-proof").exists());
    assert_eq!(record(&root)["installed"], before["installed"]);
    let retire = new_operation(request());
    current(&f, &retire, proto::ProxyDesiredState::Retired);
    assert_eq!(
        client
            .reconcile_runtime(retire)
            .await
            .unwrap()
            .into_inner()
            .observed_state,
        i32::from(proto::ProxyObservedState::Retired)
    );
    assert!(!staged.exists());
    drop(client);
    agent.stop();
    eprintln!("TASK4A actual legacy adoption root={}", root.display());
    f.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "explicit scoped Linux Docker socket/volume/Cosign acceptance"]
async fn actual_dormant_changed_instance_proof_quarantines_without_regeneration() {
    let f = Fixture::start().await;
    let root = root(&f);
    let (agent, mut client) = start(&root, &f).await;
    client.reconcile_runtime(request()).await.unwrap();
    drop(client);
    agent.stop();
    let before = record(&root);
    let file = stage(&root, &before).join("instance-proof");
    let original = fs::read(&file).unwrap();
    let mut corrupted = original.clone();
    corrupted[0] ^= 0xff;
    // The fixture's trusted owner changes only its own private file in place.
    fs::write(&file, &corrupted).unwrap();
    for _ in 0..2 {
        let (agent, mut client) = start(&root, &f).await;
        assert_eq!(
            client
                .reconcile_runtime(request())
                .await
                .unwrap_err()
                .message(),
            "RUNTIME_STAGE_QUARANTINED"
        );
        assert_eq!(fs::read(&file).unwrap(), corrupted);
        assert_eq!(record(&root), before);
        drop(client);
        agent.stop();
    }
    // Leave the exact compromised fixture quarantined; no automatic repair/delete.
    eprintln!("TASK4A proof quarantine root={}", root.display());
    f.stop().await;
}
