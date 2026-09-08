//! Shared paired pull/create/connect dispatch only, NOT a fake Docker acceptance.
use super::*;
use crate::execution::{
    journal::Journal,
    pool::{
        Resources,
        tests::shutdown::{Fault, schedule},
    },
};
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    sync::{Arc, Mutex},
};

async fn held(shutdown: bool, arguments: &[&str]) {
    held_case(shutdown, arguments, Fault::None).await;
}

async fn held_case(shutdown: bool, arguments: &[&str], fault: Fault) {
    let root = PathBuf::from("/root").join(format!("task4y-shutdown-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        "journal",
        "staging",
        "material",
        "docker-config",
        "cosign-cache",
    ] {
        fs::create_dir(root.join(name)).unwrap();
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
    }
    // A private inert socket is never connected. printf is the physical dispatch
    // witness; its output grants no image, resource, signature or inspection proof.
    let socket_path = root.join("inert.sock");
    let socket_owner = UnixListener::bind(&socket_path).unwrap();
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
    let paths = ExecutionConfig {
        journal_root: root.join("journal"),
        staging_root: root.join("staging"),
        material_root: root.join("material"),
        docker_config_root: root.join("docker-config"),
        docker_executable: "/usr/bin/printf".into(),
        docker_socket: socket_path,
        cosign_executable: "/usr/bin/printf".into(),
        cosign_cache_root: root.join("cosign-cache"),
        network_profile: None,
    };
    let engine = Engine {
        executable: crate::signature::linux::protected(&paths.docker_executable, false).unwrap(),
        config: Directory::open(&paths.docker_config_root).unwrap(),
        socket: super::super::socket(&paths.docker_socket).unwrap(),
        paths: paths.clone(),
        mount: mount::Profile::Private,
    };
    let resources = Resources {
        hooks: Arc::default(),
        journal: Journal::open(&paths.journal_root).unwrap(),
        engine,
        staging: crate::secrets::StagingOwner::open(&paths.staging_root, &paths.material_root)
            .unwrap(),
        signature: crate::signature::SignatureVerifier::open(
            &paths.cosign_executable,
            &paths.cosign_cache_root,
        )
        .unwrap(),
        network_effect: Mutex::new(()),
    };
    let arguments = arguments.iter().map(|s| (*s).to_owned()).collect();
    schedule(
        resources,
        move |engine, gate, cancel| engine.pair_effect(arguments, gate, cancel),
        shutdown,
        fault,
    )
    .await;
    drop(socket_owner);
}

#[tokio::test]
async fn task4y_held_final_rpc_shutdown_blocks_paired_pull_dispatch() {
    held(true, &["image", "pull", "fixture"]).await;
}
#[tokio::test]
async fn task4y_held_final_rpc_shutdown_blocks_paired_create_dispatch() {
    held(true, &["container", "create", "fixture"]).await;
}
#[tokio::test]
async fn task4y_held_final_rpc_shutdown_blocks_paired_connect_dispatch() {
    held(true, &["network", "connect", "fixture", "guard"]).await;
}
#[tokio::test]
async fn task4y_held_final_rpc_nonshutdown_dispatches_cleanly() {
    for args in [
        &["image", "pull", "fixture"][..],
        &["container", "create", "fixture"],
        &["network", "connect", "fixture", "guard"],
    ] {
        held(false, args).await;
    }
}

#[tokio::test]
#[should_panic(expected = "TASK4Y held observation mismatch")]
async fn task4y_held_cleanup_observation_failure_drains_before_asserting() {
    held_case(true, &["image", "pull", "fixture"], Fault::Observation).await;
}

#[tokio::test]
#[should_panic(expected = "TASK4Y held observation timeout")]
async fn task4y_held_cleanup_timeout_drains_before_asserting() {
    held_case(true, &["image", "pull", "fixture"], Fault::Timeout).await;
}

#[tokio::test]
async fn task4z_held_final_rpc_shutdown_blocks_start_dispatch_and_drains() {
    held(true, &["container", "start", &"e".repeat(64)]).await;
}

#[tokio::test]
async fn task4z_held_final_rpc_start_dispatch_drains_on_success() {
    held(false, &["container", "start", &"e".repeat(64)]).await;
}

#[tokio::test]
async fn task4z_held_final_rpc_cancellation_blocks_start_and_drains() {
    held_case(
        false,
        &["container", "start", &"e".repeat(64)],
        Fault::Cancel,
    )
    .await;
}

#[tokio::test]
async fn task4z_held_final_rpc_expired_lease_blocks_start_and_drains() {
    held_case(
        false,
        &["container", "start", &"e".repeat(64)],
        Fault::ExpiredLease,
    )
    .await;
}
