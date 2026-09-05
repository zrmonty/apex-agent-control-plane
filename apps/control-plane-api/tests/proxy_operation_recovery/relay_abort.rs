use super::support::*;
use apex_control_plane_api::{
    ControlOutboxBackend, GatewayShutdown, PostgresProxyStore, ProxyEvidenceRelayStatus,
    RecoveringPostgresOutbox, spawn_proxy_evidence_relay,
};
use std::sync::{Arc, atomic::Ordering};
use std::time::{Duration, Instant};

#[test]
fn abort_child() {
    let Ok(url) = std::env::var("APEX_PROXY_RELAY_ABORT_CHILD_URL") else {
        return;
    };
    let store = Arc::new(PostgresProxyStore::connect(&url).unwrap());
    let outbox = Arc::new(ControlOutboxBackend::new(Box::new(
        RecoveringPostgresOutbox::connect(&url, 100).unwrap(),
    )));
    let weak_store = Arc::downgrade(&store);
    let weak_outbox = Arc::downgrade(&outbox);
    let status = Arc::new(ProxyEvidenceRelayStatus::default());
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let handle = spawn_proxy_evidence_relay(
                store,
                outbox,
                Arc::clone(&status),
                GatewayShutdown::default(),
            );
            tokio::time::timeout(Duration::from_secs(5), async {
                while !status.healthy.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // Abort while idle: all PostgreSQL ownership is in the task, not in a
            // temporarily outstanding blocking call. Catch neither panic nor abort.
            handle.abort();
            assert!(handle.await.unwrap_err().is_cancelled());
            tokio::time::timeout(Duration::from_secs(5), async {
                while weak_store.strong_count() != 0 || weak_outbox.strong_count() != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert!(!status.healthy.load(Ordering::Acquire));
        });
}

#[test]
fn forced_task_abort_releases_last_database_owners_without_runtime_panic() {
    let database = Database::new();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "relay_abort::abort_child", "--nocapture"])
        .env("APEX_PROXY_RELAY_ABORT_CHILD_URL", &database.url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("aborted relay child did not release its blocking resources");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success(),
        "forced abort panicked while dropping last database owners"
    );
}
