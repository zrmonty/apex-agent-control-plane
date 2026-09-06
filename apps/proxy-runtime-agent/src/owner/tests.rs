use super::*;
#[cfg(target_os = "linux")]
pub(crate) mod network;
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) fn documents() -> (Vec<u8>, Vec<u8>) {
    let install = "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01";
    let policy = json!({"schemaVersion":1,"version":"client-policy","validFromUnixUs":"1","expiresAtUnixUs":"9223372036854775807","peers":[{"certificateSha256":"aa".repeat(32),"identityId":"controller","role":"controller","revoked":false,"grants":[{"installationId":install,"workspaceId":"work","namespaceId":"ns"}]}]});
    let catalog = json!({"schema_version":1,"version":"catalog1","valid_from_unix_us":1,"expires_at_unix_us":i64::MAX,"profiles":[{
        "installation_id":install,"workspace_id":"work","namespace_id":"ns","proxy_id":"018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e03","revision_id":"018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e04","host_policy_version":"host-1","deployment_bindings_version":"bindings-1","config_hash":"a".repeat(64),"authority_profile_ref":"live","authority_profile_version":"v1","image_catalog_id":"gateway",
        "materials":(1..=13).map(|n| json!({"role":crate::proto::RuntimeMaterialRole::try_from(n).unwrap().as_str_name(),"reference":format!("secret://deployment/m{n}"),"version":"v1","source_name":format!("m{n}")})).collect::<Vec<_>>()
    }]});
    (
        serde_json::to_vec(&policy).unwrap(),
        serde_json::to_vec(&catalog).unwrap(),
    )
}

#[test]
fn owner_checks_catalog_against_local_clock_and_poisoned_replacement() {
    let (p, c) = documents();
    let metadata = Metadata::parse(&p, &c).expect("valid protected metadata must load");
    assert!(metadata.current().is_ok());
    let mut old: serde_json::Value = serde_json::from_slice(&c).unwrap();
    old["expires_at_unix_us"] = 100.into();
    assert!(Metadata::parse(&p, &serde_json::to_vec(&old).unwrap()).is_err());
    assert!(Metadata::parse(&p, b"invalid").is_err());
}

#[test]
fn reader_poison_is_immediate_and_shutdown_waits_for_physical_read() {
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let (entered, received) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let reader = Reader::start(move || {
        let n = count.fetch_add(1, Ordering::SeqCst);
        if n == 1 {
            entered.send(()).unwrap();
            held.recv().unwrap();
            return Err(UNAVAILABLE);
        }
        let (p, c) = documents();
        Metadata::parse(&p, &c)
    })
    .expect("owned reader must start");
    let deadline = Instant::now() + Duration::from_secs(2);
    while snapshot(&reader.shared).is_err() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(snapshot(&reader.shared).is_ok());
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let shared = Arc::clone(&reader.shared);
    // A stalled physical reader cannot refresh its monotonic freshness stamp.
    shared.lock().unwrap().read_started = Instant::now() - FRESHNESS;
    assert!(snapshot(&shared).is_err());
    let (done, wait) = mpsc::channel();
    let join = std::thread::spawn(move || {
        drop(reader);
        done.send(()).unwrap();
    });
    assert!(wait.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    release.send(()).unwrap();
    wait.recv_timeout(Duration::from_secs(2)).unwrap();
    join.join().unwrap();
    assert!(snapshot(&shared).is_err());
}

#[tokio::test]
async fn first_publication_latch_waits_for_physical_load_completion() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let (sent, notified) = tokio::sync::oneshot::channel();
    let mut sent = Some(sent);
    let (release, held) = mpsc::channel();
    let reader = Reader::start(move || {
        let (p, c) = documents();
        let metadata = Metadata::parse(&p, &c)?;
        if let Some(sent) = sent.take() {
            let _ = sent.send(());
            let _ = held.recv();
        }
        Ok(metadata)
    })
    .unwrap();
    // Release before Reader's join even if an assertion panics.
    struct Release(Option<mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let release = Release(Some(release));
    tokio::time::timeout(Duration::from_secs(2), notified)
        .await
        .unwrap()
        .unwrap();
    let mut publication = reader.publication.clone();
    let mut ready = Box::pin(publication.wait_for(|published| *published));
    assert!(
        ready
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert!(snapshot(&reader.shared).is_err());
    drop(release);
    assert!(
        *tokio::time::timeout(Duration::from_secs(2), ready)
            .await
            .unwrap()
            .unwrap()
    );
    assert!(snapshot(&reader.shared).is_ok());
    drop(reader);
}
