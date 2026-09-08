//! Private deterministic physical-work hold; no fake engine success is claimed.
use super::*;
pub(in crate::execution) mod shutdown;
use std::{
    future::Future,
    task::{Context as TaskContext, Waker},
};
#[tokio::test]
async fn cancelled_requests_retain_all_slots_and_root_handles_until_physical_exit() {
    let (sender, receiver) = mpsc::sync_channel::<Work>(8);
    let receiver = Arc::new(Mutex::new(receiver));
    let (entered, observed) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let held = Arc::new(Mutex::new(held));
    let mut facility = Facility {
        sender: Some(sender),
        threads: vec![],
        slots: Arc::new(Semaphore::new(8)),
        active: Arc::new(Mutex::new(BTreeSet::new())),
        installation: uuid::Uuid::now_v7().to_string(),
    };
    for _ in 0..8 {
        let receiver = Arc::clone(&receiver);
        let held = Arc::clone(&held);
        let entered = entered.clone();
        facility.threads.push(std::thread::spawn(move || {
            let job = receiver.lock().unwrap().recv().unwrap();
            let Work::Reconcile(job) = job else {
                panic!("expected reconciliation")
            };
            entered.send(Arc::clone(&job.cancelled)).unwrap();
            held.lock().unwrap().recv().unwrap();
            drop(job);
        }));
    }
    let request = || {
        Request::new(proto::RuntimeReconcileRequest {
            schema_version: 1,
            target: Some(proto::RuntimeTarget {
                workspace_id: "w".into(),
                namespace_id: "n".into(),
                proxy_id: uuid::Uuid::now_v7().to_string(),
                revision_id: uuid::Uuid::now_v7().to_string(),
                generation: 1,
                fencing_token: 1,
            }),
            operation_id: uuid::Uuid::now_v7().to_string(),
            command_id: uuid::Uuid::now_v7().to_string(),
            config_hash: "a".repeat(64),
        })
    };
    let mut futures: Vec<_> = (0..8)
        .map(|_| Box::pin(facility.execute(request())))
        .collect();
    for future in &mut futures {
        assert!(
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    let flags: Vec<_> = (0..8)
        .map(|_| observed.recv_timeout(Duration::from_secs(5)).unwrap())
        .collect();
    assert_eq!(facility.slots.available_permits(), 0);
    drop(futures);
    assert!(flags.iter().all(|f| f.load(Ordering::Acquire)));
    assert_eq!(
        facility.execute(request()).await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    assert_eq!(facility.active.lock().unwrap().len(), 8);
    let (dropping, drop_started) = mpsc::channel();
    let (done, exited) = mpsc::channel();
    let join = std::thread::spawn(move || {
        dropping.send(()).unwrap();
        drop(facility);
        done.send(()).unwrap();
    });
    drop_started.recv().unwrap();
    assert!(matches!(exited.try_recv(), Err(mpsc::TryRecvError::Empty)));
    for _ in 0..8 {
        release.send(()).unwrap();
    }
    exited.recv_timeout(Duration::from_secs(5)).unwrap();
    join.join().unwrap();
}
