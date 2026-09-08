use super::*;
use std::{
    future::Future,
    task::{Context as TaskContext, Waker},
};

#[tokio::test]
async fn cancelled_health_keeps_physical_slot_and_allows_network_but_not_reconcile() {
    let (sender, receiver) = mpsc::sync_channel(8);
    let f = Facility {
        sender: Some(sender),
        threads: vec![],
        slots: Arc::new(Semaphore::new(8)),
        active: Arc::default(),
        installation: "018f3d4a-8b9c-7d0e-8f12-3a4b5c6d7e01".into(),
    };
    let (p, c) = owner::tests::documents();
    let metadata = Arc::new(owner::Metadata::parse(&p, &c).unwrap());
    let body = proto::RuntimeHealthObservationRequest {
        schema_version: 1,
        nonce: vec![7; 32],
        binding: Some(proto::ManagedDeploymentBinding {
            installation_id: f.installation.clone(),
            target: Some(proto::RuntimeTarget {
                workspace_id: "work".into(),
                namespace_id: "ns".into(),
                proxy_id: uuid::Uuid::now_v7().to_string(),
                revision_id: uuid::Uuid::now_v7().to_string(),
                generation: 1,
                fencing_token: 1,
            }),
            process_instance_id: uuid::Uuid::now_v7().to_string(),
            config_hash: "a".repeat(64),
            launch_context_hash: "b".repeat(64),
        }),
    };
    let mut pending = Box::pin(f.observe_health(
        Request::new(body.clone()),
        Instant::now(),
        Arc::clone(&metadata),
    ));
    assert!(
        pending
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending()
    );
    let Work::Health(held) = receiver.recv_timeout(Duration::from_secs(1)).unwrap() else {
        panic!("health job")
    };
    drop(pending);
    assert!(held.cancelled.load(Ordering::Acquire));
    assert_eq!(f.slots.available_permits(), 7);
    assert_eq!(
        f.observe_health(
            Request::new(body.clone()),
            Instant::now(),
            Arc::clone(&metadata)
        )
        .await
        .unwrap_err()
        .code(),
        tonic::Code::ResourceExhausted
    );
    let mut network = Box::pin(f.inspect_network(
        Request::new(proto::RuntimeNetworkInspectionRequest {
            schema_version: 1,
            binding: body.binding.clone(),
            nonce: body.nonce.clone(),
        }),
        Instant::now(),
        Arc::clone(&metadata),
    ));
    assert!(
        network
            .as_mut()
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending()
    );
    let network_job = receiver.recv_timeout(Duration::from_secs(1)).unwrap();
    drop(network);
    drop(network_job);
    let r = proto::RuntimeReconcileRequest {
        schema_version: 1,
        target: body.binding.as_ref().unwrap().target.clone(),
        operation_id: uuid::Uuid::now_v7().to_string(),
        command_id: uuid::Uuid::now_v7().to_string(),
        config_hash: "a".repeat(64),
    };
    assert_eq!(
        f.execute(Request::new(r)).await.unwrap_err().code(),
        tonic::Code::ResourceExhausted
    );
    drop(held);
    assert_eq!(f.slots.available_permits(), 8);
    assert!(f.active.lock().unwrap().is_empty());
    assert_eq!(
        f.observe_health(
            Request::new(body),
            Instant::now() - Duration::from_secs(11),
            metadata
        )
        .await
        .unwrap_err()
        .code(),
        tonic::Code::DeadlineExceeded
    );
}
